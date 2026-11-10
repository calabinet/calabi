#pragma once
// Private helper-to-desktop pipe. Source file paths never enter the RDP
// clipboard; only an authenticated agent batch locator is advertised there.
static SRWLOCK copyBridgeLock=SRWLOCK_INIT,copyPipeLock=SRWLOCK_INIT;
static DWORD copyBridgeSequence;
static BOOL copyBridgeBusy,copyBridgeReady;
static char copyBridgeToken[256];
static void copy_bridge_reset(void){AcquireSRWLockExclusive(&copyBridgeLock);copyBridgeSequence=0;copyBridgeReady=FALSE;copyBridgeToken[0]=0;ReleaseSRWLockExclusive(&copyBridgeLock);}
typedef struct {DWORD sequence;char paths[8193];} CopyBridgeRequest;
static DWORD WINAPI copy_bridge_worker(void *opaque){
    CopyBridgeRequest *r=opaque;char answer[300]={0};
    AcquireSRWLockExclusive(&copyPipeLock);
    fprintf(stdout,"rdp-copy %s\n",r->paths);fflush(stdout);
    if(!fgets(answer,sizeof(answer),stdin))answer[0]=0;
    ReleaseSRWLockExclusive(&copyPipeLock);
    answer[strcspn(answer,"\r\n")]=0;
    AcquireSRWLockExclusive(&copyBridgeLock);
    if(r->sequence==copyBridgeSequence){
        copyBridgeToken[0]=0;
        if(!strncmp(answer,"copy ",5) && strlen(answer+5)<sizeof(copyBridgeToken))strcpy(copyBridgeToken,answer+5);
        copyBridgeReady=TRUE;
    }
    copyBridgeBusy=FALSE;
    ReleaseSRWLockExclusive(&copyBridgeLock);free(r);return 0;
}
// Called while the caller holds the local clipboard. -1 means the legacy
// route is enabled; 0 pending/no change; 1 consumed; 2 asynchronous completion.
static int copy_bridge_read(HDROP drop,DWORD current,uint8_t **text,size_t *length,uint32_t *format){
    if(!getenv("CALABI_RDP_FILE_BRIDGE"))return -1;
    AcquireSRWLockExclusive(&copyBridgeLock);
    if(copyBridgeSequence==current){
        int result=0;
        if(copyBridgeReady){
            copyBridgeReady=FALSE;result=2;
            if(copyBridgeToken[0]){*length=strlen(copyBridgeToken)+1;*text=malloc(*length);if(*text){memcpy(*text,copyBridgeToken,*length);*format=PROBE_FORMAT_BRIDGE;probe_files_progress(0,0,6);}else *length=0;}
            else probe_files_progress(0,0,-19);
        }
        ReleaseSRWLockExclusive(&copyBridgeLock);return result;
    }
    if(copyBridgeBusy){ReleaseSRWLockExclusive(&copyBridgeLock);return 0;}
    unsigned count=DragQueryFileW(drop,0xffffffff,NULL,0);CopyBridgeRequest *r=calloc(1,sizeof(*r));
    size_t used=0;BOOL ok=r && count>0 && count<=32;
    for(unsigned i=0;ok && i<count;i++){
        wchar_t path[2048];char utf8[4096];unsigned n=DragQueryFileW(drop,i,NULL,0);
        if(!n || n>=ARRAYSIZE(path) || DragQueryFileW(drop,i,path,ARRAYSIZE(path))!=n){ok=FALSE;break;}
        int bytes=WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,path,-1,utf8,sizeof(utf8),NULL,NULL);
        if(bytes<=0 || used+2*bytes>8192){ok=FALSE;break;}
        for(int j=0;j<bytes;j++){static const char hex[]="0123456789abcdef";unsigned char c=utf8[j];r->paths[used++]=hex[c>>4];r->paths[used++]=hex[c&15];}
    }
    copyBridgeSequence=current;copyBridgeReady=FALSE;copyBridgeToken[0]=0;
    if(ok){r->sequence=current;copyBridgeBusy=TRUE;probe_files_progress(0,0,5);HANDLE worker=CreateThread(NULL,0,copy_bridge_worker,r,0,NULL);if(worker)CloseHandle(worker);else{copyBridgeBusy=FALSE;ok=FALSE;}}
    if(!ok){free(r);probe_files_progress(0,0,-19);}
    ReleaseSRWLockExclusive(&copyBridgeLock);return 1;
}
