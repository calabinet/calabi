#pragma once
#include <objbase.h>
#include <shlobj.h>

static HANDLE sourceFiles[PROBE_FILE_COUNT];
static BY_HANDLE_FILE_INFORMATION sourceInfo[PROBE_FILE_COUNT];
static unsigned sourceCount;
typedef struct LockedSources {BOOL used;uint32_t id;unsigned count;HANDLE handles[PROBE_FILE_COUNT];BY_HANDLE_FILE_INFORMATION info[PROBE_FILE_COUNT];} LockedSources;
static LockedSources lockedSources[8];
void probe_file_unlock(uint32_t id){
    for(unsigned s=0;s<ARRAYSIZE(lockedSources);s++)if(lockedSources[s].used && lockedSources[s].id==id){
        for(unsigned i=0;i<lockedSources[s].count;i++)CloseHandle(lockedSources[s].handles[i]);memset(&lockedSources[s],0,sizeof(lockedSources[s]));
    }
}
void probe_file_unlock_all(void){for(unsigned s=0;s<ARRAYSIZE(lockedSources);s++)if(lockedSources[s].used)probe_file_unlock(lockedSources[s].id);}
int probe_file_lock(uint32_t id){
    for(unsigned s=0;s<ARRAYSIZE(lockedSources);s++)if(lockedSources[s].used && lockedSources[s].id==id)return 0;
    if(!sourceCount)return 0;
    for(unsigned s=0;s<ARRAYSIZE(lockedSources);s++)if(!lockedSources[s].used){
        LockedSources *lock=&lockedSources[s];lock->used=TRUE;lock->id=id;
        for(unsigned i=0;i<sourceCount;i++){
            if(!DuplicateHandle(GetCurrentProcess(),sourceFiles[i],GetCurrentProcess(),&lock->handles[i],0,FALSE,DUPLICATE_SAME_ACCESS)){probe_file_unlock(id);return 0;}
            lock->info[i]=sourceInfo[i];lock->count++;
        }
        return 1;
    }
    return 0;
}
int probe_file_read_locked(uint32_t id,unsigned index,uint64_t offset,uint8_t *data,size_t *length,uint64_t *size){
    for(unsigned s=0;s<ARRAYSIZE(lockedSources);s++)if(lockedSources[s].used && lockedSources[s].id==id){
        LockedSources *lock=&lockedSources[s];if(index>=lock->count)return 0;
        BY_HANDLE_FILE_INFORMATION now,*old=&lock->info[index];HANDLE file=lock->handles[index];
        if(!GetFileInformationByHandle(file,&now) || now.nFileSizeHigh!=old->nFileSizeHigh || now.nFileSizeLow!=old->nFileSizeLow || CompareFileTime(&now.ftLastWriteTime,&old->ftLastWriteTime))return 0;
        *size=(uint64_t)now.nFileSizeHigh<<32 | now.nFileSizeLow;if(offset>*size)return 0;if(!data)return 1;
        if(*length>*size-offset)*length=(size_t)(*size-offset);LARGE_INTEGER at;at.QuadPart=offset;DWORD read=0;
        return SetFilePointerEx(file,at,NULL,FILE_BEGIN) && ReadFile(file,data,(DWORD)*length,&read,NULL) && read==*length;
    }
    return 0;
}
typedef struct FileBatch {
    struct FileBatch *next;
    wchar_t directory[MAX_PATH], paths[PROBE_FILE_COUNT][MAX_PATH];
    HANDLE handles[PROBE_FILE_COUNT];
    uint64_t sizes[PROBE_FILE_COUNT], total;
    unsigned count;
} FileBatch;
static FileBatch *receivingFiles, *completedFiles;
static uint64_t retainedBytes;
static unsigned retainedBatches;
static DWORD publishedFilesSequence;
static void close_file_sources(void) {
    for(unsigned i=0;i<sourceCount;i++)CloseHandle(sourceFiles[i]);
    sourceCount=0;
}
static BOOL safe_file_name(const wchar_t *name) {
    size_t n=wcslen(name);if(!n || n>=260 || name[n-1]==L'.' || name[n-1]==L' ')return FALSE;
    for(size_t i=0;i<n;i++)if(name[i]<32 || wcschr(L"\\/:*?\"<>|",name[i]))return FALSE;
    wchar_t stem[260];wcscpy(stem,name);wchar_t *dot=wcschr(stem,L'.');if(dot)*dot=0;
    if(!_wcsicmp(stem,L"CON") || !_wcsicmp(stem,L"PRN") || !_wcsicmp(stem,L"AUX") || !_wcsicmp(stem,L"NUL") ||
       !_wcsicmp(stem,L"CONIN$") || !_wcsicmp(stem,L"CONOUT$"))return FALSE;
    if(wcslen(stem)==4 && (!_wcsnicmp(stem,L"COM",3) || !_wcsnicmp(stem,L"LPT",3)) &&
       ((stem[3]>=L'0' && stem[3]<=L'9') || stem[3]==0xb9 || stem[3]==0xb2 || stem[3]==0xb3))return FALSE;
    return TRUE;
}
static BYTE *read_drop_files(HDROP drop,size_t *length) {
    close_file_sources();*length=0;
    unsigned count=drop?DragQueryFileW(drop,0xffffffff,NULL,0):0;
    if(!count || count>PROBE_FILE_COUNT)return NULL;
    size_t n=4+count*CLIP_DESCRIPTOR_SIZE;BYTE *data=calloc(1,n);if(!data)return NULL;
    clip_put32(data,count);uint64_t total=0;
    for(unsigned i=0;i<count;i++) {
        wchar_t path[32768];unsigned chars=DragQueryFileW(drop,i,NULL,0);
        if(!chars || chars>=ARRAYSIZE(path) || DragQueryFileW(drop,i,path,ARRAYSIZE(path))!=chars)goto fail;
        const wchar_t *name=wcsrchr(path,L'\\');name=name?name+1:path;
        if(!safe_file_name(name))goto fail;
        HANDLE file=CreateFileW(path,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,NULL);
        if(file==INVALID_HANDLE_VALUE)goto fail;
        sourceFiles[sourceCount++]=file;BY_HANDLE_FILE_INFORMATION *info=&sourceInfo[i];
        if(GetFileType(file)!=FILE_TYPE_DISK || !GetFileInformationByHandle(file,info) ||
           (info->dwFileAttributes&(FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_REPARSE_POINT)))goto fail;
        uint64_t size=(uint64_t)info->nFileSizeHigh<<32 | info->nFileSizeLow;
        if(size>PROBE_FILE_LIMIT || total>PROBE_FILE_LIMIT-size)goto fail;total+=size;
        BYTE *d=data+4+i*CLIP_DESCRIPTOR_SIZE;clip_put32(d,0x44);clip_put32(d+36,FILE_ATTRIBUTE_NORMAL);
        clip_put32(d+64,info->nFileSizeHigh);clip_put32(d+68,info->nFileSizeLow);
        memcpy(d+72,name,(wcslen(name)+1)*sizeof(wchar_t));
        for(unsigned j=0;j<i;j++)if(!_wcsicmp(name,(wchar_t*)(data+4+j*CLIP_DESCRIPTOR_SIZE+72)))goto fail;
    }
    if(!clip_valid_files(data,n))goto fail;
    *length=n;return data;
fail:close_file_sources();free(data);return NULL;
}
int probe_file_read(unsigned index,uint64_t offset,uint8_t *data,size_t *length,uint64_t *size) {
    if(index>=sourceCount)return 0;
    BY_HANDLE_FILE_INFORMATION now,*old=&sourceInfo[index];
    if(!GetFileInformationByHandle(sourceFiles[index],&now) || now.nFileSizeHigh!=old->nFileSizeHigh ||
       now.nFileSizeLow!=old->nFileSizeLow || CompareFileTime(&now.ftLastWriteTime,&old->ftLastWriteTime))return 0;
    *size=(uint64_t)now.nFileSizeHigh<<32 | now.nFileSizeLow;if(offset>*size)return 0;
    if(!data)return 1;
    if(*length>*size-offset)*length=(size_t)(*size-offset);
    LARGE_INTEGER at;at.QuadPart=offset;DWORD read=0;
    return SetFilePointerEx(sourceFiles[index],at,NULL,FILE_BEGIN) &&
        ReadFile(sourceFiles[index],data,(DWORD)*length,&read,NULL) && read==*length;
}
static void remove_batch(FileBatch *batch) {
    if(!batch)return;
    for(unsigned i=0;i<batch->count;i++) {
        if(batch->handles[i] && batch->handles[i]!=INVALID_HANDLE_VALUE)CloseHandle(batch->handles[i]);
        if(batch->paths[i][0])DeleteFileW(batch->paths[i]);
    }
    if(batch->directory[0])RemoveDirectoryW(batch->directory);
    free(batch);
}
void probe_files_cancel(void) {
    if(receivingFiles){retainedBytes-=receivingFiles->total;retainedBatches--;remove_batch(receivingFiles);receivingFiles=NULL;}
}
int probe_files_begin(const uint8_t *data,size_t length) {
    probe_files_cancel();if(!clip_valid_files(data,length))return -2;
    uint64_t total=0;unsigned count=clip_u32(data);
    for(unsigned i=0;i<count;i++)total+=clip_file_size(data+4+i*CLIP_DESCRIPTOR_SIZE);
    if(retainedBytes+total>256u*1024u*1024u || retainedBatches>=64)return -10;
    FileBatch *batch=calloc(1,sizeof(*batch));if(!batch)return -9;
    wchar_t temp[MAX_PATH],id[40];GUID guid;
    DWORD chars=GetTempPathW(ARRAYSIZE(temp),temp);
    if(!chars || chars>=ARRAYSIZE(temp) || FAILED(CoCreateGuid(&guid)) || !StringFromGUID2(&guid,id,ARRAYSIZE(id)))goto fail;
    if(swprintf(batch->directory,MAX_PATH,L"%lsCalabi-rdp-%ls",temp,id)<0 ||
       !CreateDirectoryW(batch->directory,NULL)){batch->directory[0]=0;goto fail;}
    batch->count=count;
    for(unsigned i=0;i<count;i++) {
        const BYTE *d=data+4+i*CLIP_DESCRIPTOR_SIZE;wchar_t name[260];memcpy(name,d+72,sizeof(name));
        if(!safe_file_name(name))goto fail;
        for(unsigned j=0;j<i;j++)if(!_wcsicmp(name,wcsrchr(batch->paths[j],L'\\')+1))goto fail;
        if(wcslen(batch->directory)+1+wcslen(name)>=MAX_PATH)goto fail;
        swprintf(batch->paths[i],MAX_PATH,L"%ls\\%ls",batch->directory,name);
        batch->handles[i]=CreateFileW(batch->paths[i],GENERIC_WRITE,FILE_SHARE_READ,NULL,CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL|FILE_FLAG_OPEN_REPARSE_POINT,NULL);
        if(batch->handles[i]==INVALID_HANDLE_VALUE){batch->paths[i][0]=0;goto fail;}
        batch->sizes[i]=clip_file_size(d);
    }
    batch->total=total;retainedBytes+=total;retainedBatches++;receivingFiles=batch;return 1;
fail:remove_batch(batch);return -9;
}
int probe_file_write(unsigned index,uint64_t offset,const uint8_t *data,size_t length) {
    FileBatch *b=receivingFiles;if(!b || index>=b->count || offset>b->sizes[index] || length>b->sizes[index]-offset)return 0;
    LARGE_INTEGER at;at.QuadPart=offset;DWORD wrote=0;
    return SetFilePointerEx(b->handles[index],at,NULL,FILE_BEGIN) && WriteFile(b->handles[index],data,(DWORD)length,&wrote,NULL) && wrote==length;
}
static HGLOBAL make_drop_files(const FileBatch *batch) {
    size_t chars=1;for(unsigned i=0;i<batch->count;i++)chars+=wcslen(batch->paths[i])+1;
    HGLOBAL data=GlobalAlloc(GMEM_MOVEABLE|GMEM_ZEROINIT,sizeof(DROPFILES)+chars*sizeof(wchar_t));
    DROPFILES *drop=data?GlobalLock(data):NULL;if(!drop){if(data)GlobalFree(data);return NULL;}
    drop->pFiles=sizeof(DROPFILES);drop->fWide=TRUE;wchar_t *p=(wchar_t*)((BYTE*)drop+drop->pFiles);
    for(unsigned i=0;i<batch->count;i++){wcscpy(p,batch->paths[i]);p+=wcslen(p)+1;}
    GlobalUnlock(data);return data;
}
static int publish_received_files(uint64_t expected,uint64_t *sequence) {
    FileBatch *b=receivingFiles;if(!b || !clipboardFilesEnabled)return 0;
    for(unsigned i=0;i<b->count;i++) {
        if(b->handles[i]) {
            LARGE_INTEGER size;if(!GetFileSizeEx(b->handles[i],&size) || (uint64_t)size.QuadPart!=b->sizes[i] || !FlushFileBuffers(b->handles[i]))return 0;
            CloseHandle(b->handles[i]);b->handles[i]=NULL;
        }
    }
    HGLOBAL data=make_drop_files(b);if(!data)return 0;
    if(!OpenClipboard(window)){GlobalFree(data);return 0;}
    BOOL ok=GetClipboardSequenceNumber()==expected && EmptyClipboard() && SetClipboardData(CF_HDROP,data)!=NULL;
    if(ok){*sequence=publishedFilesSequence=GetClipboardSequenceNumber();receivingFiles=NULL;b->next=completedFiles;completedFiles=b;}
    CloseClipboard();if(!ok)GlobalFree(data);return ok;
}
void probe_files_cleanup(void) {
    probe_file_unlock_all();
    copy_bridge_reset();
    close_file_sources();probe_files_cancel();
    if(publishedFilesSequence && OpenClipboard(window)) {
        if(GetClipboardSequenceNumber()==publishedFilesSequence)EmptyClipboard();CloseClipboard();
    }
    publishedFilesSequence=0;
    while(completedFiles){FileBatch *next=completedFiles->next;remove_batch(completedFiles);completedFiles=next;}
    retainedBytes=retainedBatches=0;
}
