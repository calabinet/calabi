#pragma once
#include <shobjidl.h>
#include <shellapi.h>
#include <shlwapi.h>

static const wchar_t *remoteMenuKeys[]={
    L"Software\\Classes\\Directory\\Background\\shell\\Calabi.RemotePaste",
    L"Software\\Classes\\DesktopBackground\\Shell\\Calabi.RemotePaste"
};
static bool remoteMenuEnabled=false;
static LONG remote_menu_string(HKEY key,const wchar_t *name,const std::wstring &value){
    return RegSetValueExW(key,name,0,REG_SZ,(const BYTE*)value.c_str(),(DWORD)((value.size()+1)*sizeof(wchar_t)));
}
static bool remote_menu_register(const std::wstring &exe,bool enabled){
    bool success=true;
    RdpLocale locale=rdp_locale_current();
    const char *code=rdp_locale_codes[locale];
    std::wstring language(code,code+strlen(code));
    for(const auto path:remoteMenuKeys){
        if(!enabled){
            LONG result=RegDeleteTreeW(HKEY_CURRENT_USER,path);
            success=success && (result==ERROR_SUCCESS || result==ERROR_FILE_NOT_FOUND);
            continue;
        }
        HKEY key=nullptr,command=nullptr;
        LONG result=RegCreateKeyExW(HKEY_CURRENT_USER,path,0,nullptr,0,KEY_WRITE,nullptr,&key,nullptr);
        if(result==ERROR_SUCCESS){
            std::wstring icon=exe.substr(0,exe.find_last_of(L"\\/")+1)+L"calabi-rdp.exe,0";
            result=remote_menu_string(key,nullptr,rdp_text_in(locale,Rdp_PasteRemote));
            if(result==ERROR_SUCCESS)result=remote_menu_string(key,L"Icon",icon);
            if(result==ERROR_SUCCESS)result=RegCreateKeyExW(key,L"command",0,nullptr,0,KEY_WRITE,nullptr,&command,nullptr);
            // The final dot also keeps a drive root's backslash away from the quote.
            if(result==ERROR_SUCCESS)result=remote_menu_string(command,nullptr,L"\""+exe+L"\" --paste-remote \"%V\\.\" "+language);
        }
        if(command)RegCloseKey(command);
        if(key)RegCloseKey(key);
        if(result!=ERROR_SUCCESS){RegDeleteTreeW(HKEY_CURRENT_USER,path);success=false;}
    }
    return success;
}
static void remote_menu_refresh(){
    static int installed=-1;
    static RdpLocale installedLocale=RdpLocaleInvalid;
    bool available=IsClipboardFormatAvailable(RegisterClipboardFormatW(L"CalabiRdpCopyOwnedV1"))!=FALSE;
    RdpLocale locale=rdp_locale_current();
    if(installed==(int)available && (!available || installedLocale==locale))return;
    wchar_t exe[32768];DWORD length=GetModuleFileNameW(nullptr,exe,ARRAYSIZE(exe));
    if(!length || length>=ARRAYSIZE(exe))return;
    if(remote_menu_register(exe,available)){
        installed=available;
        installedLocale=locale;
        fprintf(stderr,"rdp_menu visible=%d\n",available);fflush(stderr);
    }
}
static HRESULT remote_menu_copy_file(IDataObject *source,unsigned index,const FILEDESCRIPTORW &descriptor,const std::wstring &directory){
    FORMATETC format={(CLIPFORMAT)RegisterClipboardFormatW(CFSTR_FILECONTENTS),nullptr,DVASPECT_CONTENT,(LONG)index,TYMED_ISTREAM};
    STGMEDIUM medium={};HRESULT hr=source->GetData(&format,&medium);
    if(FAILED(hr))return hr;
    if(medium.tymed!=TYMED_ISTREAM || !medium.pstm){ReleaseStgMedium(&medium);return DV_E_TYMED;}
    GUID id;wchar_t unique[40]={};hr=CoCreateGuid(&id);
    if(FAILED(hr)){ReleaseStgMedium(&medium);return hr;}
    StringFromGUID2(id,unique,ARRAYSIZE(unique));
    auto temporary=directory+L"\\.calabi-receive-"+unique+L".partial";
    HANDLE file=CreateFileW(temporary.c_str(),GENERIC_WRITE|DELETE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);
    if(file==INVALID_HANDLE_VALUE){hr=HRESULT_FROM_WIN32(GetLastError());ReleaseStgMedium(&medium);return hr;}
    ULONGLONG left=((ULONGLONG)descriptor.nFileSizeHigh<<32)|descriptor.nFileSizeLow;
    BYTE buffer[65536];
    do{
        ULONG request=(ULONG)std::min<ULONGLONG>(left,sizeof(buffer)),got=0;
        hr=medium.pstm->Read(buffer,request,&got);
        if(FAILED(hr))break;
        if(got>request || (left && !got)){hr=STG_E_READFAULT;break;}
        DWORD done=0;
        while(done<got){
            DWORD written=0;
            if(!WriteFile(file,buffer+done,got-done,&written,nullptr) || !written){hr=HRESULT_FROM_WIN32(GetLastError()?GetLastError():ERROR_WRITE_FAULT);break;}
            done+=written;
        }
        if(FAILED(hr))break;
        left-=got;
    }while(left);
    ReleaseStgMedium(&medium);
    if(SUCCEEDED(hr) && !FlushFileBuffers(file))hr=HRESULT_FROM_WIN32(GetLastError());
    bool committed=false;
    if(SUCCEEDED(hr)){
        std::wstring name=descriptor.cFileName;size_t dot=name.find_last_of(L'.');
        if(dot==0 || dot==std::wstring::npos)dot=name.size();
        for(unsigned suffix=0;suffix<10000;suffix++){
            auto leaf=suffix?name.substr(0,dot)+L" ("+std::to_wstring(suffix)+L")"+name.substr(dot):name;
            auto path=directory+L"\\"+leaf;
            std::vector<BYTE> bytes(sizeof(FILE_RENAME_INFO)+path.size()*sizeof(wchar_t));
            auto rename=(FILE_RENAME_INFO*)bytes.data();rename->ReplaceIfExists=FALSE;rename->RootDirectory=nullptr;
            rename->FileNameLength=(DWORD)(path.size()*sizeof(wchar_t));memcpy(rename->FileName,path.data(),rename->FileNameLength);
            if(SetFileInformationByHandle(file,FileRenameInfo,rename,(DWORD)bytes.size())){committed=true;hr=S_OK;break;}
            DWORD error=GetLastError();hr=HRESULT_FROM_WIN32(error);
            if(error!=ERROR_ALREADY_EXISTS && error!=ERROR_FILE_EXISTS)break;
        }
    }
    if(!committed){FILE_DISPOSITION_INFO remove={TRUE};SetFileInformationByHandle(file,FileDispositionInfo,&remove,sizeof(remove));}
    CloseHandle(file);return hr;
}
static HRESULT remote_menu_copy_into(IDataObject *source,const std::vector<FILEDESCRIPTORW> &files,const wchar_t *destination){
    HANDLE folder=CreateFileW(destination,FILE_LIST_DIRECTORY|FILE_ADD_FILE,FILE_SHARE_READ|FILE_SHARE_WRITE,nullptr,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS,nullptr);
    if(folder==INVALID_HANDLE_VALUE){
        DWORD error=GetLastError();
        return HRESULT_FROM_WIN32(error==ERROR_FILE_NOT_FOUND?ERROR_PATH_NOT_FOUND:error);
    }
    wchar_t resolved[32768];DWORD length=GetFinalPathNameByHandleW(folder,resolved,ARRAYSIZE(resolved),FILE_NAME_NORMALIZED);
    BY_HANDLE_FILE_INFORMATION info={};
    HRESULT hr=HRESULT_FROM_WIN32(ERROR_DIRECTORY);
    if(length && length<ARRAYSIZE(resolved) && GetFileInformationByHandle(folder,&info) && (info.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY)){
        std::wstring directory(resolved);
        while(directory.size()>4 && directory.back()==L'\\')directory.pop_back();
        hr=S_OK;
        for(size_t i=0;SUCCEEDED(hr) && i<files.size();i++)hr=remote_menu_copy_file(source,(unsigned)i,files[i],directory);
    }
    CloseHandle(folder);
    return hr;
}
static HRESULT remote_menu_copy(IDataObject *source,const wchar_t *destination,bool *operationStarted=nullptr){
    if(!source || !destination || PathIsRelativeW(destination))return E_INVALIDARG;
    FORMATETC marker={(CLIPFORMAT)RegisterClipboardFormatW(L"CalabiRdpCopyOwnedV1"),nullptr,DVASPECT_CONTENT,-1,TYMED_HGLOBAL};
    if(FAILED(source->QueryGetData(&marker)))return DV_E_FORMATETC;
    FORMATETC descriptor={(CLIPFORMAT)RegisterClipboardFormatW(CFSTR_FILEDESCRIPTORW),nullptr,DVASPECT_CONTENT,-1,TYMED_HGLOBAL};
    STGMEDIUM medium={};HRESULT manifest=source->GetData(&descriptor,&medium);
    if(FAILED(manifest))return manifest;
    std::vector<FILEDESCRIPTORW> files;
    if(medium.tymed==TYMED_HGLOBAL){
        auto group=(FILEGROUPDESCRIPTORW*)GlobalLock(medium.hGlobal);SIZE_T size=GlobalSize(medium.hGlobal);
        if(group && size>=sizeof(UINT) && group->cItems>0 && group->cItems<=32 && size>=sizeof(UINT)+group->cItems*sizeof(FILEDESCRIPTORW))
            files.assign(group->fgd,group->fgd+group->cItems);
        if(group)GlobalUnlock(medium.hGlobal);
    }
    ReleaseStgMedium(&medium);
    if(files.empty())return DV_E_FORMATETC;
    ULONGLONG total=0;
    for(size_t i=0;i<files.size();i++){
        const auto &file=files[i];
        if(!wmemchr(file.cFileName,0,ARRAYSIZE(file.cFileName)))return E_INVALIDARG;
        std::wstring name=file.cFileName;
        if(name.empty() || name.back()==L'.' || name.back()==L' ' || name.find_first_of(L"\\/:*?\"<>|")!=std::wstring::npos ||
            !(file.dwFlags&FD_FILESIZE) || (file.dwFileAttributes&(FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_REPARSE_POINT)))return E_INVALIDARG;
        for(wchar_t ch:name)if(ch<32)return E_INVALIDARG;
        for(size_t j=0;j<i;j++)if(!_wcsicmp(file.cFileName,files[j].cFileName))return E_INVALIDARG;
        ULONGLONG size=((ULONGLONG)file.nFileSizeHigh<<32)|file.nFileSizeLow;
        if(size>100ull*1024*1024-total)return HRESULT_FROM_WIN32(ERROR_FILE_TOO_LARGE);total+=size;
    }
    IDataObjectAsyncCapability *async=nullptr;
    HRESULT hr=source->QueryInterface(IID_PPV_ARGS(&async));
    BOOL previous=TRUE,busy=FALSE;
    if(SUCCEEDED(hr))hr=async->GetAsyncMode(&previous);
    if(SUCCEEDED(hr))hr=async->InOperation(&busy);
    if(SUCCEEDED(hr) && busy)hr=HRESULT_FROM_WIN32(ERROR_BUSY);
    if(SUCCEEDED(hr))hr=async->SetAsyncMode(FALSE);
    if(SUCCEEDED(hr))hr=async->StartOperation(nullptr);
    if(SUCCEEDED(hr)){
        if(operationStarted)*operationStarted=true;
        hr=remote_menu_copy_into(source,files,destination);
        async->EndOperation(hr,nullptr,SUCCEEDED(hr)?DROPEFFECT_COPY:DROPEFFECT_NONE);
    }
    if(async){async->SetAsyncMode(previous);async->Release();}
    return hr;
}
static int remote_menu_command(){
    int argc=0;wchar_t **argv=CommandLineToArgvW(GetCommandLineW(),&argc);
    if(!argv || (argc!=3 && argc!=4)){if(argv)LocalFree(argv);return 2;}
    RdpLocale locale=rdp_locale_current();
    if(argc==4){
        char code[16];
        if(WideCharToMultiByte(CP_UTF8,0,argv[3],-1,code,sizeof(code),nullptr,nullptr)){
            RdpLocale selected=rdp_locale_parse(code);
            if(selected!=RdpLocaleInvalid)locale=selected;
        }
    }
    HRESULT hr=OleInitialize(nullptr);
    if(FAILED(hr)){LocalFree(argv);return 2;}
    HANDLE mutex=CreateMutexW(nullptr,FALSE,L"Local\\Calabi.RemotePasteV1");
    DWORD acquired=mutex?WaitForSingleObject(mutex,0):WAIT_FAILED;
    if(acquired!=WAIT_OBJECT_0 && acquired!=WAIT_ABANDONED)hr=HRESULT_FROM_WIN32(ERROR_BUSY);
    IDataObject *source=nullptr;
    bool operationStarted=false;
    if(SUCCEEDED(hr))hr=OleGetClipboard(&source);
    if(SUCCEEDED(hr))hr=remote_menu_copy(source,argv[2],&operationStarted);
    if(source)source->Release();
    if(acquired==WAIT_OBJECT_0 || acquired==WAIT_ABANDONED)ReleaseMutex(mutex);
    if(mutex)CloseHandle(mutex);
    fprintf(stderr,"rdp_menu result=0x%08lX\n",(unsigned long)hr);fflush(stderr);
    if(FAILED(hr) && !operationStarted && !paste_cancelled(hr)){
        std::wstring title=std::wstring(L"Calabi · ")+rdp_text_in(locale,Rdp_PasteRemote);
        MessageBoxW(nullptr,paste_failure_detail(hr,locale),title.c_str(),MB_OK|MB_ICONINFORMATION);
    }
    OleUninitialize();LocalFree(argv);return FAILED(hr)?1:0;
}
