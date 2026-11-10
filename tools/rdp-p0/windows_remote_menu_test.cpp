// Real menu command and Shell copy engine with synthetic bytes and private registry.
#define wWinMain unused_menu_entry
#include "shell-paste-probe.cpp"
#undef wWinMain
class MenuFixtureSource final:public RdpSource {
    bool fail;
public:
    explicit MenuFixtureSource(bool fail=false):fail(fail){}
    HRESULT read(unsigned,ULONGLONG,void *out,ULONG count,ULONG *got) override {
        if(fail){*got=0;return HRESULT_FROM_WIN32(ERROR_TIMEOUT);}
        memset(out,0x63,count);*got=count;return S_OK;
    }
};
static std::wstring menu_test_string(HKEY root,const std::wstring &path,const wchar_t *name){
    wchar_t value[32768];DWORD bytes=sizeof(value),type=0;
    assert(RegGetValueW(root,path.c_str(),name,RRF_RT_REG_SZ,&type,value,&bytes)==ERROR_SUCCESS);
    return value;
}
int main(){
    SetEnvironmentVariableW(L"CALABI_UI_LOCALE_FILE",nullptr);
    SetEnvironmentVariableW(L"CALABI_UI_LOCALE",L"fr");
    HWINSTA station=CreateWindowStationW(nullptr,0,WINSTA_ALL_ACCESS,nullptr);assert(station && SetProcessWindowStation(station));
    HDESK desktop=CreateDesktopW(L"Default",nullptr,nullptr,0,GENERIC_ALL,nullptr);assert(desktop && SetThreadDesktop(desktop));
    assert(SUCCEEDED(OleInitialize(nullptr)));
    std::wstring privateKey=L"Software\\Calabi\\Tests\\RemoteMenu-"+std::to_wstring(GetCurrentProcessId());
    HKEY fixture=nullptr;
    assert(RegCreateKeyExW(HKEY_CURRENT_USER,privateKey.c_str(),0,nullptr,0,KEY_ALL_ACCESS,nullptr,&fixture,nullptr)==ERROR_SUCCESS);
    assert(RegOverridePredefKey(HKEY_CURRENT_USER,fixture)==ERROR_SUCCESS);
    std::wstring exe=L"C:\\Calabi menu fixture\\rdp\\calabi-paste.exe";
    assert(remote_menu_register(exe,true));
    for(const auto key:remoteMenuKeys){
        assert(menu_test_string(fixture,key,nullptr)==rdp_text_in(RdpLocaleFrench,Rdp_PasteRemote));
        auto command=menu_test_string(fixture,std::wstring(key)+L"\\command",nullptr);
        int argc=0;auto argv=CommandLineToArgvW(command.c_str(),&argc);
        assert(argv && argc==4 && exe==argv[0] && !wcscmp(argv[1],L"--paste-remote") && !wcscmp(argv[2],L"%V\\.") && !wcscmp(argv[3],L"fr"));
        LocalFree(argv);
        auto icon=menu_test_string(fixture,key,L"Icon");
        assert(icon==L"C:\\Calabi menu fixture\\rdp\\calabi-rdp.exe,0");
    }
    assert(remote_menu_register(exe,false));
    for(const auto key:remoteMenuKeys){HKEY missing=nullptr;assert(RegOpenKeyExW(fixture,key,0,KEY_READ,&missing)==ERROR_FILE_NOT_FOUND);}
    assert(RegOverridePredefKey(HKEY_CURRENT_USER,nullptr)==ERROR_SUCCESS);
    RegCloseKey(fixture);assert(RegDeleteTreeW(HKEY_CURRENT_USER,privateKey.c_str())==ERROR_SUCCESS);
    wchar_t temp[MAX_PATH];assert(GetTempPathW(ARRAYSIZE(temp),temp));
    std::wstring target=std::wstring(temp)+L"Calabi-远程菜单-"+std::to_wstring(GetCurrentProcessId());
    assert(CreateDirectoryW(target.c_str(),nullptr));
    auto batch=std::make_shared<Batch>();batch->size=8192;batch->delay=0;
    auto source=new Files(batch);
    HRESULT hr=remote_menu_copy(source,target.c_str());
    fprintf(stderr,"Menu first paste: 0x%08lX\n",(unsigned long)hr);assert(SUCCEEDED(hr));
    auto file=target+L"\\"+fileName;
    HANDLE handle=CreateFileW(file.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,0,nullptr);assert(handle!=INVALID_HANDLE_VALUE);
    BYTE bytes[8192];DWORD got=0;assert(ReadFile(handle,bytes,sizeof(bytes),&got,nullptr) && got==8192);CloseHandle(handle);
    for(unsigned i=0;i<got;i++)assert(bytes[i]==i%251);
    assert(batch->finished && SUCCEEDED(batch->result));
    assert(SUCCEEDED(remote_menu_copy(source,target.c_str()))); // Collision preserves the original.
    WIN32_FIND_DATAW item;HANDLE find=FindFirstFileW((target+L"\\*").c_str(),&item);assert(find!=INVALID_HANDLE_VALUE);
    unsigned count=0;
    do{if(!(item.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY)){count++;assert(item.nFileSizeLow==8192);assert(DeleteFileW((target+L"\\"+item.cFileName).c_str()));}}while(FindNextFileW(find,&item));
    FindClose(find);assert(count==2);
    assert(remote_menu_copy(source,L"relative")==E_INVALIDARG);
    batch->cancelled=true;assert(FAILED(remote_menu_copy(source,target.c_str())));
    source->Release();
    auto cancelled=std::make_shared<Batch>();cancelled->size=1024*1024;cancelled->delay=10;
    source=new Files(cancelled);
    std::thread cancel([cancelled]{
        ULONGLONG until=GetTickCount64()+5000;
        while(!cancelled->read && GetTickCount64()<until)Sleep(1);
        assert(cancelled->read>0);cancelled->cancelled=true;
    });
    assert(FAILED(remote_menu_copy(source,target.c_str())));cancel.join();source->Release();
    find=FindFirstFileW((target+L"\\*").c_str(),&item);assert(find!=INVALID_HANDLE_VALUE);
    do{assert(item.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY);}while(FindNextFileW(find,&item));
    FindClose(find);
    int argumentCount=0;auto arguments=CommandLineToArgvW(GetCommandLineW(),&argumentCount);
    assert(arguments && argumentCount==2);
    wchar_t stationName[256];DWORD needed=0;
    assert(GetUserObjectInformationW(station,UOI_NAME,stationName,sizeof(stationName),&needed));
    std::wstring desktopName=std::wstring(stationName)+L"\\Default";
    auto paste=[&](bool fail,DWORD expectedExit){
        auto remote=std::make_shared<Batch>();remote->size=8192;remote->rdpSource=std::make_shared<MenuFixtureSource>(fail);
        auto object=new Files(remote);assert(SUCCEEDED(OleSetClipboard(object)));
        std::wstring command=L"\""+std::wstring(arguments[1])+L"\" --paste-remote \""+target+L"\\.\"";
        STARTUPINFOW startup={};startup.cb=sizeof(startup);startup.lpDesktop=desktopName.data();
        PROCESS_INFORMATION process={};
        assert(CreateProcessW(arguments[1],command.data(),nullptr,nullptr,FALSE,0,nullptr,nullptr,&startup,&process));
        ULONGLONG until=GetTickCount64()+15000;
        while(WaitForSingleObject(process.hProcess,0)==WAIT_TIMEOUT && GetTickCount64()<until){
            MSG message;while(PeekMessageW(&message,nullptr,0,0,PM_REMOVE)){TranslateMessage(&message);DispatchMessageW(&message);}
            Sleep(1);
        }
        DWORD exit=1;bool ended=WaitForSingleObject(process.hProcess,0)==WAIT_OBJECT_0;
        if(!ended){TerminateProcess(process.hProcess,99);WaitForSingleObject(process.hProcess,3000);}
        GetExitCodeProcess(process.hProcess,&exit);CloseHandle(process.hThread);CloseHandle(process.hProcess);
        assert(ended && exit==expectedExit);assert(SUCCEEDED(OleSetClipboard(nullptr)));object->Release();
        return remote;
    };
    auto failed=paste(true,1); // A duplicate modal would keep the child blocked.
    assert(failed->finished && failed->interruption==HRESULT_FROM_WIN32(ERROR_TIMEOUT));
    assert(GetFileAttributesW(file.c_str())==INVALID_FILE_ATTRIBUTES);
    paste(false,0);
    LocalFree(arguments);
    handle=CreateFileW(file.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,0,nullptr);assert(handle!=INVALID_HANDLE_VALUE);
    assert(ReadFile(handle,bytes,sizeof(bytes),&got,nullptr) && got==8192);CloseHandle(handle);
    for(unsigned i=0;i<got;i++)assert(bytes[i]==0x63);
    assert(DeleteFileW(file.c_str()));assert(RemoveDirectoryW(target.c_str()));
    OleUninitialize();
    puts("Windows remote menu passed: private clipboard, real child command, timeout without a duplicate dialog, cleanup, repeat/collision and cancellation.");
    return 0;
}
