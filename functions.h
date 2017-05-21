//
// Created by switch on 21/05/2017.
//
#include <tlhelp32.h>
#ifndef SOUYEINJECTOR_FUNCTIONS_H
#define SOUYEINJECTOR_FUNCTIONS_H

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

#endif //SOUYEINJECTOR_FUNCTIONS_H

