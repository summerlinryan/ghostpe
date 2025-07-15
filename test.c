#include <windows.h>
#include <stdio.h>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        printf("Process attached!\n");
        break;
    case DLL_THREAD_ATTACH:
        printf("Thread attached!\n");
        break;
    case DLL_THREAD_DETACH:
        printf("Thread detached!\n");
        break;
    case DLL_PROCESS_DETACH:
        printf("Process detached!\n");
        break;
    }
    return TRUE;
}
