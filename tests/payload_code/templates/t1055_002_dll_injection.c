/*
 * T1055.002 — DLL Injection: OpenProcess, VirtualAllocEx, WriteProcessMemory, CreateRemoteThread,
 * GetProcAddress(LoadLibraryA). Defense Evasion: детект по цепочке инъекции.
 */
#include <windows.h>

int main(void) {
    DWORD pid = GetCurrentProcessId();
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) return 1;
    LPVOID remote = VirtualAllocEx(hProc, NULL, 256, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (remote) {
        char dllPath[] = "C:\\Windows\\System32\\kernel32.dll";
        WriteProcessMemory(hProc, remote, dllPath, sizeof(dllPath), NULL);
        HMODULE k32 = GetModuleHandleA("kernel32.dll");
        LPVOID pLoadLibrary = GetProcAddress(k32, "LoadLibraryA");
        CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibrary, remote, 0, NULL);
    }
    CloseHandle(hProc);
    return 0;
}
