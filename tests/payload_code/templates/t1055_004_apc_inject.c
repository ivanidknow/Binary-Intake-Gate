/*
 * T1055.004 — Process Injection: APC. QueueUserAPC, NtQueueApcThread.
 * Defense Evasion: детект по APC-инъекции.
 */
#include <windows.h>
#include <stdio.h>

int main(void) {
    DWORD pid = GetCurrentProcessId();
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) return 1;
    HANDLE hThread = GetCurrentThread();
    LPVOID remote = VirtualAllocEx(hProc, NULL, 64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (remote && hThread) {
        WriteProcessMemory(hProc, remote, "\xc3", 1, NULL);  /* ret */
        QueueUserAPC((PAPCFUNC)remote, hThread, 0);
    }
    if (hProc) CloseHandle(hProc);
    return 0;
}
