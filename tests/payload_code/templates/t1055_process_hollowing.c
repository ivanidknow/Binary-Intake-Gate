/*
 * T1055.012 — Process Hollowing: цепочка CreateProcess (suspended), VirtualAllocEx, WriteProcessMemory,
 * SetThreadContext, ResumeThread. Детект по loader_process_hollowing_chain и эмуляции.
 */
#include <windows.h>

int main(void) {
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    char cmd[] = "C:\\Windows\\System32\\svchost.exe";
    if (!CreateProcessA(cmd, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
        return 1;
    /* Типичная цепочка hollowing: аллокация в целевом процессе, запись, смена контекста, возобновление */
    LPVOID remote = VirtualAllocEx(pi.hProcess, NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (remote) {
        char payload[] = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE";
        WriteProcessMemory(pi.hProcess, remote, payload, sizeof(payload), NULL);
        CONTEXT ctx = { 0 };
        ctx.ContextFlags = CONTEXT_CONTROL;
        GetThreadContext(pi.hThread, &ctx);
        SetThreadContext(pi.hThread, &ctx);
        ResumeThread(pi.hThread);
    }
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}
