/*
 * Combo / Attack Storyline: T1082 (System Info Discovery) + T1055 (Process Hollowing stub).
 * Один артефакт последовательно выполняет 2 техники для проверки «комбо-рисков».
 */
#include <windows.h>

int main(void) {
    char name[256] = { 0 };
    DWORD len = 256;
    GetComputerNameA(name, &len);

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    char cmd[] = "C:\\Windows\\System32\\svchost.exe";
    if (!CreateProcessA(cmd, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi))
        return 1;
    LPVOID remote = VirtualAllocEx(pi.hProcess, NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (remote)
        ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}
