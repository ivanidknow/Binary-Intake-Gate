/*
 * T1059.003 — Windows Command Shell: реальный вызов CreateProcess с cmd.exe.
 * Execution: детект по cmd.exe и аргументам /c.
 */
#include <windows.h>

int main(void) {
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    const char *cmd = "cmd.exe /c echo T1059.003";
    if (!CreateProcessA(NULL, (LPSTR)cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
        return 1;
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return 0;
}
