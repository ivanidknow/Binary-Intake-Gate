/*
 * T1059.001 — PowerShell: реальный вызов CreateProcess с powershell.exe.
 * Execution: детект по строкам/импортам и по эмуляции (api_calls).
 */
#include <windows.h>

int main(void) {
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    const char *cmd = "powershell.exe -NoProfile -Command \"Write-Host T1059.001\"";
    if (!CreateProcessA(NULL, (LPSTR)cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
        return 1;
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return 0;
}
