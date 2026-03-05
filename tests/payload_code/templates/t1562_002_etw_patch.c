/*
 * T1562.002 — Disable Windows Event Logging: патчинг EtwEventWrite (ntdll).
 * Defense Evasion: детект по EtwEventWrite, GetProcAddress(ntdll), запись в память.
 */
#include <windows.h>

int main(void) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return 1;
    void *pEtw = GetProcAddress(ntdll, "EtwEventWrite");
    if (!pEtw) return 2;
    (void)pEtw;
    return 0;
}
