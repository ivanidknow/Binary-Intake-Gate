/*
 * T1057 — Process Discovery. CreateToolhelp32Snapshot, Process32First/Next.
 */
#include <windows.h>
#include <tlhelp32.h>

int main(void) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 1;
    PROCESSENTRY32 pe = { sizeof(pe) };
    if (Process32First(snap, &pe)) {
        do {
            (void)pe.szExeFile;
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return 0;
}
