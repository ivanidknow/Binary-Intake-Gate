/*
 * T1003.001 — OS Credential Dumping: LSASS Memory.
 * OpenProcess с правами дампа; строки lsass/MiniDumpWriteDump для статического детекта.
 * Credential Access: детект по lsass, MiniDumpWriteDump, OpenProcess.
 */
#include <windows.h>

static const char *lsass_str = "lsass.exe";
static const char *dump_str = "MiniDumpWriteDump";

int main(void) {
    (void)lsass_str;
    (void)dump_str;
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, 4);
    if (!hProc)
        return 1;
    CloseHandle(hProc);
    return 0;
}
