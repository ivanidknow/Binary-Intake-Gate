/* Process Discovery + Injection: T1057 + T1055 */
#include <windows.h>
#include <tlhelp32.h>

int main(void) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe = { sizeof(pe) };
        Process32First(snap, &pe);
        CloseHandle(snap);
    }
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
    if (hProc) {
        VirtualAllocEx(hProc, NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        CloseHandle(hProc);
    }
    return 0;
}
