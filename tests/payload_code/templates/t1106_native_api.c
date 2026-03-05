/*
 * T1106 — Native API: загрузка ntdll и вызов NtMapViewOfSection (или аналог) через GetProcAddress.
 * Execution: детект по ntdll, NtMapViewOfSection в строках/импортах и эмуляции.
 */
#include <windows.h>

typedef int (*NtMapViewOfSection_t)(void*, void*, void*, void*, void*, void*, void*, int, int, void*);

int main(void) {
    HMODULE ntdll = LoadLibraryA("ntdll.dll");
    if (!ntdll) return 1;
    NtMapViewOfSection_t pNtMap = (NtMapViewOfSection_t)GetProcAddress(ntdll, "NtMapViewOfSection");
    (void)pNtMap;
    return 0;
}
