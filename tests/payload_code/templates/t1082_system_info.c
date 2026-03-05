/*
 * T1082 — System Information Discovery: GetComputerNameA, GetVersionExA.
 * Discovery: детект по строкам и эмуляции API.
 */
#include <windows.h>
#include <stdio.h>

int main(void) {
    char name[256] = { 0 };
    DWORD len = 256;
    GetComputerNameA(name, &len);
    OSVERSIONINFOA vi = { sizeof(vi) };
    GetVersionExA(&vi);
    (void)vi.dwMajorVersion;
    return 0;
}
