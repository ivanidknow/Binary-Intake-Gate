/*
 * T1012 — Query Registry: RegOpenKeyEx, RegQueryValueEx (HKLM CurrentVersion).
 * Discovery: детект по путям реестра и эмуляции.
 */
#include <windows.h>

int main(void) {
    HKEY hKey = NULL;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
            "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return 1;
    char buf[256] = { 0 };
    DWORD sz = sizeof(buf);
    RegQueryValueExA(hKey, "ProductName", NULL, NULL, (LPBYTE)buf, &sz);
    RegCloseKey(hKey);
    return 0;
}
