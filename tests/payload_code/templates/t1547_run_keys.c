/*
 * T1547.001 — Registry Run Keys: реальные RegOpenKeyEx, RegSetValueEx для автозагрузки.
 * Persistence: детект по путям Run/RunOnce и эмуляции RegSetValue.
 */
#include <windows.h>

int main(void) {
    HKEY hKey = NULL;
    const char *path = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
    if (RegOpenKeyExA(HKEY_CURRENT_USER, path, 0, KEY_SET_VALUE, &hKey) != ERROR_SUCCESS)
        return 1;
    const char *value = "T1547_001_test";
    const char *data = "cmd.exe /c echo persistence";
    RegSetValueExA(hKey, value, 0, REG_SZ, (const BYTE *)data, (DWORD)strlen(data) + 1);
    RegCloseKey(hKey);
    return 0;
}
