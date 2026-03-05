/*
 * T1003.002 — OS Credential Dumping: SAM.
 * Строки/вызовы для детекта: SAM, SYSTEM, RegSaveKey, reg save HKLM\SAM.
 */
#include <windows.h>
#include <stdio.h>

static const char *sam_str = "SAM";
static const char *system_str = "SYSTEM";
static const char *sec_str = "SECURITY";

int main(void) {
    (void)sam_str;
    (void)system_str;
    (void)sec_str;
    HKEY hSam = NULL, hSys = NULL;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SAM", 0, KEY_READ, &hSam) == ERROR_SUCCESS)
        RegCloseKey(hSam);
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM", 0, KEY_READ, &hSys) == ERROR_SUCCESS)
        RegCloseKey(hSys);
    return 0;
}
