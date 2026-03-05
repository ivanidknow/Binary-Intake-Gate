/*
 * T1016 — System Network Configuration Discovery. GetAdaptersInfo / GetAdaptersAddresses.
 */
#include <windows.h>
#include <iphlpapi.h>
#include <stdlib.h>

#pragma comment(lib, "iphlpapi")

int main(void) {
    ULONG bufLen = 0;
    GetAdaptersInfo(NULL, &bufLen);
    if (bufLen > 0) {
        PIP_ADAPTER_INFO buf = (PIP_ADAPTER_INFO)malloc(bufLen);
        if (buf && GetAdaptersInfo(buf, &bufLen) == NO_ERROR)
            free(buf);
    }
    return 0;
}
