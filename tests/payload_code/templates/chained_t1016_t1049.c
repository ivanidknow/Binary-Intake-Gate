/* Network Config + Connections: T1016 + T1049 */
#include <windows.h>
#include <iphlpapi.h>
#include <stdlib.h>

#pragma comment(lib, "iphlpapi")

int main(void) {
    ULONG len = 0;
    GetAdaptersInfo(NULL, &len);
    if (len > 0) {
        PIP_ADAPTER_INFO p = (PIP_ADAPTER_INFO)malloc(len);
        if (p) { GetAdaptersInfo(p, &len); free(p); }
    }
    DWORD size = 0;
    GetTcpTable(NULL, &size, FALSE);
    if (size > 0) {
        PMIB_TCPTABLE t = (PMIB_TCPTABLE)malloc(size);
        if (t) { GetTcpTable(t, &size, FALSE); free(t); }
    }
    return 0;
}
