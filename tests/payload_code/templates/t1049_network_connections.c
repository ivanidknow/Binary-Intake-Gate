/*
 * T1049 — System Network Connections Discovery. GetTcpTable / GetExtendedTcpTable.
 */
#include <windows.h>
#include <iphlpapi.h>
#include <stdlib.h>

#pragma comment(lib, "iphlpapi")

int main(void) {
    DWORD size = 0;
    GetTcpTable(NULL, &size, FALSE);
    if (size > 0) {
        PMIB_TCPTABLE p = (PMIB_TCPTABLE)malloc(size);
        if (p && GetTcpTable(p, &size, FALSE) == NO_ERROR)
            free(p);
    }
    return 0;
}
