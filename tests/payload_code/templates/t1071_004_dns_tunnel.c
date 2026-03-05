/*
 * T1071.004 — Application Layer Protocol: DNS (DNS-туннелирование).
 * Exfiltration: DnsQuery_A, dnsapi.
 */
#include <windows.h>
#include <windns.h>
#include <stdio.h>

#pragma comment(lib, "dnsapi")

int main(void) {
    PDNS_RECORD pRec = NULL;
    DNS_STATUS s = DnsQuery_A("example.com", DNS_TYPE_A, DNS_QUERY_STANDARD, NULL, &pRec, NULL);
    if (pRec)
        DnsRecordListFree(pRec, DnsFreeRecordList);
    (void)s;
    return 0;
}
