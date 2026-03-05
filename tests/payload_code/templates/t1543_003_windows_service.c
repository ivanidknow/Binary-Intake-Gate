/*
 * T1543.003 — Windows Service: OpenSCManager, CreateServiceA.
 * Persistence: детект по строкам и эмуляции SCM API.
 */
#include <windows.h>

int main(void) {
    SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) return 1;
    SC_HANDLE svc = CreateServiceA(scm, "T1543Test", "T1543Test", SERVICE_ALL_ACCESS,
            SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE,
            "C:\\Windows\\System32\\drivers\\null.sys", NULL, NULL, NULL, NULL, NULL);
    if (svc) CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return 0;
}
