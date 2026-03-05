/*
 * T1070.004 — File Deletion / Self-deletion. DeleteFile, MoveFileEx DELAY_UNTIL_REBOOT.
 */
#include <windows.h>

int main(void) {
    char self[MAX_PATH];
    GetModuleFileNameA(NULL, self, MAX_PATH);
    DeleteFileA("C:\\Windows\\Temp\\artifact.tmp");
    MoveFileExA(self, NULL, MOVEFILE_DELAY_UNTIL_REBOOT);
    return 0;
}
