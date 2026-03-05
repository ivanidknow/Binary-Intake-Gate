/*
 * T1552.001 — Credentials in Files: поиск файлов с password, .env, credentials.
 * Credential Access: детект по путям и FindFirstFile/ReadFile.
 */
#include <windows.h>

int main(void) {
    WIN32_FIND_DATAA fd = { 0 };
    HANDLE h = FindFirstFileA("*.env", &fd);
    if (h != INVALID_HANDLE_VALUE)
        FindClose(h);
    return 0;
}
