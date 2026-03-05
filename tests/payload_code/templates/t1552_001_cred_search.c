/*
 * T1552.001 — Credentials in Files: поиск учётных данных в файлах (password=, .env, config).
 */
#include <windows.h>
#include <stdio.h>

int main(void) {
    WIN32_FIND_DATAA fd = { 0 };
    HANDLE h = FindFirstFileA("*.env", &fd);
    if (h != INVALID_HANDLE_VALUE)
        FindClose(h);
    h = FindFirstFileA("*.config", &fd);
    if (h != INVALID_HANDLE_VALUE)
        FindClose(h);
    return 0;
}
