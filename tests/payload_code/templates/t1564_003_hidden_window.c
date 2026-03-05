/*
 * T1564.003 — Hidden Window. CREATE_NO_WINDOW, SW_HIDE, ShowWindow.
 * Строка для статической детекции (макросы в бинарнике не видны).
 */
#include <windows.h>

static const char *hidden_window_hint = "STARTF_USESHOWWINDOW";

int main(void) {
    (void)hidden_window_hint;
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    char cmd[] = "cmd.exe /c dir";
    CreateProcessA(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    if (pi.hProcess) CloseHandle(pi.hProcess);
    if (pi.hThread) CloseHandle(pi.hThread);
    return 0;
}
