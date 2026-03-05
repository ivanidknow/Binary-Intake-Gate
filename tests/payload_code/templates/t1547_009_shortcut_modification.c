/*
 * T1547.009 — Shortcut Modification. Persistence via Start Menu path, .lnk target strings.
 * SetPath/IShellLink pattern in strings for static detection; CreateDirectory for Start Menu.
 */
#include <windows.h>

static const char *start_menu = "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup";
static const char *lnk_target = "C:\\Windows\\System32\\cmd.exe";

int main(void) {
    (void)lnk_target;
    CreateDirectoryA(start_menu, NULL);
    return 0;
}
