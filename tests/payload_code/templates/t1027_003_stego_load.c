/*
 * T1027.003 — Steganography: загрузка/чтение данных из ресурса (LSB-подобный сценарий).
 * Defense Evasion: детект по работе с ресурсами/бинарными данными.
 */
#include <windows.h>
#include <stdio.h>

int main(void) {
    HMODULE hMod = GetModuleHandleA(NULL);
    if (hMod) {
        HRSRC res = FindResourceA(hMod, "STEGO", "DATA");
        if (res) {
            HGLOBAL g = LoadResource(hMod, res);
            if (g) {
                void *p = LockResource(g);
                (void)p;
            }
        }
    }
    return 0;
}
