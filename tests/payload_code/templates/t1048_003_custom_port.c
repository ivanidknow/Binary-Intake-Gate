/*
 * T1048.003 — Exfiltration Over Alternative Protocol: нестандартный порт (1337, 4444).
 * Winsock: WSAStartup, socket, connect.
 */
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>

#pragma comment(lib, "ws2_32")

int main(void) {
    WSADATA wsa = { 0 };
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
        return 1;
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s != INVALID_SOCKET) {
        struct sockaddr_in addr = { 0 };
        addr.sin_family = AF_INET;
        addr.sin_port = htons(1337);
        addr.sin_addr.s_addr = inet_addr("127.0.0.1");
        connect(s, (struct sockaddr *)&addr, sizeof(addr));
        closesocket(s);
    }
    WSACleanup();
    return 0;
}
