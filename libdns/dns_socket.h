#pragma once

#ifdef _WIN32
#include <WinSock2.h>
typedef int socklen_t;
#else
typedef int SOCKET;
#define INVALID_SOCKET -1
#define SOCKET_ERROR -1
void closesocket(SOCKET s);
#endif

bool setupsocket(SOCKET fd);
