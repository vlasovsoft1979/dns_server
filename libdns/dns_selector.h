#pragma once

#include <set>

#include "dns_socket.h"

class ISocketHandler
{
public:
    virtual void socketReadyRead(SOCKET s) = 0;
    virtual void socketReadyWrite(SOCKET s) = 0;
};

class DNSSelector
{
public:
    DNSSelector(ISocketHandler* handler)
        : handler(handler)
    {}

    void addReadSocket(SOCKET s);
    void removeReadSocket(SOCKET s);
    void addWriteSocket(SOCKET s);
    void removeWriteSocket(SOCKET s);
    int select();

private:
    ISocketHandler* handler;
    std::set<SOCKET> rsockets;
    std::set<SOCKET> wsockets;
};
