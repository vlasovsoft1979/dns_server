#pragma once

#include "dns_selector.h"

int DNSSelector::select()
{
    fd_set rset;
    FD_ZERO(&rset);
    for (const auto s : rsockets)
    {
        FD_SET(s, &rset);
    }
    
    fd_set wset;
    FD_ZERO(&wset);
    for (const auto s : wsockets)
    {
        FD_SET(s, &wset);
    }

    int result = ::select(0, &rset, &wset, nullptr, nullptr);
    if (result == SOCKET_ERROR)
    {
        return result;
    }

    for (auto i = 0u; i < rset.fd_count; i++)
    {
        handler->socketReadyRead(rset.fd_array[i]);
    }

    for (auto i = 0u; i < wset.fd_count; i++)
    {
        handler->socketReadyWrite(wset.fd_array[i]);
    }

    return result;
}
