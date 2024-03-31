#include <sys/select.h>

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

    int size = 0;
    if (!rsockets.empty())
    {
        size = std::max(size, *rsockets.rbegin() + 1);
    }
    if (!wsockets.empty())
    {
        size = std::max(size, *wsockets.rbegin() + 1);
    }

    int result = ::select(size, &rset, &wset, nullptr, nullptr);
    if (result == SOCKET_ERROR)
    {
        return result;
    }

    for (auto i = 0; i < size; i++)
    {
        if (FD_ISSET(i, &rset))
        {
            handler->socketReadyRead(static_cast<SOCKET>(i));
        }
        if (FD_ISSET(i, &wset))
        {
            handler->socketReadyWrite(static_cast<SOCKET>(i));
        }
    }

    return result;
}
