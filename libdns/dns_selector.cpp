#include "dns_selector.h"

void DNSSelector::addReadSocket(SOCKET s)
{
    rsockets.insert(s);
}

void DNSSelector::removeReadSocket(SOCKET s)
{
    rsockets.erase(s);
}

void DNSSelector::addWriteSocket(SOCKET s)
{
    wsockets.insert(s);
}

void DNSSelector::removeWriteSocket(SOCKET s)
{
    wsockets.erase(s);
}
