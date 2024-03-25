#pragma once

#include <string>

class DNSBuffer;

struct DNSAuthorityServer
{
public:
    DNSAuthorityServer();
    DNSAuthorityServer(const uint8_t* const orig, const uint8_t*& data);

    void append(DNSBuffer& buf) const;

public:
    std::string name;
    uint16_t type;
    uint16_t cls;
    uint32_t ttl;
    uint16_t len;
    std::string primary;
    std::string mbox;
    uint32_t serial;
    uint32_t refresh;
    uint32_t retry;
    uint32_t expire;
    uint32_t ttl_min;
};
