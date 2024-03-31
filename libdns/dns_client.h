#pragma once

#include <string>

#include "dns_consts.h"
#include "dns_package.h"

class DNSClient
{
public:
    DNSClient(const std::string& host, int port);

    bool command(const std::string& cmd);
    DNSPackage requestUdp(uint16_t id, DNSRecordType type, const std::string& host);
    DNSPackage requestTcp(uint16_t id, DNSRecordType type, const std::string& host);

private:
    std::string host;
    int port;
};

