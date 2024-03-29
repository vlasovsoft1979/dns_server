#pragma once

#include <vector>
#include <string>
#include <memory>
#include <map>

#include "dns_consts.h"
#include "dns_package.h"

class DNSServerImpl;

class DNSServer
{
public:
    DNSServer(const std::string& host, int port);
    DNSServer(const std::string& json);
    ~DNSServer();

    void addRecord(DNSRecordType type, const std::string& host, const std::vector<std::string>& answer);
    void start();
    void join();

private:
    std::unique_ptr<DNSServerImpl> impl;
};

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
