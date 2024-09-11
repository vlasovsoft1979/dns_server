#pragma once

#include <vector>
#include <string>
#include <memory>
#include <map>
#include <iosfwd>

#include "dns_consts.h"
#include "dns_package.h"

class DNSServerImpl;

class ILogger
{
public:
    virtual std::ostream& log() = 0;
};

class DNSServer
{
public:
    DNSServer(const std::string& host, int port, ILogger* logger = nullptr);
    DNSServer(const std::string& json, ILogger* logger = nullptr);
    ~DNSServer();

    void addRecord(DNSRecordType type, const std::string& host, const std::vector<std::string>& answer);
    void start();
    void join();

private:
    std::unique_ptr<DNSServerImpl> impl;
};

