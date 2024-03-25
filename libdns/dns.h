#pragma once

#include <vector>
#include <string>
#include <memory>
#include <map>

#include "dns_consts.h"
#include "dns_header.h"

class DNSBuffer;

class DNSRequest
{
public:
    DNSRequest();
    DNSRequest(const uint8_t* const orig, const uint8_t*& data);

    void append(DNSBuffer& buf) const;

public:
    std::string name;
    uint16_t type;
    uint16_t cls;
};

class DNSAnswerExt;

struct DNSAnswer
{
public:
    DNSAnswer();
    DNSAnswer(const uint8_t* const orig, const uint8_t*& data);
    ~DNSAnswer();

    void append(DNSBuffer& buf) const;

public:
    std::string name;
    uint16_t type;
    uint16_t cls;
    uint32_t ttl;
    std::shared_ptr<DNSAnswerExt> ext;
};

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

class DNSPackage
{
public:
    DNSPackage() {}
    DNSPackage(const uint8_t* data);

    void append(DNSBuffer& buf) const;

    void addAnswerTypeA(const std::string& name, const std::string& ip);
    void addAnswerTypeTxt(const std::string& name, const std::string& text);
    void addAnswerTypeMx(const std::string& name, const std::string& text);
    void addAnswerTypeCname(const std::string& name, const std::string& text);
    void addAnswerTypePtr(const std::string& name, const std::string& text);

public:
    DNSHeader header;
    std::vector<DNSRequest> requests;
    std::vector<DNSAnswer> answers;
    std::vector<DNSAuthorityServer> authorities;
};

class DNSServerImpl;

class DNSServer
{
public:
    DNSServer(const std::string& host, int port);
    DNSServer(const std::string& json);
    ~DNSServer();

    void addRecord(DNSRecordType type, const std::string& host, const std::vector<std::string>& answer);
    void process();

private:
    std::unique_ptr<DNSServerImpl> impl;
};