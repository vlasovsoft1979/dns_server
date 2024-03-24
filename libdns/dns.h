#pragma once

#include <vector>
#include <string>
#include <memory>
#include <map>

enum class DNSRecordType : uint16_t
{
    OTHER = 0,
    A = 1,
    CNAME = 5,
    MX = 15,
    TXT = 16,
};

enum class DNSResultCode
{
    NoError = 0,
    FormatError = 1,
    ServerFailure = 2,
    NameError = 3,
    NotImplemented = 4,
    Refused = 5
};

class DNSBuffer;

DNSRecordType StrToRecType(const std::string& str);

struct DNSHeaderFlags
{
public:
    DNSHeaderFlags();
    DNSHeaderFlags(const uint8_t*& data);

    void append(DNSBuffer& buf) const;

public:
    uint16_t RCODE : 4;   // response only, query result
    uint16_t Z : 3;       // reserved, always 0
    uint16_t RA : 1;      // response only, 1=server supports recursion
    uint16_t RD : 1;      // 1=recursion desired
    uint16_t TC : 1;      // response only, 1=truncated
    uint16_t AA : 1;      // response only, 1=authority answer
    uint16_t Opcode : 4;  // 0=standard, 1=inverse, 2=status, 3..15=reserved
    uint16_t QR : 1;      // 0=request, 1=response
};

struct DNSHeader
{
public:
    DNSHeader();
    DNSHeader(const uint8_t*& data);

    void append(DNSBuffer& buf) const;

public:
    uint16_t ID;          // query id
    DNSHeaderFlags flags;
    uint16_t QDCOUNT;     // number of records in query section
    uint16_t ANCOUNT;     // number of records in answer section
    uint16_t NSCOUNT;     // number of records in authority section
    uint16_t ARCOUNT;     // number of records in additional record section
};

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

public:
    DNSHeader header;
    std::vector<DNSRequest> requests;
    std::vector<DNSAnswer> answers;
    std::vector<DNSAuthorityServer> authorities;
};

class DNSBuffer
{
public:
    DNSBuffer();

    void clear();

    void append_domain(const std::string& str);
    void append_label(const std::string& str);
    void append(const uint16_t val);
    void append(const uint32_t val);
    void append(const uint8_t val);
    void append(const uint8_t* ptr, size_t size);

    void overwrite_uint16(size_t pos, uint16_t val);
public:
    size_t data_start;
    size_t max_size;
    std::vector<uint8_t> result;

private:
    std::map<std::string, size_t> compress;
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