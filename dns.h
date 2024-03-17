#pragma once

#include <vector>
#include <string>
#include <map>

struct DNSHeaderFlags
{
public:
    DNSHeaderFlags() = default;
    DNSHeaderFlags(const uint8_t*& data);

public:
    uint16_t QR : 1;      // 0=request, 1=response
    uint16_t Opcode : 4;  // 0=standard, 1=inverse, 2=status, 3..15=reserved
    uint16_t AA : 1;      // response only, 1=authority answer
    uint16_t TC : 1;      // response only, 1=truncated
    uint16_t RD : 1;      // don't provide intermediate info
    uint16_t RA : 1;      // response only, 1=server supports recursion
    uint16_t Z : 3;       // reserved, always 0
    uint16_t RCODE : 4;   // response only, query result
};

struct DNSHeader
{
public:
    DNSHeader() = default;
    DNSHeader(const uint8_t*& data);

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
    DNSRequest(const uint8_t* const orig, const uint8_t*& data);

public:
    std::string name;
    uint16_t type;
    uint16_t cls;
};

struct DNSAnswer
{
public:
    DNSAnswer(const uint8_t* const orig, const uint8_t*& data);

public:
    std::string name;
    uint16_t type;
    uint16_t cls;
    uint32_t ttl;
    std::vector<uint8_t> data;
};

class DNSPackage
{
public:
    DNSPackage(const uint8_t* data);

public:
    DNSHeader header;
    std::vector<DNSRequest> requests;
    std::vector<DNSAnswer> answers;
};

class DNSBuffer
{
public:
    DNSBuffer();

    void append(const DNSPackage& val);
    const std::vector<uint8_t> getResult() const;

private:
    void append(const DNSHeaderFlags& val);
    void append(const DNSHeader& val);
    void append(const DNSRequest& val);
    void append(const DNSAnswer& val);
    void append_domain(const std::string& str);
    void append_label(const std::string& str);
    void append_uint16(const uint16_t val);
    void append_uint32(const uint32_t val);

    std::vector<uint8_t> result;
    std::map<std::string, size_t> compress;
};
