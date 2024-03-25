#pragma once

#include <cstdint>

class DNSBuffer;

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
