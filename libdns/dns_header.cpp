#include "dns_header.h"
#include "dns_utils.h"
#include "dns_buffer.h"

DNSHeaderFlags::DNSHeaderFlags()
    : QR(0)
    , Opcode(0)
    , AA(0)
    , TC(0)
    , RD(0)
    , RA(0)
    , Z(0)
    , RCODE(0)
{}

DNSHeaderFlags::DNSHeaderFlags(const uint8_t*& data)
{
    uint16_t val = get_uint16(data);
    *this = *reinterpret_cast<const DNSHeaderFlags*>(&val);
}

void DNSHeaderFlags::append(DNSBuffer& buf) const
{
    buf.append(*reinterpret_cast<const uint16_t*>(this));
}

DNSHeader::DNSHeader()
    : ID(0)
    , QDCOUNT(0)
    , ANCOUNT(0)
    , NSCOUNT(0)
    , ARCOUNT(0)
{}

DNSHeader::DNSHeader(const uint8_t*& data)
    : ID(get_uint16(data))
    , flags(data)
    , QDCOUNT(get_uint16(data))
    , ANCOUNT(get_uint16(data))
    , NSCOUNT(get_uint16(data))
    , ARCOUNT(get_uint16(data))
{}

void DNSHeader::append(DNSBuffer& buf) const
{
    buf.append(ID);
    flags.append(buf);
    buf.append(QDCOUNT);
    buf.append(ANCOUNT);
    buf.append(NSCOUNT);
    buf.append(ARCOUNT);
}
