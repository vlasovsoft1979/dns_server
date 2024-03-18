#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdint.h>
#include <ostream>

#include "dns.h"

namespace {

uint16_t get_uint16(const uint8_t*& data)
{
    uint16_t val = ntohs(*reinterpret_cast<const uint16_t*>(data));
    data += sizeof(uint16_t);
    return val;
}
uint32_t get_uint32(const uint8_t*& data)
{
    uint32_t val = ntohl(*reinterpret_cast<const uint32_t*>(data));
    data += sizeof(uint32_t);
    return val;
}

std::string get_domain(const uint8_t* const orig, const uint8_t*& data)
{
    std::string result;
    const uint8_t* curr = data;
    bool compressed = false;
    while (*curr)
    {
        auto type = curr[0] >> 6;
        if (0 == type)
        {
            auto len = curr[0];
            std::string label(reinterpret_cast<const char*>(curr + 1), len);
            result = result.empty() ?
                label :
                result.append(".").append(label);
            curr += len;
            curr += 1;
            if (!compressed)
            {
                data += len;
                data += 1;
            }
        }
        else if (3 == type)
        {
            curr = orig + (static_cast<uint16_t>(*curr & 0b00111111) << 8) + curr[1];
            if (!compressed)
            {
                data += 2;
            }
            compressed = true;
        }
    }
    if (!compressed)
    {
        data += 1;
    }
    return result;
}

}

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

DNSHeader::DNSHeader(const uint8_t*& data)
    : ID(get_uint16(data))
    , flags(data)
    , QDCOUNT(get_uint16(data))
    , ANCOUNT(get_uint16(data))
    , NSCOUNT(get_uint16(data))
    , ARCOUNT(get_uint16(data))
{
}

DNSRequest::DNSRequest(const uint8_t* const orig, const uint8_t*& data)
    : name(get_domain(orig, data))
    , type(get_uint16(data))
    , cls(get_uint16(data))
{
}

DNSAnswer::DNSAnswer(const uint8_t* const orig, const uint8_t*& data)
    : name(get_domain(orig, data))
    , type(get_uint16(data))
    , cls(get_uint16(data))
    , ttl(get_uint32(data))
{
    uint16_t len = get_uint16(data);
    this->data.reserve(len);
    this->data.insert(this->data.end(), data, data + len);
    data += len;
}

DNSAuthorityServer::DNSAuthorityServer(const uint8_t* const orig, const uint8_t*& data)
    : name(get_domain(orig, data))
    , type(get_uint16(data))
    , cls(get_uint16(data))
    , ttl(get_uint32(data))
    , len(get_uint16(data))
    , primary(get_domain(orig, data))
    , mbox(get_domain(orig, data))
    , serial(get_uint32(data))
    , refresh(get_uint32(data))
    , retry(get_uint32(data))
    , expire(get_uint32(data))
    , ttl_min(get_uint32(data))
{
}

DNSPackage::DNSPackage(const uint8_t* data)
{
    const uint8_t* orig = data;
    header = DNSHeader(data);
    for (auto i = 0; i < header.QDCOUNT; ++i)
    {
        requests.emplace_back(DNSRequest{ orig, data });
    }
    for (auto i = 0; i < header.ANCOUNT; ++i)
    {
        answers.emplace_back(DNSAnswer{ orig, data });
    }
    for (auto i = 0; i < header.NSCOUNT; ++i)
    {
        authorities.emplace_back(DNSAuthorityServer{ orig, data });
    }
}

void DNSPackage::addAnswerTypeA(const std::string& name, const std::string& ip)
{
    DNSAnswer answer;
    answer.name = name;
    answer.type = 1;
    answer.cls = 1;
    answer.ttl = 3600;
    std::vector<uint8_t> data;
    sockaddr_in sa;
    if (0 == inet_pton(AF_INET, ip.c_str(), &sa.sin_addr))
    {
        throw std::runtime_error("invalid IPv4 address");
    }
    answer.data.reserve(4);
    answer.data.push_back(sa.sin_addr.S_un.S_un_b.s_b1);
    answer.data.push_back(sa.sin_addr.S_un.S_un_b.s_b2);
    answer.data.push_back(sa.sin_addr.S_un.S_un_b.s_b3);
    answer.data.push_back(sa.sin_addr.S_un.S_un_b.s_b4);
    answers.push_back(answer);
}

std::ostream& operator << (std::ostream& stream, const DNSHeader& header)
{
    return stream
        << "ID:      " << header.ID << '\n'
        << "QR:      " << header.flags.QR << '\n'
        << "Opcode:  " << header.flags.Opcode << '\n'
        << "AA:      " << header.flags.AA << '\n'
        << "TC:      " << header.flags.TC << '\n'
        << "RD:      " << header.flags.RD << '\n'
        << "RA:      " << header.flags.RA << '\n'
        << "Z:       " << header.flags.Z << '\n'
        << "RCODE:   " << header.flags.RCODE << '\n'
        << "QDCOUNT: " << header.QDCOUNT << '\n'
        << "ANCOUNT: " << header.ANCOUNT << '\n'
        << "NSCOUNT: " << header.NSCOUNT << '\n'
        << "ARCOUNT: " << header.ARCOUNT << '\n'
        ;
}

std::ostream& operator << (std::ostream& stream, const DNSRequest& req)
{
    return stream << req.name << " " << req.type << " " << req.cls << "\n";
}

DNSBuffer::DNSBuffer()
{
    result.reserve(512);
}

void DNSBuffer::append(const DNSPackage& val)
{
    append(val.header);
    for (const auto& elem : val.requests)
    {
        append(elem);
    }
    for (const auto& elem : val.answers)
    {
        append(elem);
    }
    for (const auto& elem : val.authorities)
    {
        append(elem);
    }
}

void DNSBuffer::append(const DNSHeaderFlags& val)
{
    append_uint16(*reinterpret_cast<const uint16_t*>(&val));
}

void DNSBuffer::append(const DNSHeader& val)
{
    append_uint16(val.ID);
    append(val.flags);
    append_uint16(val.QDCOUNT);
    append_uint16(val.ANCOUNT);
    append_uint16(val.NSCOUNT);
    append_uint16(val.ARCOUNT);
}

void DNSBuffer::append(const DNSRequest& val)
{
    append_domain(val.name);
    append_uint16(val.type);
    append_uint16(val.cls);
}

void DNSBuffer::append(const DNSAnswer& val)
{
    append_domain(val.name);
    append_uint16(val.type);
    append_uint16(val.cls);
    append_uint32(val.ttl);
    append_uint16(static_cast<uint16_t>(val.data.size()));
    result.insert(result.end(), val.data.begin(), val.data.end());
}

void DNSBuffer::append(const DNSAuthorityServer& val)
{
    append_domain(val.name);
    append_uint16(val.type);
    append_uint16(val.cls);
    append_uint32(val.ttl);
    append_uint16(val.len);
    append_domain(val.primary);
    append_domain(val.mbox);
    append_uint32(val.serial);
    append_uint32(val.refresh);
    append_uint32(val.retry);
    append_uint32(val.expire);
    append_uint32(val.ttl_min);
}

void DNSBuffer::append_domain(const std::string& str)
{
    if (str.empty())
    {
        result.push_back('\0');
        return;
    }
    auto iter = compress.find(str);
    if (iter != compress.end())
    {
        uint16_t val = static_cast<uint16_t>(iter->second);
        val |= 0xc000;
        append_uint16(val);
    }
    else
    {
        auto prev_size = result.size();
        auto pos = str.find('.');
        if (pos != std::string::npos)
        {
            auto before = str.substr(0, pos);
            append_label(before);
            compress.emplace(str, prev_size);
            auto after = str.substr(pos + 1);
            append_domain(after);
        }
        else
        {
            append_label(str);
            compress.emplace(str, prev_size);
            result.push_back('\0');
        }
    }
}

void DNSBuffer::append_label(const std::string& str)
{
    result.push_back(static_cast<char>(str.size()));
    result.insert(result.end(), str.begin(), str.end());
}

void DNSBuffer::append_uint16(uint16_t val)
{
    val = htons(val);
    const uint8_t* ptr = reinterpret_cast<const uint8_t*>(&val);
    result.insert(result.end(), ptr, ptr + sizeof(val));
}

void DNSBuffer::append_uint32(uint32_t val)
{
    val = htonl(val);
    const uint8_t* ptr = reinterpret_cast<const uint8_t*>(&val);
    result.insert(result.end(), ptr, ptr + sizeof(val));
}