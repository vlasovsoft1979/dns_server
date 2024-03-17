#include <winsock2.h>
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
            curr = orig + ((static_cast<int>(*curr) & 0b00111111) << 8) + curr[1];
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

DNSHeaderFlags::DNSHeaderFlags(const uint8_t*& data)
{
    *this = *reinterpret_cast<const DNSHeaderFlags*>(data);
    data += sizeof(DNSHeaderFlags);
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
    for (const auto& query : val.requests)
    {
        append(query);
    }
    for (const auto& answer : val.answers)
    {
        append(answer);
    }
}

const std::vector<uint8_t> DNSBuffer::getResult() const
{
    return result;
}

void DNSBuffer::append(const DNSHeaderFlags& val)
{
    const char* begin = reinterpret_cast<const char*>(&val);
    const char* end = begin + sizeof(DNSHeaderFlags);
    result.insert(result.end(), begin, end);
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
    append_uint16(val.data.size());
    result.insert(result.end(), val.data.begin(), val.data.end());
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