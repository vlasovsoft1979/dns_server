#include "dns_utils.h"

#include <unordered_map>
#include <algorithm>
#include <WinSock2.h>
#include <WS2tcpip.h>

uint8_t get_uint8(const uint8_t*& data)
{
    uint8_t val = *data;
    data += sizeof(uint8_t);
    return val;
}

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

std::string get_string(const uint8_t*& data, size_t len)
{
    std::string result(reinterpret_cast<const char*>(data), len);
    data += len;
    return result;
}

void append_uint16(std::vector<uint8_t>& buf, uint16_t val)
{
    val = htons(val);
    const uint8_t* ptr = reinterpret_cast<const uint8_t*>(&val);
    buf.insert(buf.end(), ptr, ptr + sizeof(val));
}

void append_uint32(std::vector<uint8_t>& buf, uint32_t val)
{
    val = htonl(val);
    const uint8_t* ptr = reinterpret_cast<const uint8_t*>(&val);
    buf.insert(buf.end(), ptr, ptr + sizeof(val));
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
            curr += static_cast<size_t>(len) + 1u;
            if (!compressed)
            {
                data += static_cast<size_t>(len) + 1u;
            }
        }
        else if (3 == type)
        {
            curr = orig + (static_cast<size_t>(curr[0] & 0x3F) << 8) + curr[1];
            if (!compressed)
            {
                data += 2u;
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

DNSRecordType StrToRecType(const std::string& str)
{
    static const std::unordered_map<std::string, DNSRecordType> map = {
        {"A", DNSRecordType::A},
        {"CNAME", DNSRecordType::CNAME},
        {"PTR", DNSRecordType::PTR},
        {"MX", DNSRecordType::MX},
        {"TXT", DNSRecordType::TXT},
    };
    std::string strUpper{ str };
    std::transform(str.begin(), str.end(), strUpper.begin(), std::toupper);
    const auto iter = map.find(strUpper);
    return iter != map.end() ? iter->second : DNSRecordType::OTHER;
}

bool str_to_ipv4(const std::string& val, uint8_t out[4])
{
    return 0 != inet_pton(AF_INET, val.c_str(), out);
}

bool str_to_ipv6(const std::string& val, uint8_t out[16])
{
    return 0 != inet_pton(AF_INET6, val.c_str(), out);
}

std::string ipv4_to_str(uint8_t addr[4])
{
    char buf[INET_ADDRSTRLEN] = {0};
    inet_ntop(AF_INET, addr, buf, INET_ADDRSTRLEN);
    return std::string(buf);
}

std::string ipv6_to_str(uint8_t addr[16])
{
    char buf[INET6_ADDRSTRLEN] = { 0 };
    inet_ntop(AF_INET6, addr, buf, INET_ADDRSTRLEN);
    return std::string(buf);
}
