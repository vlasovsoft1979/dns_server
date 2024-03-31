#include "dns_buffer.h"

#if defined(_WIN32)
#include <WinSock2.h>
#else
#include <arpa/inet.h>
#endif

#include "dns_utils.h"

DNSBuffer::DNSBuffer()
    : data_start(0u)
    , max_size(0u)
{
    result.reserve(512);
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
        append(val);
    }
    else
    {
        auto offset = result.size() - data_start;
        auto pos = str.find('.');
        if (pos != std::string::npos)
        {
            auto before = str.substr(0, pos);
            append_label(before);
            compress.emplace(str, offset);
            auto after = str.substr(pos + 1);
            append_domain(after);
        }
        else
        {
            append_label(str);
            compress.emplace(str, offset);
            result.push_back('\0');
        }
    }
}

void DNSBuffer::append_label(const std::string& str)
{
    result.push_back(static_cast<uint8_t>(str.size()));
    result.insert(result.end(), str.begin(), str.end());
}

void DNSBuffer::append(uint16_t val)
{
    ::append_uint16(result, val);
}

void DNSBuffer::append(uint32_t val)
{
    ::append_uint32(result, val);
}

void DNSBuffer::append(uint8_t val)
{
    result.push_back(val);
}

void DNSBuffer::append(const uint8_t* ptr, size_t size)
{
    result.insert(result.end(), ptr, ptr + size);
}

void DNSBuffer::overwrite_uint16(size_t pos, uint16_t val)
{
    *reinterpret_cast<uint16_t*>(&result[pos]) = htons(val);
}

void DNSBuffer::clear()
{
    data_start = 0u;
    max_size = 0u;
    result.clear();
    compress.clear();
}
