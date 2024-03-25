#pragma once

#include <string>
#include <map>
#include <vector>

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
