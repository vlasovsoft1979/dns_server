#pragma once

#include <string>

#include "dns_consts.h"

class DNSBuffer;

class DNSRequest
{
public:
    DNSRequest();
    DNSRequest(DNSRecordType type, const std::string& name);
    DNSRequest(const uint8_t* const orig, const uint8_t*& data);

    void append(DNSBuffer& buf) const;

public:
    std::string name;
    uint16_t type;
    uint16_t cls;
};
