#pragma once

#include <vector>

#include "dns_header.h"
#include "dns_request.h"
#include "dns_answer.h"
#include "dns_auth_server.h"

class DNSPackage
{
public:
    DNSPackage() {}
    DNSPackage(const uint8_t* data);

    void append(DNSBuffer& buf) const;

    void addAnswer(DNSRecordType type, const std::string& name, const std::string& data);

public:
    DNSHeader header;
    std::vector<DNSRequest> requests;
    std::vector<DNSAnswer> answers;
    std::vector<DNSAuthorityServer> authorities;
};
