#include "dns_package.h"

#include <stdexcept>

#include <WinSock2.h> // TODO: remove
#include <ws2tcpip.h> // TODO: remove

#include "dns_consts.h"

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

void DNSPackage::append(DNSBuffer& buf) const
{
    header.append(buf);
    for (const auto& elem : requests)
    {
        elem.append(buf);
    }
    for (const auto& elem : answers)
    {
        elem.append(buf);
    }
    for (const auto& elem : authorities)
    {
        elem.append(buf);
    }
}

void DNSPackage::addAnswer(DNSRecordType type, const std::string& name, const std::string& data)
{
    DNSAnswer answer(type, data);
    if (answer.ext.get() != nullptr)
    {
        answer.name = name;
        answer.type = 1;
        answer.cls = 1;
        answer.ttl = 3600;
        answers.push_back(answer);
    }
}
