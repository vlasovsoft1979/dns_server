#pragma once

#include <string>
#include <memory>

#include "dns_consts.h"

class DNSBuffer;
class DNSAnswerExt;

struct DNSAnswer
{
public:
    DNSAnswer(DNSRecordType type, const std::string& data);
    DNSAnswer(const uint8_t* const orig, const uint8_t*& data);
    ~DNSAnswer();

    void append(DNSBuffer& buf) const;

public:
    std::string name;
    uint16_t type;
    uint16_t cls;
    uint32_t ttl;
    std::shared_ptr<DNSAnswerExt> ext;
};
