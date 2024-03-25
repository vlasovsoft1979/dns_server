#include "dns_answer.h"

#include <stdexcept>

#include <WinSock2.h> // TODO: remove
#include <WS2tcpip.h> // TODO: remove

#include "dns_utils.h"
#include "dns_buffer.h"

class DNSAnswerExt
{
public:
    virtual void append(DNSBuffer&) const = 0;
};

class DNSAnswerExtA : public DNSAnswerExt
{
public:
    DNSAnswerExtA(const uint8_t* const orig, const uint8_t*& data)
    {
        auto len = get_uint16(data);
        if (len != sizeof(addr))
        {
            throw std::runtime_error("invalid DNS answer of type A");
        }
        std::copy(data, data + 4, addr);
        data += len;
    }
    DNSAnswerExtA(const std::string& data)
    {
        if (!str_to_ipv4(data, addr))
        {
            std::fill(addr, addr + 4, 0);
        }
    }
    virtual ~DNSAnswerExtA() {}
    virtual void append(DNSBuffer& buf) const override
    {
        buf.append(static_cast<uint16_t>(sizeof(addr)));
        buf.append(addr, sizeof(addr));
    }

private:
    uint8_t addr[4];
};

class DNSAnswerExtTxt : public DNSAnswerExt
{
public:
    DNSAnswerExtTxt(const uint8_t* const orig, const uint8_t*& data)
    {
        uint16_t size = get_uint16(data);
        uint8_t len = get_uint8(data);
        text = get_string(data, len);
    }
    DNSAnswerExtTxt(const std::string& text)
        : text(text)
    {}
    virtual void append(DNSBuffer& buf) const override
    {
        buf.append(static_cast<uint16_t>(text.size() + sizeof(uint8_t)));
        buf.append_label(text);
    }

private:
    std::string text;
};

class DNSAnswerExtMx : public DNSAnswerExt
{
public:
    DNSAnswerExtMx(const uint8_t* const orig, const uint8_t*& data)
        : preference(10)
    {
        auto len = get_uint16(data);
        preference = get_uint16(data);
        text = get_domain(orig, data);
    }
    DNSAnswerExtMx(const std::string& text)
        : text(text)
        , preference(10)
    {}
    virtual void append(DNSBuffer& buf) const override
    {
        size_t pos = buf.result.size();
        buf.append(static_cast<uint16_t>(0));  // SIZE (will be calculated later)
        buf.append(preference);
        buf.append_domain(text);
        // little hack: overwrite calculated size
        buf.overwrite_uint16(pos, static_cast<uint16_t>(buf.result.size() - pos - sizeof(uint16_t)));
    }

private:
    uint16_t preference;
    std::string text;
};

class DNSAnswerExtCname : public DNSAnswerExt
{
public:
    DNSAnswerExtCname(const uint8_t* const orig, const uint8_t*& data)
    {
        auto len = get_uint16(data);
        text = get_domain(orig, data);
    }
    DNSAnswerExtCname(const std::string& data)
        : text(data)
    {}
    virtual void append(DNSBuffer& buf) const override
    {
        size_t pos = buf.result.size();
        buf.append(static_cast<uint16_t>(0));  // SIZE (will be calculated later)
        buf.append_domain(text);
        // little hack: overwrite calculated size
        buf.overwrite_uint16(pos, static_cast<uint16_t>(buf.result.size() - pos - sizeof(uint16_t)));
    }

private:
    std::string text;
};

class DNSAnswerExtPtr : public DNSAnswerExt
{
public:
    DNSAnswerExtPtr(const uint8_t* const orig, const uint8_t*& data)
    {
        auto len = get_uint16(data);
        host = get_domain(orig, data);
    }
    DNSAnswerExtPtr(const std::string& data)
        : host(data)
    {}
    virtual void append(DNSBuffer& buf) const override
    {
        size_t pos = buf.result.size();
        buf.append(static_cast<uint16_t>(0));  // SIZE (will be calculated later)
        buf.append_domain(host);
        // little hack: overwrite calculated size
        buf.overwrite_uint16(pos, static_cast<uint16_t>(buf.result.size() - pos - sizeof(uint16_t)));
    }

private:
    std::string host;
};


DNSAnswer::DNSAnswer(DNSRecordType type, const std::string& data)
    : type(static_cast<uint16_t>(type))
    , cls(0)
    , ttl(0)
{
    switch (type)
    {
    case DNSRecordType::A:
        ext.reset(new DNSAnswerExtA{ data });
        break;
    case DNSRecordType::CNAME:
        ext.reset(new DNSAnswerExtCname{ data });
        break;
    case DNSRecordType::PTR:
        ext.reset(new DNSAnswerExtPtr{ data });
        break;
    case DNSRecordType::MX:
        ext.reset(new DNSAnswerExtMx{ data });
        break;
    case DNSRecordType::TXT:
        ext.reset(new DNSAnswerExtTxt{ data });
        break;
    default:
        break;
    }
}

DNSAnswer::DNSAnswer(const uint8_t* const orig, const uint8_t*& data)
    : name(get_domain(orig, data))
    , type(get_uint16(data))
    , cls(get_uint16(data))
    , ttl(get_uint32(data))
{
    switch (static_cast<DNSRecordType>(type))
    {
    case DNSRecordType::A:
        ext.reset(new DNSAnswerExtA{ orig, data });
        break;
    case DNSRecordType::MX:
        ext.reset(new DNSAnswerExtMx{ orig, data });
        break;
    case DNSRecordType::TXT:
        ext.reset(new DNSAnswerExtTxt{ orig, data });
        break;
    case DNSRecordType::CNAME:
        ext.reset(new DNSAnswerExtCname{ orig, data });
        break;
    case DNSRecordType::PTR:
        ext.reset(new DNSAnswerExtPtr{ orig, data });
        break;
    default:
        break;
    }
}

DNSAnswer::~DNSAnswer()
{}

void DNSAnswer::append(DNSBuffer& buf) const
{
    buf.append_domain(name);
    buf.append(type);
    buf.append(cls);
    buf.append(ttl);
    if (ext)
    {
        ext->append(buf);
    }
}
