#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdint.h>
#include <ostream>
#include <fstream>
#include <json/json.h>

#include "dns.h"

namespace {

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

void DNSHeaderFlags::append(DNSBuffer& buf) const
{
    buf.append(*reinterpret_cast<const uint16_t*>(this));
}

DNSHeader::DNSHeader()
    : ID(0)
    , QDCOUNT(0)
    , ANCOUNT(0)
    , NSCOUNT(0)
    , ARCOUNT(0)
{}

DNSHeader::DNSHeader(const uint8_t*& data)
    : ID(get_uint16(data))
    , flags(data)
    , QDCOUNT(get_uint16(data))
    , ANCOUNT(get_uint16(data))
    , NSCOUNT(get_uint16(data))
    , ARCOUNT(get_uint16(data))
{}

void DNSHeader::append(DNSBuffer& buf) const
{
    buf.append(ID);
    flags.append(buf);
    buf.append(QDCOUNT);
    buf.append(ANCOUNT);
    buf.append(NSCOUNT);
    buf.append(ARCOUNT);
}

DNSRequest::DNSRequest()
    : type(0)
    , cls(0)
{}

DNSRequest::DNSRequest(const uint8_t* const orig, const uint8_t*& data)
    : name(get_domain(orig, data))
    , type(get_uint16(data))
    , cls(get_uint16(data))
{}

void DNSRequest::append(DNSBuffer& buf) const
{
    buf.append_domain(name);
    buf.append(type);
    buf.append(cls);
}

class DNSAnswerExt
{
public:
    virtual void append(DNSBuffer&) = 0;
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
        for (int i = 0; i < len; ++i)
        {
            addr[i] = data[i];
        }
        data += len;
    }
    DNSAnswerExtA(uint8_t a[4])
    {
        for (auto i = 0; i < sizeof(a); ++i)
        {
            addr[i] = a[i];
        }
    }
    virtual ~DNSAnswerExtA() {}
    virtual void append(DNSBuffer& buf) override
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
    virtual void append(DNSBuffer& buf) override
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
    virtual void append(DNSBuffer& buf) override
    {
        size_t pos = buf.result.size();
        buf.append(static_cast<uint16_t>(0));  // SIZE (will be calculated later)
        buf.append(preference);
        buf.append_domain(text);
        // little hack: overwrite calculated size
        size_t size = buf.result.size() - pos - 2;
        if (size != 0)
        {
            *reinterpret_cast<uint16_t*>(&buf.result[pos]) = htons(static_cast<uint16_t>(size));
        }
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
    DNSAnswerExtCname(const std::string& text)
        : text(text)
    {}
    virtual void append(DNSBuffer& buf) override
    {
        size_t pos = buf.result.size();
        buf.append(static_cast<uint16_t>(0));  // SIZE (will be calculated later)
        buf.append_domain(text);
        // little hack: overwrite calculated size
        size_t size = buf.result.size() - pos - 2;
        if (size != 0)
        {
            *reinterpret_cast<uint16_t*>(&buf.result[pos]) = htons(static_cast<uint16_t>(size));
        }
    }

private:
    std::string text;
};

DNSAnswer::DNSAnswer()
    : type(0)
    , cls(0)
    , ttl(0)
{}

DNSAnswer::DNSAnswer(const uint8_t* const orig, const uint8_t*& data)
    : name(get_domain(orig, data))
    , type(get_uint16(data))
    , cls(get_uint16(data))
    , ttl(get_uint32(data))
{
    switch (static_cast<DNSRecordType>(type))
    {
    case DNSRecordType::A:
        ext = std::make_shared<DNSAnswerExtA>(orig, data);
        break;
    case DNSRecordType::MX:
        ext = std::make_shared<DNSAnswerExtMx>(orig, data);
        break;
    case DNSRecordType::TXT:
        ext = std::make_shared<DNSAnswerExtTxt>(orig, data);
        break;
    case DNSRecordType::CNAME:
        ext = std::make_shared<DNSAnswerExtCname>(orig, data);
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

DNSAuthorityServer::DNSAuthorityServer()
    : type(0)
    , cls(0)
    , ttl(0)
    , len(0)
    , serial(0)
    , refresh(0)
    , retry(0)
    , expire(0)
    , ttl_min(0)
{}

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

void DNSAuthorityServer::append(DNSBuffer& buf) const
{
    buf.append_domain(name);
    buf.append(type);
    buf.append(cls);
    buf.append(ttl);
    buf.append(len);
    buf.append_domain(primary);
    buf.append_domain(mbox);
    buf.append(serial);
    buf.append(refresh);
    buf.append(retry);
    buf.append(expire);
    buf.append(ttl_min);
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

void DNSPackage::addAnswerTypeA(const std::string& name, const std::string& ip)
{
    DNSAnswer answer;
    answer.name = name;
    answer.type = 1;
    answer.cls = 1;
    answer.ttl = 3600;
    sockaddr_in sa;
    if (0 == inet_pton(AF_INET, ip.c_str(), &sa.sin_addr))
    {
        throw std::runtime_error("invalid IPv4 address");
    }
    uint8_t addr[] = {
        sa.sin_addr.S_un.S_un_b.s_b1,
        sa.sin_addr.S_un.S_un_b.s_b2,
        sa.sin_addr.S_un.S_un_b.s_b3,
        sa.sin_addr.S_un.S_un_b.s_b4,
    };
    answer.ext = std::make_shared<DNSAnswerExtA>(addr);

    answers.push_back(answer);
}

void DNSPackage::addAnswerTypeTxt(const std::string& name, const std::string& text)
{
    DNSAnswer answer;
    answer.name = name;
    answer.type = static_cast<uint16_t>(DNSRecordType::TXT);
    answer.cls = 1;
    answer.ttl = 3600;
    answer.ext = std::make_shared<DNSAnswerExtTxt>(text);
    answers.push_back(answer);
}

void DNSPackage::addAnswerTypeMx(const std::string& name, const std::string& host)
{
    DNSAnswer answer;
    answer.name = name;
    answer.type = static_cast<uint16_t>(DNSRecordType::MX);
    answer.cls = 1;
    answer.ttl = 3600;
    answer.ext = std::make_shared<DNSAnswerExtMx>(host);
    answers.push_back(answer);
}

void DNSPackage::addAnswerTypeCname(const std::string& name, const std::string& host)
{
    DNSAnswer answer;
    answer.name = name;
    answer.type = static_cast<uint16_t>(DNSRecordType::CNAME);
    answer.cls = 1;
    answer.ttl = 3600;
    answer.ext = std::make_shared<DNSAnswerExtCname>(host);
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

void DNSBuffer::append(const uint8_t val)
{
    result.push_back(val);
}

void DNSBuffer::append(const uint8_t* ptr, size_t size)
{
    result.insert(result.end(), ptr, ptr + size);
}

class DNSServerImpl
{
    struct Request
    {
        DNSRecordType type;
        std::string host;
        Request(DNSRecordType type, const std::string& host)
            : type(type)
            , host(host)
        {}
        bool operator < (const Request& val) const
        {
            return type < val.type || type == val.type && host < val.host;
        }
    };

public:
    DNSServerImpl(const std::string& host, int port)
        : wsa{0}
        , server_socket{0}
        , server{0}
        , client{0}
    {
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
            throw std::runtime_error("WSAStartup() failed");
        }

        if ((server_socket = socket(AF_INET, SOCK_DGRAM, 0)) == INVALID_SOCKET) {
            throw std::runtime_error("Create socket failed");
        }

        server.sin_family = AF_INET;
        server.sin_addr.s_addr = INADDR_ANY;
        server.sin_port = htons(port);

        if (bind(server_socket, (sockaddr*)&server, sizeof(server)) == SOCKET_ERROR) {
            throw std::runtime_error("Bind failed");
        }
    }

    void addRecord(DNSRecordType type, const std::string& host, const std::string& answer)
    {
        table[Request(type, host)] = answer;
    }

    void process()
    {
        while (true)
        {
            char message[BUFLEN] = {};

            int message_len = 0;
            int slen = sizeof(sockaddr_in);
            if ((message_len = recvfrom(server_socket, message, BUFLEN, 0, (sockaddr*)&client, &slen)) == SOCKET_ERROR) 
            {
                throw std::runtime_error("recvfrom() failed");
            }

            if (message_len < sizeof(DNSHeader))
            {
                throw std::runtime_error("DNS packet too small");
            }

            DNSPackage package(reinterpret_cast<uint8_t*>(message));

            package.header.flags.QR = 1; // answer
            package.header.flags.RA = 1; // supports recursion
            package.header.flags.RCODE = static_cast<uint16_t>(DNSResultCode::NoError);
            for (const auto& query : package.requests)
            {
                DNSRecordType type = static_cast<DNSRecordType>(query.type);
                Request req{ type, query.name };
                const auto iter = table.find(req);
                if (iter != table.end())
                {
                    switch (type)
                    {
                    case DNSRecordType::A:
                        package.addAnswerTypeA(query.name, iter->second);
                        break;
                    case DNSRecordType::MX:
                        package.addAnswerTypeMx(query.name, iter->second);
                        break;
                    case DNSRecordType::TXT:
                        package.addAnswerTypeTxt(query.name, iter->second);
                        break;
                    case DNSRecordType::CNAME:
                        package.addAnswerTypeCname(query.name, iter->second);
                        break;
                    default:
                        package.header.flags.RCODE = static_cast<uint16_t>(DNSResultCode::NotImplemented);
                        break;
                    }
                }
                else
                {
                    package.header.flags.RCODE = static_cast<uint16_t>(DNSResultCode::NameError);
                }
                if (package.header.flags.RCODE != static_cast<uint16_t>(DNSResultCode::NoError))
                {
                    break;
                }
            }

            if (package.header.flags.RCODE != static_cast<uint16_t>(DNSResultCode::NoError))
            {
                package.answers.clear();
            }

            package.header.ANCOUNT = static_cast<uint16_t>(package.answers.size());
            package.header.ARCOUNT = 0;

            DNSBuffer buf;
            package.append(buf);

            if (sendto(server_socket, reinterpret_cast<const char*>(&buf.result[0]), static_cast<int>(buf.result.size()), 0, (sockaddr*)&client, sizeof(sockaddr_in)) == SOCKET_ERROR) 
            {
                throw std::runtime_error("recvfrom() failed");
            }
        }
    }

private:
    WSADATA wsa;
    SOCKET server_socket;
    sockaddr_in server, client;
    std::map<Request, std::string> table;

    static const int BUFLEN = 512;
};

const int DNSServerImpl::BUFLEN;

DNSServer::DNSServer(const std::string& host, int port)
    : impl(new DNSServerImpl{host, port})
{}

DNSServer::DNSServer(const std::string& jsonFile)
{
    Json::Value root;
    std::ifstream ifs(jsonFile.c_str());
    if (!ifs.is_open())
    {
        throw std::runtime_error("Error opening json file");
    }
    Json::CharReaderBuilder builder;
    JSONCPP_STRING errs;
    if (!parseFromStream(builder, ifs, &root, &errs)) 
    {
        throw std::runtime_error("Error parsing json file");
    }
    std::string ip = root.get("ip", "127.0.0.1").asString();
    int port = root.get("port", 10000).asInt();

    impl.reset(new DNSServerImpl{ ip, port });

    const Json::Value records = root["records"];
    for (int index = 0; index < records.size(); ++index)
    {
        DNSRecordType type = static_cast<DNSRecordType>(records[index].get("type", 0).asInt());
        std::string host = records[index].get("host", "").asString();
        std::string answer = records[index].get("response", "").asString();
        addRecord(type, host, answer);
    }
}

DNSServer::~DNSServer()
{}

void DNSServer::addRecord(DNSRecordType type, const std::string& host, const std::string& answer)
{
    impl->addRecord(type, host, answer);
}

void DNSServer::process()
{
    impl->process();
}
