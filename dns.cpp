#include <winsock2.h>
#include <ws2tcpip.h>
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

void DNSPackage::addAnswerTypeA(const std::string& name, const std::string& ip)
{
    DNSAnswer answer;
    answer.name = name;
    answer.type = 1;
    answer.cls = 1;
    answer.ttl = 3600;
    std::vector<uint8_t> data;
    sockaddr_in sa;
    if (0 == inet_pton(AF_INET, ip.c_str(), &sa.sin_addr))
    {
        throw std::runtime_error("invalid IPv4 address");
    }
    answer.data = {
        sa.sin_addr.S_un.S_un_b.s_b1,
        sa.sin_addr.S_un.S_un_b.s_b2,
        sa.sin_addr.S_un.S_un_b.s_b3,
        sa.sin_addr.S_un.S_un_b.s_b4,
    };
    answers.push_back(answer);
}

void DNSPackage::addAnswerTypeTxt(const std::string& name, const std::string& text)
{
    DNSAnswer answer;
    answer.name = name;
    answer.type = static_cast<uint16_t>(DNSRecordType::TXT);
    answer.cls = 1;
    answer.ttl = 3600;
    answer.data.push_back(static_cast<uint8_t>(text.size()));
    answer.data.insert(answer.data.end(), text.begin(), text.end());
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

void DNSBuffer::append(const DNSPackage& val)
{
    append(val.header);
    for (const auto& elem : val.requests)
    {
        append(elem);
    }
    for (const auto& elem : val.answers)
    {
        append(elem);
    }
    for (const auto& elem : val.authorities)
    {
        append(elem);
    }
}

void DNSBuffer::append(const DNSHeaderFlags& val)
{
    append(*reinterpret_cast<const uint16_t*>(&val));
}

void DNSBuffer::append(const DNSHeader& val)
{
    append(val.ID);
    append(val.flags);
    append(val.QDCOUNT);
    append(val.ANCOUNT);
    append(val.NSCOUNT);
    append(val.ARCOUNT);
}

void DNSBuffer::append(const DNSRequest& val)
{
    append_domain(val.name);
    append(val.type);
    append(val.cls);
}

void DNSBuffer::append(const DNSAnswer& val)
{
    append_domain(val.name);
    append(val.type);
    append(val.cls);
    append(val.ttl);
    append(static_cast<uint16_t>(val.data.size()));
    result.insert(result.end(), val.data.begin(), val.data.end());
}

void DNSBuffer::append(const DNSAuthorityServer& val)
{
    append_domain(val.name);
    append(val.type);
    append(val.cls);
    append(val.ttl);
    append(val.len);
    append_domain(val.primary);
    append_domain(val.mbox);
    append(val.serial);
    append(val.refresh);
    append(val.retry);
    append(val.expire);
    append(val.ttl_min);
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
    result.push_back(static_cast<char>(str.size()));
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

            int message_len;
            int slen = sizeof(sockaddr_in);
            if ((message_len = recvfrom(server_socket, message, BUFLEN, 0, (sockaddr*)&client, &slen)) == SOCKET_ERROR) {
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
                    case DNSRecordType::TXT:
                        package.addAnswerTypeTxt(query.name, iter->second);
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
            buf.append(package);

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
