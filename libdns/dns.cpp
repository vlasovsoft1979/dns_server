#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdint.h>
#include <ostream>
#include <iostream>
#include <fstream>
#include <unordered_map>
#include <algorithm>
#include <thread>
#include <json/json.h>

#include "dns.h"
#include "dns_utils.h"
#include "dns_header.h"
#include "dns_buffer.h"
#include "dns_request.h"
#include "dns_package.h"

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

    struct TcpSocketContext
    {
        std::vector<uint8_t> request;
        std::vector<uint8_t> response;
        int bytes_sent;
        TcpSocketContext()
            : bytes_sent(0)
        {}
    };

    struct UdpSocketContext
    {
        std::vector<uint8_t> request;
        sockaddr_in client;
        UdpSocketContext()
            : client{ 0 }
        {}
    };

    void closeTcpSocket(SOCKET s)
    {
        pollfds_del(&readfds, s);
        pollfds_del(&writefds, s);
        closesocket(s);
    }

    void closeUdpSocket(SOCKET s)
    {
        pollfds_del(&readfds, s);
        pollfds_del(&writefds, s);
        closesocket(s);
    }

    void readTcpSocket(SOCKET s)
    {
        TcpSocketContext& ctx = tcp_socket_data[s];
        if (ctx.request.size() < sizeof(uint16_t))
        {
            // receive data length
            int bytes_to_read = static_cast<int>(sizeof(uint16_t) - ctx.request.size());
            std::vector<uint8_t> buf(bytes_to_read, 0);
            int msg_len = recv(s, reinterpret_cast<char*>(&buf[0]), bytes_to_read, 0);
            if (msg_len <= 0)
            {
                // error or close connection
                closeTcpSocket(s);
                tcp_socket_data.erase(s);
                return;
            }
            ctx.request.insert(ctx.request.end(), buf.begin(), buf.end());
            return; // need more data
        }

        const uint8_t* dataPtr = &ctx.request[0];
        uint16_t expected_size = get_uint16(dataPtr);
        if (ctx.request.size() < expected_size + sizeof(uint16_t))
        {
            int bytes_to_read = static_cast<int>(sizeof(uint16_t) + expected_size - ctx.request.size());
            std::vector<uint8_t> buf(bytes_to_read, 0);
            int msg_len = recv(s, reinterpret_cast<char*>(&buf[0]), bytes_to_read, 0);
            if (msg_len <= 0)
            {
                // error or close connection
                closeTcpSocket(s);
                tcp_socket_data.erase(s);
                return;
            }
            ctx.request.insert(ctx.request.end(), buf.begin(), buf.end());
        }

        if (ctx.request.size() < expected_size + sizeof(uint16_t))
        {
            return; // need more data
        }

        // now be ready to write response
        pollfds_del(&readfds, s);
        pollfds_add(&writefds, s);
    }

    void writeTcpSocket(SOCKET s)
    {
        TcpSocketContext& ctx = tcp_socket_data[s];
        if (ctx.response.empty())
        {
            DNSBuffer buf;
            buf.append(static_cast<uint16_t>(0u));  // SIZE (will be calculated later)
            buf.data_start = buf.result.size();
            process(&ctx.request[sizeof(uint16_t)], buf);
            buf.overwrite_uint16(0, static_cast<uint16_t>(buf.result.size() - sizeof(uint16_t)));
            ctx.response = std::move(buf.result);
        }
        if (ctx.bytes_sent < ctx.response.size())
        {
            int bytes_to_write = static_cast<int>(ctx.response.size() - ctx.bytes_sent);
            int bytes_written = send(s, reinterpret_cast<const char*>(&ctx.response[ctx.bytes_sent]), bytes_to_write, 0);
            if (bytes_written <= 0)
            {
                // error or close connection
                closeTcpSocket(s);
                tcp_socket_data.erase(s);
                return;
            }
            ctx.bytes_sent += bytes_written;
            if (ctx.bytes_sent >= ctx.response.size())
            {
                // all data is sent, close connection
                closeTcpSocket(s);
                tcp_socket_data.erase(s);
                return;
            }
        }
        if (ctx.bytes_sent < ctx.response.size())
        {
            return; // need send more data
        }

        // All data is sent. Close connection
        closeTcpSocket(s);
        tcp_socket_data.erase(s);
    }

    void readUdpSocket(SOCKET s)
    {
        char message[UDP_SIZE] = {};
        int slen = sizeof(udp_socket_data.client);
        int msg_len = recvfrom(s, message, UDP_SIZE, 0, (sockaddr*)&udp_socket_data.client, &slen);
        if (msg_len <= 0)
        {
            // recvfrom error: just ignore
            return;
        }

        const uint8_t* ptr = reinterpret_cast<const uint8_t*>(message);
        udp_socket_data.request.assign(ptr, ptr + msg_len);

        // now be ready to write response
        pollfds_del(&readfds, s);
        pollfds_add(&writefds, s);
    }

    void writeUdpSocket(SOCKET s)
    {
        int slen = sizeof(udp_socket_data.client);
        if (udp_socket_data.request.size() < sizeof(DNSHeader))
        {
            std::string cmd(udp_socket_data.request.begin(), udp_socket_data.request.end());
            if (cmd == "quit" || cmd == "exit")
            {
                canExit = true;
                cmd = "Terminating...\n";
            }
            else
            {
                cmd = "Unknown command!\n";
            }
            sendto(s, cmd.c_str(), static_cast<int>(cmd.size()), 0, (sockaddr*)&udp_socket_data.client, slen);
        }
        else
        {
            DNSBuffer buf;
            buf.max_size = UDP_SIZE;
            process(&udp_socket_data.request[0], buf);

            int bytes_to_write = static_cast<int>(buf.result.size());
            sendto(s, reinterpret_cast<const char*>(&buf.result[0]), bytes_to_write, 0, (sockaddr*)&udp_socket_data.client, slen);
        }

        udp_socket_data.request.clear();

        pollfds_del(&writefds, s);
        pollfds_add(&readfds, s);
    }

    void process(const uint8_t* query, DNSBuffer& buf)
    {
        DNSPackage package(query);

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
                for (const auto& item : iter->second)
                {
                    package.addAnswer(type, query.name, item);
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

        package.append(buf);

        if (buf.max_size > 0 && buf.result.size() > buf.max_size)
        {
            package.header.ANCOUNT = 0;
            package.answers.clear();
            package.header.NSCOUNT = 0;
            package.authorities.clear();
            package.header.flags.TC = 1; // truncated
            buf.clear();
            package.append(buf);
        }
    }

    static void pollfds_add(fd_set* set, SOCKET fd)
    {
        FD_SET(fd, set);
    }

    static void pollfds_del(fd_set* set, SOCKET fd)
    {
        FD_CLR(fd, set);
    }

    void process()
    {
        u_long mode = 1;  // 1 to enable non-blocking socket

        fd_set readfds_work;
        fd_set writefds_work;

        FD_ZERO(&readfds);
        FD_ZERO(&writefds);

        sockaddr_in server = { 0 };
        server.sin_family = AF_INET;
        server.sin_addr.s_addr = INADDR_ANY;
        server.sin_port = htons(port);

        // UDP socket
        SOCKET socket_udp = 0;
        if ((socket_udp = socket(AF_INET, SOCK_DGRAM, 0)) == INVALID_SOCKET)
        {
            throw std::runtime_error("Create UDP socket failed");
        }

        ioctlsocket(socket_udp, FIONBIO, &mode);
        if (bind(socket_udp, (sockaddr*)&server, sizeof(server)) == SOCKET_ERROR)
        {
            throw std::runtime_error("Bind UDP socket failed");
        }
        pollfds_add(&readfds, socket_udp);

        // TCP socket
        SOCKET socket_tcp = 0;
        if ((socket_tcp = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET)
        {
            throw std::runtime_error("Create TCP socket failed");
        }
        ioctlsocket(socket_tcp, FIONBIO, &mode);
        if (bind(socket_tcp, (sockaddr*)&server, sizeof(server)) == SOCKET_ERROR)
        {
            throw std::runtime_error("Bind UDP socket failed");
        }
        listen(socket_tcp, 5);
        pollfds_add(&readfds, socket_tcp);

        canExit = false;
        while (!canExit)
        {
            readfds_work = readfds;
            writefds_work = writefds;

            int res = select(0, &readfds_work, &writefds_work, NULL, NULL);
            if (res == -1)
            {
                int code = WSAGetLastError();
                continue;
            }

            for (auto i = 0u; i < readfds_work.fd_count; i++)
            {
                SOCKET fd = readfds_work.fd_array[i];
                if (fd == socket_tcp)
                {
                    struct sockaddr_storage client_addr;
                    socklen_t client_addr_len = sizeof(client_addr);
                    SOCKET client = accept(fd, (struct sockaddr*)&client_addr, &client_addr_len);
                    pollfds_add(&readfds, client);
                    u_long mode = 1;  // 1 to enable non-blocking socket
                    ioctlsocket(client, FIONBIO, &mode);
                }
                else if (fd == socket_udp)
                {
                    readUdpSocket(fd);
                }
                else
                {
                    readTcpSocket(fd);
                }
            }
            for (auto i = 0u; i < writefds_work.fd_count; i++)
            {
                SOCKET fd = writefds_work.fd_array[i];
                if (fd == socket_udp) // client socket
                {
                    writeUdpSocket(fd);
                }
                else if (fd != socket_tcp)
                {
                    writeTcpSocket(fd);
                }
            }
        }

        closeUdpSocket(socket_udp);
        closeTcpSocket(socket_tcp);
        for (auto it = tcp_socket_data.begin(); it != tcp_socket_data.end();)
        {
            closeTcpSocket(it->first);
            it = tcp_socket_data.erase(it);
        }
    }

public:
    DNSServerImpl(const std::string& host, int port)
        : wsa{0}
        , host(host)
        , port(port)
    {
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) 
        {
            throw std::runtime_error("WSAStartup() failed");
        }
    }

    void addRecord(DNSRecordType type, const std::string& host, const std::vector<std::string>& answer)
    {
        table[Request(type, host)] = answer;
    }

    void start()
    {
        thread = std::thread{ [this] { process(); } };
    }

    void join()
    {
        thread.join();
    }

private:
    WSADATA wsa;
    std::string host;
    int port;
    SOCKET socket_udp, socket_tcp;
    std::map<Request, std::vector<std::string> > table;
    std::map<SOCKET, TcpSocketContext> tcp_socket_data;
    UdpSocketContext udp_socket_data;
    fd_set readfds;
    fd_set writefds;
    std::thread thread;
    bool canExit;

    static const int UDP_SIZE = 512;
};

const int DNSServerImpl::UDP_SIZE;

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
    for (auto index = 0u; index < records.size(); ++index)
    {
        DNSRecordType type = ::StrToRecType(records[index].get("type", "").asString());
        if (DNSRecordType::OTHER == type)
        {
            throw std::runtime_error("Error parsing json file: wrong DNS record type");
        }
        std::string host = records[index].get("host", "").asString();
        const Json::Value response = records[index]["response"];
        std::vector<std::string> answers;
        for (auto i = 0u; i < response.size(); ++i)
        {
            answers.push_back(response[i].asString());
        }
        addRecord(type, host, answers);
    }
}

DNSServer::~DNSServer()
{}

void DNSServer::addRecord(DNSRecordType type, const std::string& host, const std::vector<std::string>& answer)
{
    impl->addRecord(type, host, answer);
}

void DNSServer::start()
{
    impl->start();
}

void DNSServer::join()
{
    impl->join();
}

DNSClient::DNSClient(const std::string& host, int port)
    : host(host)
    , port(port)
{}

void DNSClient::requestUdp(DNSPackage& result, uint16_t id, DNSRecordType type, const std::string& host)
{
    DNSPackage package;
    package.header.ID = id;
    package.header.flags.RD = 1;
    package.header.QDCOUNT = 1;
}

void DNSClient::requestTcp(DNSPackage& result, uint16_t id, DNSRecordType type, const std::string& host)
{
    DNSPackage package;
    package.header.ID = id;
    package.header.flags.RD = 1;
    package.header.QDCOUNT = 1;
}

bool DNSClient::command(const std::string& cmd)
{
    SOCKET s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s == INVALID_SOCKET)
    {
        throw std::runtime_error("Can't create UDP socket");
    }
    sockaddr_in server = {0};
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    inet_pton(AF_INET, host.c_str(), &server.sin_addr.S_un.S_addr);

    int length = sendto(s, cmd.c_str(), static_cast<int>(cmd.size()), 0, reinterpret_cast<sockaddr*>(&server), static_cast<int>(sizeof(server)));
    return length == cmd.size();
}
