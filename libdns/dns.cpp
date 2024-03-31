#if defined(_WIN32)
#include <WinSock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#endif
#include <stdint.h>
#include <ostream>
#include <iostream>
#include <fstream>
#include <set>
#include <algorithm>
#include <thread>
#include <json/json.h>

#include "dns.h"
#include "dns_utils.h"
#include "dns_header.h"
#include "dns_buffer.h"
#include "dns_request.h"
#include "dns_package.h"
#include "dns_selector.h"

class DNSServerImpl: private ISocketHandler
{
    friend class ISocketHandler;

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
        selector.removeReadSocket(s);
        selector.removeWriteSocket(s);
        closesocket(s);
    }

    void closeUdpSocket(SOCKET s)
    {
        selector.removeReadSocket(s);
        selector.removeWriteSocket(s);
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
        selector.removeReadSocket(s);
        selector.addWriteSocket(s);
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
        socklen_t slen = sizeof(udp_socket_data.client);
        int msg_len = recvfrom(s, message, UDP_SIZE, 0, (sockaddr*)&udp_socket_data.client, &slen);
        if (msg_len <= 0)
        {
            // recvfrom error: just ignore
            return;
        }

        const uint8_t* ptr = reinterpret_cast<const uint8_t*>(message);
        udp_socket_data.request.assign(ptr, ptr + msg_len);

        // now be ready to write response
        selector.removeReadSocket(s);
        selector.addWriteSocket(s);
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

        // now be ready to read requests
        selector.removeWriteSocket(s);
        selector.addReadSocket(s);

        udp_socket_data.request.clear();
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

    // ISocketHandler
    virtual void socketReadyRead(SOCKET s)
    {
        if (s == socket_tcp)
        {
            struct sockaddr_storage client_addr;
            socklen_t client_addr_len = sizeof(client_addr);
            SOCKET client = ::accept(s, (struct sockaddr*)&client_addr, &client_addr_len);
            selector.addReadSocket(client);
            setupsocket(client);
        }
        else if (s == socket_udp)
        {
            readUdpSocket(s);
        }
        else
        {
            readTcpSocket(s);
        }
    }

    // ISocketHandler
    virtual void socketReadyWrite(SOCKET s)
    {
        if (s == socket_udp)
        {
            writeUdpSocket(s);
        }
        else if (s != socket_tcp)
        {
            writeTcpSocket(s);
        }
    }

    void process()
    {
        sockaddr_in server = { 0 };
        server.sin_family = AF_INET;
        server.sin_addr.s_addr = INADDR_ANY;
        server.sin_port = htons(port);

        // UDP socket
        if ((socket_udp = socket(AF_INET, SOCK_DGRAM, 0)) == INVALID_SOCKET)
        {
            throw std::runtime_error("Create UDP socket failed");
        }
        setupsocket(socket_udp);
        if (bind(socket_udp, (sockaddr*)&server, sizeof(server)) == SOCKET_ERROR)
        {
            std::cerr << "Bind error:" << errno << std::endl;
            throw std::runtime_error("Bind UDP socket failed");
        }
        selector.addReadSocket(socket_udp);

        // TCP socket
        if ((socket_tcp = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET)
        {
            throw std::runtime_error("Create TCP socket failed");
        }
        setupsocket(socket_tcp);
        if (bind(socket_tcp, (sockaddr*)&server, sizeof(server)) == SOCKET_ERROR)
        {
            throw std::runtime_error("Bind TCP socket failed");
        }
        listen(socket_tcp, 5);
        selector.addReadSocket(socket_tcp);

        canExit = false;
        while (!canExit)
        {
            selector.select();
        }

        closeUdpSocket(socket_udp);
        for (auto it = tcp_socket_data.begin(); it != tcp_socket_data.end();)
        {
            closeTcpSocket(it->first);
            it = tcp_socket_data.erase(it);
        }
        closeTcpSocket(socket_tcp);
    }

public:
    DNSServerImpl(const std::string& host, int port)
        : selector(this)
        , host(host)
        , port(port)
        , socket_udp(INVALID_SOCKET)
        , socket_tcp(INVALID_SOCKET)
#ifdef _WIN32
        , wsa{0}
#endif
    {
#ifdef _WIN32
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) 
        {
            throw std::runtime_error("WSAStartup() failed");
        }
#endif
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
    DNSSelector selector;
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
#ifdef _WIN32
    WSADATA wsa;
#endif
};

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
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
}

void DNSServer::join()
{
    impl->join();
}

DNSClient::DNSClient(const std::string& host, int port)
    : host(host)
    , port(port)
{}

DNSPackage DNSClient::requestUdp(uint16_t id, DNSRecordType type, const std::string& host)
{
    DNSPackage package;
    package.header.ID = id;
    package.header.flags.RD = 1;
    package.header.QDCOUNT = 1;
    package.requests.emplace_back(DNSRequest{ type, host });
    DNSBuffer buf;
    package.append(buf);
    if (buf.result.size() > UDP_SIZE)
    {
        throw std::runtime_error("UDP request too big");
    }

    SOCKET s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s == INVALID_SOCKET)
    {
        throw std::runtime_error("Can't create UDP socket");
    }
    sockaddr_in server = { 0 };
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    inet_pton(AF_INET, this->host.c_str(), &server.sin_addr);

    int bytes_sent = sendto(s, reinterpret_cast<const char*>(&buf.result[0]), static_cast<int>(buf.result.size()), 0, reinterpret_cast<sockaddr*>(&server), static_cast<int>(sizeof(server)));
    if (bytes_sent < buf.result.size())
    {
        throw std::runtime_error("Error sending UDP data");
    }
    
    std::vector<uint8_t> in_buf(UDP_SIZE, 0);
    int bytes_received = recvfrom(s, reinterpret_cast<char*>(&in_buf[0]), static_cast<int>(in_buf.size()), 0, nullptr, nullptr);
    if (bytes_received < 0)
    {
        throw std::runtime_error("Error receiving UDP data");
    }

    closesocket(s);

    DNSPackage response(&in_buf[0]);

    return response;
}

DNSPackage DNSClient::requestTcp(uint16_t id, DNSRecordType type, const std::string& host)
{
    DNSPackage package;
    package.header.ID = id;
    package.header.flags.RD = 1;
    package.header.QDCOUNT = 1;
    package.requests.emplace_back(DNSRequest{ type, host });
    DNSBuffer buf;
    buf.append(static_cast<uint16_t>(0u));  // SIZE (will be calculated later)
    buf.data_start = buf.result.size();
    package.append(buf);
    buf.overwrite_uint16(0, static_cast<uint16_t>(buf.result.size() - sizeof(uint16_t)));

    SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET)
    {
        throw std::runtime_error("Can't create TCP socket");
    }
    sockaddr_in server = { 0 };
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    inet_pton(AF_INET, this->host.c_str(), &server.sin_addr);

    int result = connect(s, reinterpret_cast<sockaddr*>(&server), sizeof(server));
    if (result == SOCKET_ERROR) {
        throw std::runtime_error("Can't connect to server");
    }

    int bytes_sent = send(s, reinterpret_cast<const char*>(&buf.result[0]), static_cast<int>(buf.result.size()), 0);
    if (bytes_sent < buf.result.size())
    {
        throw std::runtime_error("Error sending TCP data");
    }

    std::vector<uint8_t> in_buf(sizeof(uint16_t), 0);
    int bytes_received = recv(s, reinterpret_cast<char*>(&in_buf[0]), static_cast<int>(in_buf.size()), 0);
    if (bytes_received < 0)
    {
        throw std::runtime_error("Error receiving TCP data");
    }

    const uint8_t* ptr = &in_buf[0];
    uint16_t size = get_uint16(ptr);
    in_buf.resize(in_buf.size() + size, 0);
    bytes_received = recv(s, reinterpret_cast<char*>(&in_buf[sizeof(uint16_t)]), static_cast<int>(size), 0);
    if (bytes_received < 0)
    {
        throw std::runtime_error("Error receiving TCP data");
    }

    closesocket(s);

    DNSPackage response(&in_buf[sizeof(uint16_t)]);

    return response;
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
    inet_pton(AF_INET, host.c_str(), &server.sin_addr);

    int length = sendto(s, cmd.c_str(), static_cast<int>(cmd.size()), 0, reinterpret_cast<sockaddr*>(&server), static_cast<int>(sizeof(server)));
 
    closesocket(s);

    return length == cmd.size();
}
