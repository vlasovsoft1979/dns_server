#include "dns.h"

#if defined(_WIN32)
#include <WinSock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif

#include <fstream>
#include <algorithm>
#include <thread>
#include <sstream>
#include <json/json.h>

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
        if (s != INVALID_SOCKET)
        {
            selector.removeReadSocket(s);
            selector.removeWriteSocket(s);
            tcp_socket_data.erase(s);
            closesocket(s);
        }
    }

    void closeUdpSocket(SOCKET s)
    {
        if (s != INVALID_SOCKET)
        {
            selector.removeReadSocket(s);
            selector.removeWriteSocket(s);
            closesocket(s);
        }
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
            processQuery(&ctx.request[sizeof(uint16_t)], buf);
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
                return;
            }
            ctx.bytes_sent += bytes_written;
            if (ctx.bytes_sent >= ctx.response.size())
            {
                // all data is sent, close connection
                closeTcpSocket(s);
                return;
            }
        }
        if (ctx.bytes_sent < ctx.response.size())
        {
            return; // need send more data
        }

        // All data is sent. Close connection
        closeTcpSocket(s);
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
            processQuery(&udp_socket_data.request[0], buf);

            int bytes_to_write = static_cast<int>(buf.result.size());
            sendto(s, reinterpret_cast<const char*>(&buf.result[0]), bytes_to_write, 0, (sockaddr*)&udp_socket_data.client, slen);
        }

        // now be ready to read requests
        selector.removeWriteSocket(s);
        selector.addReadSocket(s);

        udp_socket_data.request.clear();
    }

    void processQuery(const uint8_t* query, DNSBuffer& buf)
    {
        DNSPackage package(query);

        if (logger)
        {
            std::stringstream stream;
            stream << "Processing query [" << package.header.ID << "]: "
                   << package.requests.size() << " request(s)";
            logger->log(stream.str().c_str());
        }

        package.header.flags.QR = 1; // answer
        package.header.flags.RA = 1; // supports recursion
        package.header.flags.RCODE = static_cast<uint16_t>(DNSResultCode::NoError);
        for (const auto& query : package.requests)
        {
            if (logger)
            {
                std::stringstream stream;
                stream << "Processing request [" << package.header.ID
                       << "]: type=" << RecTypeToStr(static_cast<DNSRecordType>(query.type)) 
                       << ", name=" << query.name;
                logger->log(stream.str().c_str());
            }

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

        if (logger)
        {
            std::stringstream stream;
            stream << "Sending result: ["
                   << package.header.ID << "]: "
                   << package.answers.size() << " answer(s), result=" 
                   << ResultCodeToStr(static_cast<DNSResultCode>(package.header.flags.RCODE));
            logger->log(stream.str().c_str());
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
            if (client != INVALID_SOCKET)
            {
                setupsocket(client);
                selector.addReadSocket(client);
            }
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
        try
        {
            if (logger)
            {
                logger->log("DNS server started!");
            }

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
        }
        catch(const std::exception& e)
        {
            if (logger)
            {
                std::stringstream stream;
                stream << "DNS server error: " << e.what();
                logger->log(stream.str().c_str());
            }
        }

        // cleanup
        closeUdpSocket(socket_udp);
        for (auto elem: tcp_socket_data)
        {
            closeTcpSocket(elem.first);
        }
        closeTcpSocket(socket_tcp);

        if (logger)
        {
            logger->log("DNS server finished!");
        }
    }

public:
    DNSServerImpl(const std::string& host, int port, ILogger* logger)
        : selector(this)
        , host(host)
        , port(port)
        , socket_udp(INVALID_SOCKET)
        , socket_tcp(INVALID_SOCKET)
        , logger(logger)
#ifdef _WIN32
        , wsa{0}
    {
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) 
        {
            throw std::runtime_error("WSAStartup() failed");
        }
    }
#else
{}
#endif

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
    ILogger* logger;
#ifdef _WIN32
    WSADATA wsa;
#endif
};

DNSServer::DNSServer(const std::string& host, int port, ILogger* logger)
    : impl(new DNSServerImpl{host, port, logger})
{}

DNSServer::DNSServer(const std::string& jsonFile, ILogger* logger)
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

    impl.reset(new DNSServerImpl{ ip, port, logger });

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
