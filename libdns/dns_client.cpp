#include "dns_client.h"

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

#include <stdexcept>

#include "dns_socket.h"
#include "dns_request.h"
#include "dns_buffer.h"
#include "dns_utils.h"

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

