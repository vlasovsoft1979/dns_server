#include <iostream>
#include <winsock2.h>

#include <string>
#include <vector>
#include <map>

#include "dns.h"
#include "params.h"


class UDPServer {
public:
    UDPServer() {
        // initialise winsock
        printf("Initialising Winsock...");
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
            printf("Failed. Error Code: %d", WSAGetLastError());
            exit(0);
        }
        printf("Initialised.\n");

        // create a socket
        if ((server_socket = socket(AF_INET, SOCK_DGRAM, 0)) == INVALID_SOCKET) {
            printf("Could not create socket: %d", WSAGetLastError());
            exit(EXIT_FAILURE);
        }
        printf("Socket created.\n");

        // prepare the sockaddr_in structure
        server.sin_family = AF_INET;
        server.sin_addr.s_addr = INADDR_ANY;
        server.sin_port = htons(PORT);

        // bind
        if (bind(server_socket, (sockaddr*)&server, sizeof(server)) == SOCKET_ERROR) {
            printf("Bind failed with error code: %d", WSAGetLastError());
            exit(EXIT_FAILURE);
        }
        puts("Bind done.");
    }

    ~UDPServer() {
        closesocket(server_socket);
        WSACleanup();
    }

    void process() 
    {
        while (true)
        {
            char message[BUFLEN] = {};

            // try to receive some data, this is a blocking call
            int message_len;
            int slen = sizeof(sockaddr_in);
            if ((message_len = recvfrom(server_socket, message, BUFLEN, 0, (sockaddr*)&client, &slen)) == SOCKET_ERROR) {
                std::cerr << "recvfrom() failed with error code: " << WSAGetLastError() << std::endl;
                return;
            }

            // print details of the client/peer and the data received
            std::cout << "Received packet from " << inet_ntoa(client.sin_addr) << ":" << ntohs(client.sin_port) << std::endl;
            if (message_len < sizeof(DNSHeader))
            {
                std::cerr << "packet too small" << std::endl;
                return;
            }

            DNSPackage package(reinterpret_cast<uint8_t*>(message));

            std::cout << package.header.flags.QR << std::endl;

            package.header.flags.QR = 1;
            package.header.flags.RA = 1;
            package.header.flags.RCODE = 0;
            package.header.ANCOUNT = 1;
            package.header.ARCOUNT = 0;
            package.addAnswerTypeA("vlasovsoft.net", "1.1.1.1");

            DNSBuffer buf;
            buf.append(package);

            const std::vector<uint8_t> result = buf.result;

            if (sendto(server_socket, reinterpret_cast<const char*>(&result[0]), static_cast<int>(result.size()), 0, (sockaddr*)&client, sizeof(sockaddr_in)) == SOCKET_ERROR) {
                std::cerr << "sendto() failed with error code: " << WSAGetLastError() << std::endl;
                return;
            }
        }
    }

private:
    WSADATA wsa;
    SOCKET server_socket;
    sockaddr_in server, client;
    bool exitRequested = false;
};

int main() {
    system("title UDP Server");

    UDPServer udpServer;
    udpServer.process();
}
