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

            DNSPackage package(message);

            /*
            if (sendto(server_socket, message, index, 0, (sockaddr*)&client, sizeof(sockaddr_in)) == SOCKET_ERROR) {
                std::cerr << "sendto() failed with error code: " << WSAGetLastError() << std::endl;
                return;
            }
            */
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
