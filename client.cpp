#include <iostream>
#include <winsock2.h>
using namespace std;

#pragma comment(lib,"ws2_32.lib") 
#pragma warning(disable:4996) 

#include "params.h"

class UDPClient {
public:
    UDPClient() {
        printf("Initialising Winsock...");
        if (WSAStartup(MAKEWORD(2, 2), &ws) != 0) {
            printf("Failed. Error Code: %d", WSAGetLastError());
            exit(EXIT_FAILURE);
        }
        printf("Initialised.\n");

        // create socket
        if ((client_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == SOCKET_ERROR) {
            printf("socket() failed with error code: %d", WSAGetLastError());
            exit(EXIT_FAILURE);
        }

        // setup address structure
        memset((char*)&server, 0, sizeof(server));
        server.sin_family = AF_INET;
        server.sin_port = htons(PORT);
        server.sin_addr.S_un.S_addr = inet_addr(SERVER);
    }

    ~UDPClient() {
        closesocket(client_socket);
        WSACleanup();
    }

    void request() {
        char message[BUFLEN];
        printf("Enter message: ");
        cin.getline(message, BUFLEN);

        // Send the message
        if (sendto(client_socket, message, strlen(message), 0, (sockaddr*)&server, sizeof(sockaddr_in)) == SOCKET_ERROR) {
            printf("sendto() failed with error code: %d", WSAGetLastError());
            exit(EXIT_FAILURE);
        }

        // receive a reply and print it
        // clear the answer by filling null, it might have previously received data
        char answer[BUFLEN] = {};

        // try to receive some data, this is a blocking call
        int slen = sizeof(sockaddr_in);
        int answer_length;
        if ((answer_length = recvfrom(client_socket, answer, BUFLEN, 0, (sockaddr*)&server, &slen)) == SOCKET_ERROR) {
            printf("recvfrom() failed with error code: %d", WSAGetLastError());
            exit(EXIT_FAILURE);
        }

        cout << "Server's response: " << answer << "\n";
    }

private:
    WSADATA ws;
    SOCKET client_socket;
    sockaddr_in server;
};

int main() {
    system("title UDP Client");

    UDPClient udpClient;
    udpClient.request();
}
