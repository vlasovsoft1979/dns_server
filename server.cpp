#include <iostream>
#include <string>

#include "dns.h"

int main(int argc, char* argv[]) 
{
    if (argc != 2)
    {
        std::cerr << "usage: dns_server <file.json>" << std::endl;
        return 1;
    }

    try
    {
        DNSServer server(argv[1]);
        server.start();
        server.join();
    }
    catch (const std::exception& e)
    {
        std::cerr << "Critical error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
