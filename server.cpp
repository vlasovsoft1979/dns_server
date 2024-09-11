#include <iostream>
#include <string>

#include "dns.h"

class LoggerImpl: public ILogger
{
public:
    std::ostream& log() override
    {
        return std::cout;
    }
};

int main(int argc, char* argv[]) 
{
    const char* cfg = argc >= 2 ? argv[1] : "dns_server.json";
    try
    {
        LoggerImpl logger;
        DNSServer server(cfg, &logger);
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
