#include <iostream>
#include <winsock2.h>

#include <string>
#include <vector>
#include <map>

#include "dns.h"
#include "params.h"
#include "dns.h"

int main() {
    try
    {
        DNSServer server("127.0.0.1", 10000);
        server.addRecord(DNSRecordType::A, "google.com", "1.1.1.1");
        server.addRecord(DNSRecordType::A, "apple.com", "2.2.2.2");
        server.addRecord(DNSRecordType::A, "microsoft.com", "3.3.3.3");
        server.addRecord(DNSRecordType::TXT, "test.com", "some text example");
        server.addRecord(DNSRecordType::MX, "test.com", "mx.test.com");
        server.process();
    }
    catch (const std::exception& e)
    {
        std::cerr << "Critical error: " << e.what() << std::endl;
    }
}
