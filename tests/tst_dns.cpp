#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <json/json.h>

#include "dns.h"
#include "dns_buffer.h"
#include "dns_header.h"
#include "dns_package.h"

static const std::string HOST = "127.0.0.1";
static const int PORT = 10000;

char fromHex(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return 10 + c - 'a';
    if (c >= 'A' && c <= 'F')
        return 10 + c - 'A';
    throw std::runtime_error("invalid symbol");
}

std::vector<uint8_t> fromHex(const std::string& str)
{
    std::vector<uint8_t> result;
    auto len = str.size() / 2;
    result.reserve(len);
    for (auto i = 0; i < len; ++i)
    {
        result.push_back((fromHex(str[2*i]) << 4) + fromHex(str[2*i+1]));
    }
    return result;
}

std::string toHex(const std::vector<uint8_t> vec)
{
    char table[] = "0123456789abcdef";
    std::string result;
    result.reserve(2 * vec.size());
    for (auto c : vec)
    {
        result.push_back(table[c >> 4]);
        result.push_back(table[c & 0b00001111]);
    }
    return result;
}

TEST(Dns, ParseQueryHeaderFlags)
{
    std::string pkg{ "0120" };
    auto vec = fromHex(pkg);
    const uint8_t* data = &vec[0];
    DNSHeaderFlags flags(data);
    ASSERT_EQ(0, flags.QR);
    ASSERT_EQ(0, flags.Opcode);
    ASSERT_EQ(0, flags.AA);
    ASSERT_EQ(0, flags.TC);
    ASSERT_EQ(1, flags.RD);
    ASSERT_EQ(0, flags.RA);
    ASSERT_EQ(2, flags.Z);
    ASSERT_EQ(0, flags.RCODE);
    DNSBuffer buf;
    flags.append(buf);
    ASSERT_EQ(pkg, toHex(buf.result));
}

TEST(Dns, ParseQuery)
{
    std::string pkg{ "1cb901000001000000000000033132310a766c61736f76736f6674036e65740000010001" };
    auto vec = fromHex(pkg);
    DNSPackage package(&vec[0]);
    ASSERT_EQ(0x1cb9, package.header.ID);
    ASSERT_EQ(1, package.header.QDCOUNT);
    ASSERT_EQ(0, package.header.ANCOUNT);
    ASSERT_EQ(0, package.header.NSCOUNT);
    ASSERT_EQ(0, package.header.ARCOUNT);
    DNSBuffer buf;
    package.append(buf);
    ASSERT_EQ(pkg, toHex(buf.result));
}

TEST(Dns, ParseResponse_TypeA_Success)
{
    std::string pkg{ "4f16818000010001000000000a766c61736f76736f6674036e65740000010001c00c0001000100000e100004b9fddb5c" };
    auto vec = fromHex(pkg);
    DNSPackage package(&vec[0]);
    ASSERT_EQ(0x4f16, package.header.ID);
    ASSERT_EQ(1, package.header.QDCOUNT);
    ASSERT_EQ(1, package.header.ANCOUNT);
    ASSERT_EQ(0, package.header.NSCOUNT);
    ASSERT_EQ(0, package.header.ARCOUNT);
    DNSBuffer buf;
    package.append(buf);
    ASSERT_EQ(pkg, toHex(buf.result));
}

TEST(Dns, ParseResponse_TypeA_HostNotFound)
{
    std::string pkg{ "db2481830001000000010000086e78646f6d61696e0a766c61736f76736f6674036e65740000010001c01500060001000006fd002e056e7331303107636c6f75646e73c02007737570706f7274c03b78a4450e00001c20000007080012750000000e10" };
    auto vec = fromHex(pkg);
    DNSPackage package(&vec[0]);
    ASSERT_EQ(0xdb24, package.header.ID);
    ASSERT_EQ(DNSResultCode::NameError, static_cast<DNSResultCode>(package.header.flags.RCODE));
    ASSERT_EQ(1, package.header.QDCOUNT);
    ASSERT_EQ(0, package.header.ANCOUNT);
    ASSERT_EQ(1, package.header.NSCOUNT);
    ASSERT_EQ(0, package.header.ARCOUNT);
    DNSBuffer buf;
    package.append(buf);
    ASSERT_EQ(pkg, toHex(buf.result));
}

TEST(Dns, ParseResponse_TypeMX_Success)
{
    std::string pkg{ "3f2c8180000100010000000006676f6f676c6503636f6d00000f0001c00c000f0001000001060009000a04736d7470c00c" };
    auto vec = fromHex(pkg);
    DNSPackage package(&vec[0]);
    ASSERT_EQ(0x3f2c, package.header.ID);
    ASSERT_EQ(1, package.header.QDCOUNT);
    ASSERT_EQ(1, package.header.ANCOUNT);
    ASSERT_EQ(0, package.header.NSCOUNT);
    ASSERT_EQ(0, package.header.ARCOUNT);
    DNSBuffer buf;
    package.append(buf);
    ASSERT_EQ(pkg, toHex(buf.result));
}

TEST(Dns, ParseResponse_TypeMX_HostNotFound)
{
    std::string pkg{ "b5e7818300010000000100000a6e6f745f657869737473036e657400000f0001c0170006000100000384003d01610c67746c642d73657276657273c017056e73746c640c766572697369676e2d67727303636f6d0065f84efb000007080000038400093a8000015180" };
    auto vec = fromHex(pkg);
    DNSPackage package(&vec[0]);
    ASSERT_EQ(0xb5e7, package.header.ID);
    ASSERT_EQ(DNSResultCode::NameError, static_cast<DNSResultCode>(package.header.flags.RCODE));
    ASSERT_EQ(1, package.header.QDCOUNT);
    ASSERT_EQ(0, package.header.ANCOUNT);
    ASSERT_EQ(1, package.header.NSCOUNT);
    ASSERT_EQ(0, package.header.ARCOUNT);
    DNSBuffer buf;
    package.append(buf);
    ASSERT_EQ(pkg, toHex(buf.result));
}

TEST(Dns, ParseResponse_TypeTXT_Success)
{
    std::string pkg{ "248c818000010001000000000a766c61736f76736f6674036e65740000100001c00c0010000100000e10000e0d763d737066312061202d616c6c" };
    auto vec = fromHex(pkg);
    DNSPackage package(&vec[0]);
    ASSERT_EQ(0x248c, package.header.ID);
    ASSERT_EQ(1, package.header.QDCOUNT);
    ASSERT_EQ(1, package.header.ANCOUNT);
    ASSERT_EQ(0, package.header.NSCOUNT);
    ASSERT_EQ(0, package.header.ARCOUNT);
    DNSBuffer buf;
    package.append(buf);
    ASSERT_EQ(pkg, toHex(buf.result));
}

TEST(Dns, ParseResponse_TypeTXT_HostNotFound)
{
    std::string pkg{ "b5e7818300010000000100000a6e6f745f657869737473036e657400000f0001c0170006000100000384003d01610c67746c642d73657276657273c017056e73746c640c766572697369676e2d67727303636f6d0065f84efb000007080000038400093a8000015180" };
    auto vec = fromHex(pkg);
    DNSPackage package(&vec[0]);
    ASSERT_EQ(0xb5e7, package.header.ID);
    ASSERT_EQ(DNSResultCode::NameError, static_cast<DNSResultCode>(package.header.flags.RCODE));
    ASSERT_EQ(1, package.header.QDCOUNT);
    ASSERT_EQ(0, package.header.ANCOUNT);
    ASSERT_EQ(1, package.header.NSCOUNT);
    ASSERT_EQ(0, package.header.ARCOUNT);
    DNSBuffer buf;
    package.append(buf);
    ASSERT_EQ(pkg, toHex(buf.result));
}

TEST(Dns, ParseResponse_TypeCNAME_Success)
{
    std::string pkg{ "09178180000100010000000005636d61696c0a766c61736f76736f6674036e65740000050001c00c0005000100000e100007046d61696cc012" };
    auto vec = fromHex(pkg);
    DNSPackage package(&vec[0]);
    ASSERT_EQ(0x0917, package.header.ID);
    ASSERT_EQ(1, package.header.QDCOUNT);
    ASSERT_EQ(1, package.header.ANCOUNT);
    ASSERT_EQ(0, package.header.NSCOUNT);
    ASSERT_EQ(0, package.header.ARCOUNT);
    DNSBuffer buf;
    package.append(buf);
    ASSERT_EQ(pkg, toHex(buf.result));
}

#if (0)
TEST(Dns, DNSServer_quit_command_works)
{
    DNSServer server(HOST, PORT);
    server.start();
    sleep(20);
    DNSClient client(HOST, PORT);
    ASSERT_TRUE(client.command("quit"));
    server.join();
}
#endif

#if (0)
TEST(Dns, DNSServer_exit_command_works)
{
    DNSServer server(HOST, PORT);
    server.start();
    sleep(20);
    DNSClient client(HOST, PORT);
    ASSERT_TRUE(client.command("exit"));
    server.join();
}
#endif

class DnsServerFixture : public testing::Test 
{
public:
    DnsServerFixture()
        : server(HOST, PORT)
        , client(HOST, PORT)
    {
        server.start();
    }
    ~DnsServerFixture()
    {
        client.command("exit");
        server.join();
    }

protected:
    DNSServer server;
    DNSClient client;
};

TEST_F(DnsServerFixture, CanHandleRequestTypeA)
{
    server.addRecord(DNSRecordType::A, "domain.com", { "1.1.1.1", "2.2.2.2", "3.3.3.3" });

    DNSPackage result_udp = client.requestUdp(555, DNSRecordType::A, "domain.com");
    ASSERT_EQ(555, result_udp.header.ID);
    ASSERT_EQ(DNSResultCode::NoError, static_cast<DNSResultCode>(result_udp.header.flags.RCODE));
    ASSERT_EQ(3, result_udp.header.ANCOUNT);
    ASSERT_EQ(3, result_udp.answers.size());
    ASSERT_EQ(std::string{ "1.1.1.1" }, result_udp.answers[0].decode());
    ASSERT_EQ(std::string{ "2.2.2.2" }, result_udp.answers[1].decode());
    ASSERT_EQ(std::string{ "3.3.3.3" }, result_udp.answers[2].decode());
    
    DNSPackage result_tcp = client.requestTcp(777, DNSRecordType::A, "domain.com");
    ASSERT_EQ(777, result_tcp.header.ID);
    ASSERT_EQ(DNSResultCode::NoError, static_cast<DNSResultCode>(result_tcp.header.flags.RCODE));
    ASSERT_EQ(3, result_tcp.header.ANCOUNT);
    ASSERT_EQ(3, result_tcp.answers.size());
    ASSERT_EQ(std::string{ "1.1.1.1" }, result_tcp.answers[0].decode());
    ASSERT_EQ(std::string{ "2.2.2.2" }, result_tcp.answers[1].decode());
    ASSERT_EQ(std::string{ "3.3.3.3" }, result_tcp.answers[2].decode());
}

TEST_F(DnsServerFixture, HostNotFoundForRequestTypeA)
{
    server.addRecord(DNSRecordType::A, "domain.com", { "1.1.1.1", "2.2.2.2", "3.3.3.3" });
    DNSPackage result_udp = client.requestUdp(555, DNSRecordType::A, "domain1.com");
    ASSERT_EQ(555, result_udp.header.ID);
    ASSERT_EQ(DNSResultCode::NameError, static_cast<DNSResultCode>(result_udp.header.flags.RCODE));
    ASSERT_EQ(0, result_udp.header.ANCOUNT);
    ASSERT_EQ(0, result_udp.answers.size());
}

TEST_F(DnsServerFixture, CanHandleRequestTypeCname)
{
    server.addRecord(DNSRecordType::CNAME, "alias.domain.com", { "domain.com" });
    DNSPackage result = client.requestUdp(555, DNSRecordType::CNAME, "alias.domain.com");
    ASSERT_EQ(555, result.header.ID);
    ASSERT_EQ(DNSResultCode::NoError, static_cast<DNSResultCode>(result.header.flags.RCODE));
    ASSERT_EQ(1, result.header.ANCOUNT);
    ASSERT_EQ(1, result.answers.size());
    ASSERT_EQ(std::string{ "domain.com" }, result.answers[0].decode());
}

TEST_F(DnsServerFixture, CanHandleRequestTypePtr)
{
    server.addRecord(DNSRecordType::PTR, "139.238.125.74.in-addr.arpa", { "domain1.com", "domain2.com" });
    DNSPackage result = client.requestUdp(555, DNSRecordType::PTR, "139.238.125.74.in-addr.arpa");
    ASSERT_EQ(555, result.header.ID);
    ASSERT_EQ(DNSResultCode::NoError, static_cast<DNSResultCode>(result.header.flags.RCODE));
    ASSERT_EQ(2, result.header.ANCOUNT);
    ASSERT_EQ(2, result.answers.size());
    ASSERT_EQ(std::string{ "domain1.com" }, result.answers[0].decode());
    ASSERT_EQ(std::string{ "domain2.com" }, result.answers[1].decode());
}

TEST_F(DnsServerFixture, CanHandleRequestTypeMx)
{
    server.addRecord(DNSRecordType::MX, "domain.com", { "mx1.domain.com", "mx2.domain.com", "mx3.domain.com" });
    DNSPackage result = client.requestUdp(555, DNSRecordType::MX, "domain.com");
    ASSERT_EQ(555, result.header.ID);
    ASSERT_EQ(DNSResultCode::NoError, static_cast<DNSResultCode>(result.header.flags.RCODE));
    ASSERT_EQ(3, result.header.ANCOUNT);
    ASSERT_EQ(3, result.answers.size());
    ASSERT_EQ(std::string{ "mx1.domain.com" }, result.answers[0].decode());
    ASSERT_EQ(std::string{ "mx2.domain.com" }, result.answers[1].decode());
    ASSERT_EQ(std::string{ "mx3.domain.com" }, result.answers[2].decode());
}

TEST_F(DnsServerFixture, CanHandleRequestTypeTxt)
{
    server.addRecord(DNSRecordType::TXT, "domain.com", { "text message 1", "text message 2", "text message 3" });
    DNSPackage result = client.requestUdp(555, DNSRecordType::TXT, "domain.com");
    ASSERT_EQ(555, result.header.ID);
    ASSERT_EQ(DNSResultCode::NoError, static_cast<DNSResultCode>(result.header.flags.RCODE));
    ASSERT_EQ(3, result.header.ANCOUNT);
    ASSERT_EQ(3, result.answers.size());
    ASSERT_EQ(std::string{ "text message 1" }, result.answers[0].decode());
    ASSERT_EQ(std::string{ "text message 2" }, result.answers[1].decode());
    ASSERT_EQ(std::string{ "text message 3" }, result.answers[2].decode());
}

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
