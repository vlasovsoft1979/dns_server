#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "dns.h"

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

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
