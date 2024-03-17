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
    buf.append(package);
    ASSERT_EQ(pkg, toHex(buf.getResult()));
}

TEST(Dns, ParseResponse)
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
    buf.append(package);
    ASSERT_EQ(pkg, toHex(buf.getResult()));
}

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
