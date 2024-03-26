#pragma once

enum class DNSRecordType
{
    OTHER = 0,
    A = 1,
    CNAME = 5,
    PTR = 12,
    MX = 15,
    TXT = 16,
};

enum class DNSResultCode
{
    NoError = 0,
    FormatError = 1,
    ServerFailure = 2,
    NameError = 3,
    NotImplemented = 4,
    Refused = 5
};

#define UDP_SIZE 512
