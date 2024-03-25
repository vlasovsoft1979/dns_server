#include "dns_request.h"
#include "dns_buffer.h"
#include "dns_utils.h"

DNSRequest::DNSRequest()
    : type(0)
    , cls(0)
{}

DNSRequest::DNSRequest(const uint8_t* const orig, const uint8_t*& data)
    : name(get_domain(orig, data))
    , type(get_uint16(data))
    , cls(get_uint16(data))
{}

void DNSRequest::append(DNSBuffer& buf) const
{
    buf.append_domain(name);
    buf.append(type);
    buf.append(cls);
}
