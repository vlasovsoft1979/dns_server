#include "dns_auth_server.h"
#include "dns_utils.h"
#include "dns_buffer.h"

DNSAuthorityServer::DNSAuthorityServer()
    : type(0)
    , cls(0)
    , ttl(0)
    , len(0)
    , serial(0)
    , refresh(0)
    , retry(0)
    , expire(0)
    , ttl_min(0)
{}

DNSAuthorityServer::DNSAuthorityServer(const uint8_t* const orig, const uint8_t*& data)
    : name(get_domain(orig, data))
    , type(get_uint16(data))
    , cls(get_uint16(data))
    , ttl(get_uint32(data))
    , len(get_uint16(data))
    , primary(get_domain(orig, data))
    , mbox(get_domain(orig, data))
    , serial(get_uint32(data))
    , refresh(get_uint32(data))
    , retry(get_uint32(data))
    , expire(get_uint32(data))
    , ttl_min(get_uint32(data))
{}

void DNSAuthorityServer::append(DNSBuffer& buf) const
{
    buf.append_domain(name);
    buf.append(type);
    buf.append(cls);
    buf.append(ttl);
    buf.append(len);
    buf.append_domain(primary);
    buf.append_domain(mbox);
    buf.append(serial);
    buf.append(refresh);
    buf.append(retry);
    buf.append(expire);
    buf.append(ttl_min);
}
