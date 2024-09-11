#pragma once

#include <string>
#include <vector>

#include "dns_consts.h"

uint8_t get_uint8(const uint8_t*& data);
uint16_t get_uint16(const uint8_t*& data);
uint32_t get_uint32(const uint8_t*& data);
std::string get_string(const uint8_t*& data, size_t len);
std::string get_domain(const uint8_t* const orig, const uint8_t*& data);

void append_uint16(std::vector<uint8_t>& buf, uint16_t val);
void append_uint32(std::vector<uint8_t>& buf, uint32_t val);

DNSRecordType StrToRecType(const std::string& str);
std::string RecTypeToStr(DNSRecordType type);

std::string ResultCodeToStr(DNSResultCode code);

bool str_to_ipv4(const std::string& val, uint8_t out[4]);
bool str_to_ipv6(const std::string& val, uint8_t out[16]);

std::string ipv4_to_str(uint8_t const addr[4]);
std::string ipv6_to_str(uint8_t const addr[16]);
