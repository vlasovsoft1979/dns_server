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
