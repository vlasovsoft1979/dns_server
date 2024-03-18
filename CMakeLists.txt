project(dns_server)

cmake_minimum_required(VERSION 3.16)

set(CMAKE_COMPILE_WARNING_AS_ERROR ON)

find_package(jsoncpp CONFIG REQUIRED)

add_executable(dns_server 
    server.cpp 
    dns.cpp dns.h
)

target_link_libraries(dns_server PRIVATE JsonCpp::JsonCpp)

if(WIN32)
  target_link_libraries(dns_server PRIVATE wsock32 ws2_32)
endif()

add_subdirectory(tests)
