project(dns_server)

cmake_minimum_required(VERSION 3.16)

find_package(jsoncpp CONFIG REQUIRED)

add_executable(server 
    server.cpp 
    dns.cpp dns.h
    params.h
)

target_link_libraries(server PRIVATE JsonCpp::JsonCpp)

if(WIN32)
  target_link_libraries(server PRIVATE wsock32 ws2_32)
endif()

add_subdirectory(tests)
