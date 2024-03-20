project(dns_server)

cmake_minimum_required(VERSION 3.16)

set(CMAKE_COMPILE_WARNING_AS_ERROR ON)

add_executable(dns_server
    server.cpp
)

target_link_libraries(dns_server PRIVATE dns)

add_subdirectory(libdns)
add_subdirectory(tests)
