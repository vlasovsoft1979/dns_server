project(dns_server)

cmake_minimum_required(VERSION 3.16)

add_executable(client 
    client.cpp
    params.h
)
add_executable(server 
    server.cpp 
    dns.cpp dns.h
    params.h
)

if(WIN32)
  target_link_libraries(client wsock32 ws2_32)
  target_link_libraries(server wsock32 ws2_32)
endif()

add_subdirectory(tests)
