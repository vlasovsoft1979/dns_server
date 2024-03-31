find_package(jsoncpp CONFIG REQUIRED)

add_library(dns STATIC
    dns_consts.cpp dns_consts.h
    dns_utils.cpp dns_utils.h
    dns_header.cpp dns_header.h
    dns_buffer.cpp dns_buffer.h
    dns_request.cpp dns_request.h
    dns_answer.cpp dns_answer.h
    dns_auth_server.cpp dns_auth_server.h
    dns_package.cpp dns_package.h
    dns_selector.cpp dns_selector.h
    dns_socket.cpp dns_socket.h
    dns_client.cpp dns_client.h
    dns.cpp dns.h
)

target_include_directories(dns PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(dns PRIVATE JsonCpp::JsonCpp)

if(WIN32)
  target_link_libraries(dns PUBLIC wsock32 ws2_32)
  target_sources(dns PRIVATE dns_selector_win32.cpp)
else()
  target_link_libraries(dns PUBLIC pthread)
  target_sources(dns PRIVATE dns_selector_posix.cpp)
endif()
