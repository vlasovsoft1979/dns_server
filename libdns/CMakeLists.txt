find_package(jsoncpp CONFIG REQUIRED)

add_library(dns STATIC
    dns_consts.h
    dns_utils.cpp dns_utils.h
    dns_header.cpp dns_header.h
    dns_buffer.cpp dns_buffer.h 
    dns.cpp dns.h
)

target_include_directories(dns PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(dns PRIVATE JsonCpp::JsonCpp)

if(WIN32)
  target_link_libraries(dns PUBLIC wsock32 ws2_32)
endif()
