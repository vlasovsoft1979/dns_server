enable_testing()

find_package(GTest REQUIRED)

include_directories("..")

add_executable(
  tst_dns
  tst_dns.cpp
  ../dns.cpp ../dns.h
)

target_link_libraries(
  tst_dns
  GTest::gtest GTest::gtest_main GTest::gmock GTest::gmock_main
)

if(WIN32)
  target_link_libraries(tst_dns wsock32 ws2_32)
endif()
