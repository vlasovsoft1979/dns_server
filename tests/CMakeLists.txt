enable_testing()

find_package(GTest REQUIRED)
find_package(Threads REQUIRED)

add_executable(
  tst_dns
  tst_dns.cpp
)

target_link_libraries(
  tst_dns
  dns
  GTest::gtest
  GTest::gtest_main
  GTest::gmock
  GTest::gmock_main
)
