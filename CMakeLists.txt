cmake_minimum_required(VERSION 3.20)

project(PacketSail LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(packetsail
    src/main.cpp
    src/tls_record.cpp
)

target_include_directories(packetsail PRIVATE include)

enable_testing()

add_executable(tls_record_test
    tests/tls_record_test.cpp
    src/tls_record.cpp
)

target_include_directories(tls_record_test PRIVATE include)

add_test(
    NAME tls_record_validation
    COMMAND tls_record_test
)
