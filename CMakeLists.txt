cmake_minimum_required(VERSION 3.20)

project(PacketSail LANGUAGES CXX)

add_library(packetsail_project_options INTERFACE)

target_compile_features(packetsail_project_options INTERFACE cxx_std_20)

if(MSVC)
    target_compile_options(packetsail_project_options INTERFACE /W4)
else()
    target_compile_options(packetsail_project_options INTERFACE
        -Wall
        -Wextra
        -Wpedantic
    )
endif()

add_library(packetsail_core STATIC
    src/core/proxy_config.cpp
)

target_include_directories(packetsail_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(packetsail_core PRIVATE packetsail_project_options)

add_executable(packetsail
    src/main.cpp
)

target_link_libraries(packetsail PRIVATE
    packetsail_core
    packetsail_project_options
)

enable_testing()

add_executable(proxy_config_test
    tests/proxy_config_test.cpp
)

target_link_libraries(proxy_config_test PRIVATE
    packetsail_core
    packetsail_project_options
)

add_test(
    NAME proxy_config_test
    COMMAND proxy_config_test
)
