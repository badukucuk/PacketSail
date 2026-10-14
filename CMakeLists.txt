cmake_minimum_required(VERSION 3.20)

project(PacketSail LANGUAGES CXX)

add_executable(packetsail
    src/main.cpp
)

target_compile_features(packetsail PRIVATE cxx_std_20)

if(MSVC)
    target_compile_options(packetsail PRIVATE /W4)
else()
    target_compile_options(packetsail PRIVATE
        -Wall
        -Wextra
        -Wpedantic
    )
endif()