# PacketSail

PacketSail is an open-source C++20 project focused on improving network compatibility in environments affected by Deep Packet Inspection (DPI).

The initial goal is to develop a macOS command-line tool to help restore access to Discord.

## Project Status

PacketSail is in early development.

Implemented components:
- TLS record splitting with unit tests.
- RAII-based socket ownership management.
- A sequential TCP echo server with connection handling.
- TCP data transfer utilities and integration tests.

SOCKS5 proxy support and TLS traffic integration are not yet implemented.

PacketSail cannot currently establish Discord connections.

## Goals

- Develop a lightweight DPI compatibility tool for macOS.
- Implement and test TLS record splitting.
- Support Discord connectivity without requiring a remote VPN server.
- Keep the codebase small, maintainable, and testable.
- Explore Windows support after validating the macOS implementation.

## Technology

- C++20
- CMake
- Apple Clang
- CTest

## Build

Requirements:

- A C++20-compatible compiler
- CMake 3.20 or newer

```bash
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
./build/packetsail
```

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.
