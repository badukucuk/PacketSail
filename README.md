# PacketSail

PacketSail is an open-source C++20 project focused on improving network compatibility in environments affected by Deep Packet Inspection (DPI).

The initial goal is to develop a macOS command-line application capable of helping restore access to Discord through DPI compatibility techniques.

## Project Status

PacketSail is in early development.

The initial technical research identified TLS record splitting as a promising approach. This behavior was successfully tested using an external reference tool, but it has not yet been implemented in PacketSail.

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
- CTest (planned)

## Build

Requirements:

- A C++20-compatible compiler
- CMake 3.20 or newer

```bash
cmake -S . -B build
cmake --build build
./build/packetsail
```

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.
