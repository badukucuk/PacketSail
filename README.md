# PacketSail

PacketSail is an open-source project in development, aiming to build a cross-platform network analysis and DPI compatibility tool using modern C++.

## Project Status

Early development. The current version provides a minimal application and CMake-based build configuration.

## Requirements

- CMake 3.20 or later
- A C++20-compatible compiler

## Build

```bash
cmake -S . -B build/debug -DCMAKE_BUILD_TYPE=Debug
cmake --build build/debug
```

## Supported Platforms

- macOS: Initial development platform
- Windows: Planned support

## License

PacketSail is licensed under the Apache License, Version 2.0.

See the [LICENSE](LICENSE) file for details.