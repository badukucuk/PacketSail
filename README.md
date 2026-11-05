# PacketSail

PacketSail is an open-source DPI circumvention tool written in Go, designed to improve connectivity on networks affected by Deep Packet Inspection (DPI).

The initial focus is restoring access to Discord on macOS, with Windows support planned for the future.

## Goals

- Implement TLS record fragmentation to mitigate SNI-based filtering.
- Provide a lightweight and easy-to-use command-line application.
- Support reliable DNS resolution in restricted networks.
- Enable Discord connectivity on macOS.
- Extend support to Windows.

## Approach

PacketSail will initially explore TLS record fragmentation as its primary DPI circumvention technique.

This approach was selected after preliminary network experiments showed that splitting TLS records could allow HTTPS connections to complete where ordinary TLS handshakes were being reset.

## Project Status

**Early development**

PacketSail is currently in its initial setup phase. DPI circumvention functionality has not yet been implemented.

## Building

PacketSail is written in Go.

Build and usage instructions will be added when the initial command-line application is implemented.

## License

PacketSail is licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.
