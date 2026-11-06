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

PacketSail requires Go 1.27.3 or later.

Clone the repository:

```bash
git clone https://github.com/badukucuk/PacketSail.git
cd PacketSail
```

Build the CLI:

```bash
go build -o bin/packetsail ./cmd/packetsail
```

Run the application:

```bash
./bin/packetsail --help
```

## Usage

Display version information:

```bash
./bin/packetsail --version
```

Display available options:

```bash
./bin/packetsail --help
```

PacketSail is under active development. Network proxying and DPI circumvention functionality are not yet available.

## License

PacketSail is licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.
