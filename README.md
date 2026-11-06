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

PacketSail provides a command-line interface and an experimental local SOCKS5 proxy supporting IPv4 TCP CONNECT requests and domain-name destinations.

Domain names are resolved using DNS-over-HTTPS (DoH) through Google Public DNS. The resolver connects to a predefined IPv4 address to avoid relying on the operating system's DNS configuration for the DoH server.

When DNS returns multiple IPv4 addresses, PacketSail attempts TCP connections sequentially until one succeeds or all attempts fail.

TLS record fragmentation and DPI circumvention are not yet implemented. IPv6 destinations, UDP relay, and SOCKS5 authentication are not supported.

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

### Local SOCKS5 Proxy

Start the experimental SOCKS5 proxy:

```bash
./bin/packetsail --proxy
```

By default, PacketSail listens on `127.0.0.1:9876` and accepts unauthenticated SOCKS5 TCP CONNECT requests.

The proxy supports IPv4 addresses and domain-name destinations.

Test connectivity with locally resolved DNS:

```bash
curl -4 -I --socks5 127.0.0.1:9876 https://example.com
```

Test proxy-side hostname resolution:

```bash
curl -4 -I --socks5-hostname 127.0.0.1:9876 https://example.com
```

Stop the proxy with `Ctrl+C`.

**Limitations:** Domain-name destinations are resolved using Google Public DNS over HTTPS. The DoH endpoint uses a fixed bootstrap IP address and requires network access to the provider. The resolver currently supports IPv4 A records only. PacketSail does not yet implement TLS record fragmentation or DPI circumvention. The proxy is intended for local experimental use only.

## License

PacketSail is licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.
