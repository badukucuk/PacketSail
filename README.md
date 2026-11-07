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

Domain names are resolved using DNS-over-HTTPS (DoH) through Google Public DNS. The resolver uses a fixed bootstrap IPv4 address to avoid relying on system DNS for the DoH server.

When multiple IPv4 addresses are returned, PacketSail attempts TCP connections sequentially until one succeeds or all attempts fail.

PacketSail also supports **experimental TLS ClientHello record fragmentation**, which can be enabled using the `--fragment` flag. When enabled, the proxy attempts to split the initial ClientHello into two TLS handshake records at a position inside the SNI hostname for connections targeting port 443.

TLS fragmentation is disabled by default. Unsupported ClientHello formats are forwarded without modification when possible.

Local tests have verified successful TLS 1.3 handshakes with fragmented ClientHello records, and manual HTTPS connectivity tests have succeeded in both proxy modes.

**DPI circumvention and Discord connectivity have not yet been verified using PacketSail.**

IPv6 destinations, UDP relay, and SOCKS5 authentication are not supported.

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

Start the local SOCKS5 proxy:

```bash
./bin/packetsail --proxy
```

By default, PacketSail listens on `127.0.0.1:9876` and accepts unauthenticated SOCKS5 TCP CONNECT requests.

Domain-name destinations are resolved using DNS-over-HTTPS.

Test HTTPS connectivity:

```bash
curl -4 -I \
  --socks5-hostname 127.0.0.1:9876 \
  https://example.com
```

### Experimental TLS Fragmentation

Enable TLS ClientHello record fragmentation:

```bash
./bin/packetsail --proxy --fragment
```

When enabled, PacketSail examines the initial TLS handshake record for connections targeting port 443. For supported ClientHello messages containing an SNI hostname, the proxy splits the handshake payload into two TLS records while preserving the original handshake bytes.

The feature is experimental and may not work with all TLS implementations, network conditions, or ClientHello formats.

TLS fragmentation is disabled by default. Use `--proxy` without `--fragment` to run the proxy without TLS record modification.

Stop the proxy using `Ctrl+C`.

**Limitations:** The DNS resolver supports IPv4 A records through a single DoH provider with a fixed bootstrap IP address. TLS fragmentation currently targets port 443 and supports only certain ClientHello layouts. DPI circumvention is not guaranteed. The proxy is intended for local experimental use.

## License

PacketSail is licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.
