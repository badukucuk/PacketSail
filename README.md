# PacketSail

PacketSail is an open-source DPI circumvention tool written in Go, designed to help restore access to online services on networks where connectivity is restricted by Deep Packet Inspection (DPI).

The project aims to provide a lightweight, cross-platform solution for users affected by network-level restrictions.

Discord connectivity on macOS is the first implemented and verified use case. Windows support is planned for the future.

## Features

- Local SOCKS5 and HTTP CONNECT proxies
- Experimental TLS ClientHello fragmentation
- Three fragmentation strategies: `sni-midpoint`, `before-sni`, and `dual-split`
- DNS-over-HTTPS (DoH) resolution
- Support for Discord Voice Gateway TLS ports

## Project Status

**v0.1.0 — Initial MVP**

PacketSail has successfully enabled Discord desktop connectivity on macOS across multiple tested networks, including messaging, media transfers, and voice communication.

The `dual-split` fragmentation strategy is currently the recommended configuration for the tested Discord environment.

PacketSail remains experimental. Compatibility may vary depending on the network, service, and filtering mechanisms involved.

## Requirements

- macOS
- Go 1.27.3 or later (for building from source)

## Installation

```bash
git clone https://github.com/badukucuk/PacketSail.git
cd PacketSail
go build -o bin/packetsail ./cmd/packetsail
```

## Usage

### Discord on macOS

Start PacketSail with the HTTP CONNECT proxy and the `dual-split` strategy:

```bash
./bin/packetsail --http-proxy --fragment \
  --fragment-strategy=dual-split
```

Configure the macOS network HTTPS proxy to use:

- **Server:** `127.0.0.1`
- **Port:** `9877`

Then launch Discord.

Remember to disable the system HTTPS proxy when PacketSail is no longer running.

### SOCKS5 Proxy

```bash
./bin/packetsail --proxy
```

The SOCKS5 proxy listens on `127.0.0.1:9876`.

### TLS Fragmentation Strategies

Enable TLS fragmentation using one of the supported strategies:

| Strategy | Description |
|---|---|
| `sni-midpoint` | Splits the ClientHello within the SNI hostname (default) |
| `before-sni` | Splits immediately before the SNI hostname |
| `dual-split` | Splits within the SNI and uses separate initial TCP writes |

Fragmentation is disabled by default.

### Debugging

Enable additional HTTP CONNECT logging with `--debug`:

```bash
./bin/packetsail --http-proxy --fragment \
  --fragment-strategy=dual-split --debug
```

Diagnostics include connection attempts, destination addresses, errors, and tunnel lifecycle events.

Debug logging is disabled by default.

### Other Commands

```bash
./bin/packetsail --help
./bin/packetsail --version
```

## Limitations

- IPv4 TCP connections only
- No UDP relay or IPv6 support
- No SOCKS5 authentication
- HTTP CONNECT supports port `443` and selected additional TLS ports for `*.discord.media`
- Discord voice UDP traffic is not routed through PacketSail
- TLS fragmentation does not guarantee successful DPI circumvention
- TLS fragmentation does not guarantee connectivity on every restricted network

PacketSail is intended for local experimental use.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.
