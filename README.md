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

PacketSail provides a command-line interface with local SOCKS5 and HTTP CONNECT proxies. Both support IPv4 TCP tunneling, domain-name destinations, DNS-over-HTTPS resolution, and optional experimental TLS ClientHello fragmentation.

Domain names are resolved using DNS-over-HTTPS (DoH) through Google Public DNS. The resolver uses a fixed bootstrap IPv4 address to avoid relying on system DNS for the DoH server.

When multiple IPv4 addresses are returned, PacketSail attempts TCP connections sequentially until one succeeds or all attempts fail.

PacketSail also supports **experimental TLS ClientHello record fragmentation**, which can be enabled using the `--fragment` flag. When enabled, the proxy attempts to split the initial ClientHello into two TLS handshake records at a position inside the SNI hostname for connections targeting port 443.

TLS fragmentation is disabled by default. Unsupported ClientHello formats are forwarded without modification when possible.

Local tests have verified successful TLS 1.3 handshakes with fragmented ClientHello records, and manual HTTPS connectivity tests have succeeded in both proxy modes.

**Discord web connectivity has been successfully verified on macOS using PacketSail with TLS fragmentation enabled.** Testing on a restricted network confirmed successful HTTPS connections, authenticated web access, direct and server messaging, file transfers, and Discord Gateway WebSocket connectivity.

Joining a voice channel, local microphone testing, and camera preview also worked. End-to-end voice and video communication have not yet been verified.

The Discord desktop application remains unverified because its updater fails to complete. Network diagnostics confirmed that the updater uses HTTP CONNECT. PacketSail now accepts these requests on its dedicated HTTP proxy listener, but the updater's TLS handshake still fails in the tested environment.

These results reflect the tested environment and do not guarantee compatibility across all networks or Discord versions.

IPv6 destinations, UDP relay, and SOCKS5 authentication are not supported.

## Verified Connectivity

The following results were obtained on macOS using PacketSail with `--proxy --fragment` enabled.

| Test | Result |
|---|---|
| Discord HTTPS | Successful |
| Discord web login | Successful |
| Direct and server messaging | Successful |
| File transfers | Successful |
| Gateway WebSocket upgrade and Hello | Successful |
| Voice channel connection | Successful |
| Local microphone test | Successful |
| Camera preview | Successful |
| End-to-end voice/video communication | Not yet verified |
| Discord desktop application | Updater failure |

### Current Desktop Limitation

The Discord desktop updater has been observed using HTTP CONNECT to access `updates.discord.com`.

PacketSail now supports HTTP CONNECT on `127.0.0.1:9877`. Manual tests confirmed that this proxy can establish an HTTPS tunnel to the Discord update server, complete a TLS 1.3 handshake, and receive an HTTP response.

However, the Discord updater still encounters TLS connection failures, both with fragmentation enabled and disabled. The cause remains under investigation. Successful desktop application operation has not yet been verified.

### Performance Testing

A Discord voice connection latency of approximately 112 ms was observed on a café Wi-Fi network. This is an initial observation, not a PacketSail performance benchmark.

Latency, packet loss, and connection stability will be evaluated again on a home network.

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

### Local HTTP CONNECT Proxy

Start the local HTTP CONNECT proxy:

```bash
./bin/packetsail --http-proxy
```

PacketSail listens on `127.0.0.1:9877` and accepts HTTP/1.1 CONNECT requests for destinations on port 443.

Test HTTPS connectivity through the HTTP proxy:

```bash
curl -4 -I \
  --noproxy '' \
  --proxy http://127.0.0.1:9877 \
  https://updates.discord.com/
```

Enable experimental TLS fragmentation for HTTP CONNECT:

```bash
./bin/packetsail --http-proxy --fragment
```

Run both local proxies simultaneously:

```bash
./bin/packetsail --proxy --http-proxy --fragment
```

When both proxies are enabled, SOCKS5 listens on port `9876` and HTTP CONNECT listens on port `9877`. Both listeners bind to `127.0.0.1`.

The HTTP proxy supports TCP tunneling through CONNECT only. It is not a general-purpose HTTP forwarding proxy. TLS fragmentation is disabled by default.

Successful HTTPS connectivity through the HTTP CONNECT proxy has been verified. Compatibility with the Discord desktop updater remains under investigation.

### Experimental TLS Fragmentation

Enable TLS ClientHello record fragmentation:

```bash
./bin/packetsail --proxy --fragment
```

When enabled, PacketSail examines the initial TLS handshake record for connections targeting port 443. For supported ClientHello messages containing an SNI hostname, the proxy splits the handshake payload into two TLS records while preserving the original handshake bytes.

The feature is experimental and may not work with all TLS implementations, network conditions, or ClientHello formats.

TLS fragmentation is disabled by default. Omit `--fragment` to run either proxy without TLS record modification.

Stop the proxy using `Ctrl+C`.

**Limitations:** PacketSail currently supports IPv4 TCP connections only. The DNS resolver uses a single DNS-over-HTTPS provider with a fixed bootstrap IPv4 address. The SOCKS5 proxy does not support authentication, UDP relay, or IPv6 destinations. The HTTP CONNECT proxy supports only destinations on port 443 and does not implement general HTTP forwarding or proxy authentication. TLS fragmentation is experimental and supports only certain ClientHello layouts. DPI circumvention and desktop application compatibility are not guaranteed. PacketSail is intended for local experimental use.

## License

PacketSail is licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.
