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

PacketSail also supports **experimental TLS ClientHello record fragmentation**, which can be enabled using the `--fragment` flag. For connections targeting port 443, the proxy examines the initial ClientHello and attempts to split it into two TLS handshake records without modifying the original handshake payload.

Two fragmentation strategies are supported:

- `sni-midpoint` (default): Splits the ClientHello inside the SNI hostname.
- `before-sni`: Splits the ClientHello immediately before the SNI hostname.

The strategy can be selected using `--fragment-strategy`. TLS fragmentation is disabled by default. Unsupported ClientHello formats are forwarded without modification when possible.

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

PacketSail supports HTTP CONNECT on `127.0.0.1:9877`. Manual tests confirmed that this proxy can establish an HTTPS tunnel to the Discord update server, complete a TLS 1.3 handshake, and receive an HTTP response.

However, the Discord updater still encounters TLS connection failures in the tested environment.

Network diagnostics confirmed that the updater's ClientHello was fragmented and that the remote endpoint responded with a TLS ServerHello before the TCP connection was reset.

Similar updater failures were observed on both Wi-Fi and a mobile hotspot. Direct TLS connections to the tested destination also encountered connection resets.

Successful Discord desktop application operation remains unverified.

The `before-sni` fragmentation strategy has also been tested against the Discord desktop updater. Both `sni-midpoint` and `before-sni` continue to produce TLS connection failures in the tested environment.

Manual HTTPS tests successfully complete TLS 1.3 handshakes with both strategies. TLS 1.2 connections, however, fail after receiving a ServerHello.

The underlying cause remains unresolved. Additional fragmentation strategies will be considered after further protocol compatibility testing.

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

PacketSail supports experimental TLS ClientHello record fragmentation for connections targeting port 443.

When fragmentation is enabled, PacketSail examines the initial TLS handshake record and attempts to split supported ClientHello messages into two TLS handshake records. The original handshake payload is preserved.

Fragmentation is disabled by default.

#### Fragmentation Strategies

Two strategies are available:

| Strategy | Description |
|---|---|
| `sni-midpoint` | Splits the ClientHello in the middle of the SNI hostname. This is the default strategy. |
| `before-sni` | Splits the ClientHello immediately before the SNI hostname. |

**Default strategy**

Enable TLS fragmentation with the default `sni-midpoint` strategy:

```bash
./bin/packetsail --proxy --fragment
```

This is equivalent to:

```bash
./bin/packetsail --proxy --fragment \
  --fragment-strategy=sni-midpoint
```

**Before-SNI strategy**

Select the alternative strategy:

```bash
./bin/packetsail --proxy --fragment \
  --fragment-strategy=before-sni
```

**HTTP CONNECT proxy**

Enable the alternative strategy for HTTP CONNECT:

```bash
./bin/packetsail --http-proxy --fragment \
  --fragment-strategy=before-sni
```

**Both proxies**

Run SOCKS5 and HTTP CONNECT simultaneously with the same strategy:

```bash
./bin/packetsail --proxy --http-proxy \
  --fragment --fragment-strategy=before-sni
```

The `--fragment-strategy` option requires `--fragment`. Unsupported strategy names are rejected.

Omitting `--fragment-strategy` preserves the existing `sni-midpoint` behavior.

#### Validation

Local tests have verified that both strategies preserve the original ClientHello handshake payload.

Local TLS 1.2 and TLS 1.3 handshake tests have also succeeded with multiple fragmentation positions.

These tests validate local TLS compatibility but do not guarantee successful DPI circumvention or compatibility with every TLS implementation.

Discord web connectivity has been verified using the default `sni-midpoint` strategy.

Both fragmentation strategies have been tested against the Discord desktop updater in a restricted network. Neither has resolved the updater's TLS connection failures.

#### Limitations

PacketSail currently supports IPv4 TCP connections only.

The DNS resolver uses a single DNS-over-HTTPS provider with a fixed bootstrap IPv4 address.

The SOCKS5 proxy does not support authentication, UDP relay, or IPv6 destinations.

The HTTP CONNECT proxy supports only destinations on port 443 and does not implement general HTTP forwarding or proxy authentication.

TLS fragmentation is experimental and supports only certain ClientHello layouts. Unsupported records are forwarded unchanged when possible.

DPI circumvention and Discord desktop application compatibility are not guaranteed.

PacketSail is intended for local experimental use.

Stop the proxy using `Ctrl+C`.

## License

PacketSail is licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.
