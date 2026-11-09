package socks5

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"testing"
	"time"

	"github.com/badukucuk/PacketSail/internal/tlsfrag"
)

// testLookupIPv4 resolves localhost without depending on external DNS.
func testLookupIPv4(ctx context.Context, hostname string) ([]net.IP, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if hostname != "localhost" {
		return nil, fmt.Errorf("unexpected test hostname %q", hostname)
	}

	return []net.IP{net.IPv4(127, 0, 0, 1)}, nil
}

func TestUnsupportedAuthMethod(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("start test listener: %v", err)
	}
	defer listener.Close()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}

		handleConnection(conn, testLookupIPv4, false, tlsfrag.StrategySNIMidpoint)
	}()

	client, err := net.Dial("tcp4", listener.Addr().String())
	if err != nil {
		t.Fatalf("connect to test listener: %v", err)
	}
	defer client.Close()

	if err := client.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set test deadline: %v", err)
	}

	// Offer only username/password authentication, which PacketSail does not support.
	greeting := []byte{0x05, 0x01, 0x02}

	if _, err := client.Write(greeting); err != nil {
		t.Fatalf("send SOCKS5 greeting: %v", err)
	}

	var reply [2]byte
	if _, err := io.ReadFull(client, reply[:]); err != nil {
		t.Fatalf("read SOCKS5 method selection: %v", err)
	}

	expected := [2]byte{0x05, 0xFF}
	if reply != expected {
		t.Fatalf("unexpected reply: got %v, want %v", reply, expected)
	}
}

func TestConnectAndRelay(t *testing.T) {
	targetListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("start target listener: %v", err)
	}
	defer targetListener.Close()

	// Echo back everything received from the proxy.
	go func() {
		conn, err := targetListener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		io.Copy(conn, conn)
	}()

	proxyListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("start proxy listener: %v", err)
	}
	defer proxyListener.Close()

	go func() {
		conn, err := proxyListener.Accept()
		if err != nil {
			return
		}

		handleConnection(conn, testLookupIPv4, false, tlsfrag.StrategySNIMidpoint)
	}()

	client, err := net.Dial("tcp4", proxyListener.Addr().String())
	if err != nil {
		t.Fatalf("connect to proxy: %v", err)
	}
	defer client.Close()

	if err := client.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set client deadline: %v", err)
	}

	// Negotiate SOCKS5 with no authentication.
	if _, err := client.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("write greeting: %v", err)
	}

	var methodReply [2]byte
	if _, err := io.ReadFull(client, methodReply[:]); err != nil {
		t.Fatalf("read method reply: %v", err)
	}
	if methodReply != [2]byte{0x05, 0x00} {
		t.Fatalf("unexpected method reply: %v", methodReply)
	}

	// Request a TCP connection to the local echo server.
	request := []byte{0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0, 0}
	port := targetListener.Addr().(*net.TCPAddr).Port
	binary.BigEndian.PutUint16(request[8:10], uint16(port))

	if _, err := client.Write(request); err != nil {
		t.Fatalf("write CONNECT request: %v", err)
	}

	var connectReply [10]byte
	if _, err := io.ReadFull(client, connectReply[:]); err != nil {
		t.Fatalf("read CONNECT reply: %v", err)
	}
	if connectReply[0] != 0x05 || connectReply[1] != 0x00 {
		t.Fatalf("CONNECT failed: %v", connectReply)
	}

	if connectReply[2] != 0x00 || connectReply[3] != 0x01 {
		t.Fatalf("invalid CONNECT reply header: %v", connectReply)
	}

	bindIP := net.IP(connectReply[4:8])
	if !bindIP.Equal(net.IPv4(127, 0, 0, 1)) {
		t.Fatalf("unexpected bind IP: %s", bindIP)
	}

	bindPort := binary.BigEndian.Uint16(connectReply[8:10])
	if bindPort == 0 {
		t.Fatal("CONNECT reply contains an invalid bind port")
	}

	// Check that application data travels through the proxy in both directions.
	message := []byte("ping")
	if _, err := client.Write(message); err != nil {
		t.Fatalf("write payload: %v", err)
	}

	response := make([]byte, len(message))
	if _, err := io.ReadFull(client, response); err != nil {
		t.Fatalf("read echoed payload: %v", err)
	}

	if string(response) != string(message) {
		t.Fatalf("unexpected payload: got %q, want %q", response, message)
	}
}

func TestConnectFailure(t *testing.T) {
	target, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve target port: %v", err)
	}

	targetPort := target.Addr().(*net.TCPAddr).Port

	// Release the port so that the following CONNECT attempt should fail.
	if err := target.Close(); err != nil {
		t.Fatalf("close target listener: %v", err)
	}

	proxyListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("start proxy listener: %v", err)
	}
	defer proxyListener.Close()

	go func() {
		conn, err := proxyListener.Accept()
		if err != nil {
			return
		}

		handleConnection(conn, testLookupIPv4, false, tlsfrag.StrategySNIMidpoint)
	}()

	client, err := net.Dial("tcp4", proxyListener.Addr().String())
	if err != nil {
		t.Fatalf("connect to proxy: %v", err)
	}
	defer client.Close()

	if err := client.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set client deadline: %v", err)
	}

	// Negotiate SOCKS5 without authentication.
	if _, err := client.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("write greeting: %v", err)
	}

	var methodReply [2]byte
	if _, err := io.ReadFull(client, methodReply[:]); err != nil {
		t.Fatalf("read method reply: %v", err)
	}

	if methodReply != [2]byte{0x05, 0x00} {
		t.Fatalf("unexpected method reply: %v", methodReply)
	}

	// Request a connection to the port whose listener we closed.
	request := []byte{0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0, 0}
	binary.BigEndian.PutUint16(request[8:10], uint16(targetPort))

	if _, err := client.Write(request); err != nil {
		t.Fatalf("write CONNECT request: %v", err)
	}

	var reply [10]byte
	if _, err := io.ReadFull(client, reply[:]); err != nil {
		t.Fatalf("read CONNECT failure reply: %v", err)
	}

	if reply[0] != 0x05 || reply[1] != 0x01 {
		t.Fatalf("unexpected failure reply: %v", reply)
	}
}

func TestConnectWithDomain(t *testing.T) {
	targetListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("start target listener: %v", err)
	}
	defer targetListener.Close()

	go func() {
		conn, err := targetListener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		if _, err := io.Copy(conn, conn); err != nil {
			t.Logf("echo connection ended: %v", err)
		}
	}()

	proxyListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("start proxy listener: %v", err)
	}
	defer proxyListener.Close()

	go func() {
		conn, err := proxyListener.Accept()
		if err != nil {
			return
		}

		handleConnection(conn, testLookupIPv4, false, tlsfrag.StrategySNIMidpoint)
	}()

	client, err := net.Dial("tcp4", proxyListener.Addr().String())
	if err != nil {
		t.Fatalf("connect to proxy: %v", err)
	}
	defer client.Close()

	if err := client.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set client deadline: %v", err)
	}

	// Negotiate SOCKS5 without authentication.
	if _, err := client.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("write greeting: %v", err)
	}

	var methodReply [2]byte
	if _, err := io.ReadFull(client, methodReply[:]); err != nil {
		t.Fatalf("read method reply: %v", err)
	}

	if methodReply != [2]byte{0x05, 0x00} {
		t.Fatalf("unexpected method reply: %v", methodReply)
	}

	// Build a SOCKS5 CONNECT request containing a domain name.
	domain := "localhost"
	request := []byte{0x05, 0x01, 0x00, 0x03, byte(len(domain))}
	request = append(request, []byte(domain)...)

	port := targetListener.Addr().(*net.TCPAddr).Port
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(port))
	request = append(request, portBytes...)

	if _, err := client.Write(request); err != nil {
		t.Fatalf("write domain CONNECT request: %v", err)
	}

	var connectReply [10]byte
	if _, err := io.ReadFull(client, connectReply[:]); err != nil {
		t.Fatalf("read CONNECT reply: %v", err)
	}

	if connectReply[0] != 0x05 || connectReply[1] != 0x00 {
		t.Fatalf("domain CONNECT failed: %v", connectReply)
	}

	// Verify that traffic is relayed after resolving the domain.
	message := []byte("ping")

	if _, err := client.Write(message); err != nil {
		t.Fatalf("write payload: %v", err)
	}

	response := make([]byte, len(message))
	if _, err := io.ReadFull(client, response); err != nil {
		t.Fatalf("read echoed payload: %v", err)
	}

	if string(response) != string(message) {
		t.Fatalf("unexpected payload: got %q, want %q", response, message)
	}
}

func TestEmptyDomain(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("start test listener: %v", err)
	}
	defer listener.Close()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}

		handleConnection(conn, testLookupIPv4, false, tlsfrag.StrategySNIMidpoint)
	}()

	client, err := net.Dial("tcp4", listener.Addr().String())
	if err != nil {
		t.Fatalf("connect to proxy: %v", err)
	}
	defer client.Close()

	if err := client.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set client deadline: %v", err)
	}

	if _, err := client.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("write greeting: %v", err)
	}

	var methodReply [2]byte
	if _, err := io.ReadFull(client, methodReply[:]); err != nil {
		t.Fatalf("read method reply: %v", err)
	}

	if methodReply != [2]byte{0x05, 0x00} {
		t.Fatalf("unexpected method reply: %v", methodReply)
	}

	// ATYP=0x03 with a zero-length hostname.
	request := []byte{0x05, 0x01, 0x00, 0x03, 0x00, 0x01, 0xBB}

	if _, err := client.Write(request); err != nil {
		t.Fatalf("write empty domain request: %v", err)
	}

	var reply [10]byte
	if _, err := io.ReadFull(client, reply[:]); err != nil {
		t.Fatalf("read failure reply: %v", err)
	}

	if reply[0] != 0x05 || reply[1] != 0x04 {
		t.Fatalf("unexpected failure reply: %v", reply)
	}
}

func TestConnectWithDomainFallback(t *testing.T) {
	targetListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("start target listener: %v", err)
	}
	defer targetListener.Close()

	go func() {
		conn, err := targetListener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		io.Copy(conn, conn)
	}()

	proxyListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("start proxy listener: %v", err)
	}
	defer proxyListener.Close()

	// Return an unreachable loopback address before the working address.
	lookup := func(ctx context.Context, hostname string) ([]net.IP, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		if hostname != "localhost" {
			return nil, fmt.Errorf("unexpected hostname: %s", hostname)
		}

		return []net.IP{
			net.IPv4(127, 0, 0, 2),
			net.IPv4(127, 0, 0, 1),
		}, nil
	}

	go func() {
		conn, err := proxyListener.Accept()
		if err != nil {
			return
		}

		handleConnection(conn, lookup, false, tlsfrag.StrategySNIMidpoint)
	}()

	client, err := net.Dial("tcp4", proxyListener.Addr().String())
	if err != nil {
		t.Fatalf("connect to proxy: %v", err)
	}
	defer client.Close()

	if err := client.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("set client deadline: %v", err)
	}

	if _, err := client.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("write SOCKS5 greeting: %v", err)
	}

	var methodReply [2]byte
	if _, err := io.ReadFull(client, methodReply[:]); err != nil {
		t.Fatalf("read method reply: %v", err)
	}

	if methodReply != [2]byte{0x05, 0x00} {
		t.Fatalf("unexpected method reply: %v", methodReply)
	}

	domain := "localhost"
	request := []byte{0x05, 0x01, 0x00, 0x03, byte(len(domain))}
	request = append(request, []byte(domain)...)

	port := targetListener.Addr().(*net.TCPAddr).Port
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(port))
	request = append(request, portBytes...)

	if _, err := client.Write(request); err != nil {
		t.Fatalf("write CONNECT request: %v", err)
	}

	var reply [10]byte
	if _, err := io.ReadFull(client, reply[:]); err != nil {
		t.Fatalf("read CONNECT reply: %v", err)
	}

	if reply[0] != 0x05 || reply[1] != 0x00 {
		t.Fatalf("fallback CONNECT failed: %v", reply)
	}

	message := []byte("ping")
	if _, err := client.Write(message); err != nil {
		t.Fatalf("write payload: %v", err)
	}

	response := make([]byte, len(message))
	if _, err := io.ReadFull(client, response); err != nil {
		t.Fatalf("read echoed payload: %v", err)
	}

	if string(response) != string(message) {
		t.Fatalf("unexpected payload: got %q, want %q", response, message)
	}
}

func testForwardClientTrafficFragmentsTLS(t *testing.T, strategy tlsfrag.Strategy) {
	t.Helper()

	// Construct a minimal ClientHello containing example.com as SNI.
	hostname := []byte("example.com")

	nameEntry := []byte{0x00, 0x00, byte(len(hostname))}
	nameEntry = append(nameEntry, hostname...)

	nameList := []byte{0x00, byte(len(nameEntry))}
	nameList = append(nameList, nameEntry...)

	extension := []byte{0x00, 0x00, 0x00, byte(len(nameList))}
	extension = append(extension, nameList...)

	body := make([]byte, 34)
	body[0], body[1] = 0x03, 0x03

	body = append(body,
		0x00,                   // Session ID length.
		0x00, 0x02, 0x13, 0x01, // One cipher suite.
		0x01, 0x00, // One compression method.
		0x00, byte(len(extension)),
	)
	body = append(body, extension...)

	handshake := []byte{
		0x01,
		byte(len(body) >> 16),
		byte(len(body) >> 8),
		byte(len(body)),
	}
	handshake = append(handshake, body...)

	original := []byte{0x16, 0x03, 0x03, 0x00, 0x00}
	binary.BigEndian.PutUint16(original[3:5], uint16(len(handshake)))
	original = append(original, handshake...)

	// Simulate the client-to-proxy and proxy-to-server connections.
	client, proxy := net.Pipe()
	defer client.Close()
	defer proxy.Close()

	server, observer := net.Pipe()
	defer server.Close()
	defer observer.Close()

	deadline := time.Now().Add(5 * time.Second)

	for _, conn := range []net.Conn{client, proxy, server, observer} {
		if err := conn.SetDeadline(deadline); err != nil {
			t.Fatalf("set connection deadline: %v", err)
		}
	}

	forwardDone := make(chan error, 1)

	go func() {
		forwardDone <- forwardClientTrafficWithStrategy(proxy, server, 443, initialTLSReadTimeout, strategy)
	}()

	writeDone := make(chan error, 1)

	go func() {
		_, err := client.Write(original)
		writeDone <- err
	}()

	// Read one complete TLS record from the observed output.
	readRecord := func() []byte {
		var header [5]byte

		if _, err := io.ReadFull(observer, header[:]); err != nil {
			t.Fatalf("read TLS header: %v", err)
		}

		length := int(binary.BigEndian.Uint16(header[3:5]))
		if length == 0 || length > 16384 {
			t.Fatalf("invalid TLS record length: %d", length)
		}

		record := make([]byte, 5+length)
		copy(record, header[:])

		if _, err := io.ReadFull(observer, record[5:]); err != nil {
			t.Fatalf("read TLS payload: %v", err)
		}

		return record
	}

	first := readRecord()
	second := readRecord()

	if err := <-writeDone; err != nil {
		t.Fatalf("write original ClientHello: %v", err)
	}

	// Send additional data after the fragmented ClientHello.
	// This write can complete only when the proxy starts its normal io.Copy phase.
	additional := []byte("ping")

	additionalDone := make(chan error, 1)

	go func() {
		_, err := client.Write(additional)
		additionalDone <- err
	}()

	received := make([]byte, len(additional))

	if _, err := io.ReadFull(observer, received); err != nil {
		t.Fatalf("read additional data: %v", err)
	}

	if !bytes.Equal(received, additional) {
		t.Fatalf("unexpected additional data: got %q, want %q", received, additional)
	}

	// The additional data was relayed successfully.
	// The proxy has already cleared its temporary read deadline.
	if err := client.Close(); err != nil {
		t.Fatalf("close test client: %v", err)
	}

	if err := <-forwardDone; err != nil {
		t.Fatalf("forward client traffic: %v", err)
	}

	if first[0] != 0x16 || second[0] != 0x16 {
		t.Fatal("expected two TLS handshake records")
	}

	reconstructed := append([]byte{}, first[5:]...)
	reconstructed = append(reconstructed, second[5:]...)

	if !bytes.Equal(reconstructed, original[5:]) {
		t.Fatal("fragmentation changed the ClientHello payload")
	}

	// Verify that the selected strategy produced the expected boundary.
	hostnameStart := bytes.Index(original, hostname)
	if hostnameStart < 0 {
		t.Fatal("original ClientHello has no hostname")
	}

	boundary := len(first)

	var expectedBoundary int

	switch strategy {
	case tlsfrag.StrategySNIMidpoint:
		expectedBoundary = hostnameStart + len(hostname)/2

	case tlsfrag.StrategyBeforeSNI:
		expectedBoundary = hostnameStart

	default:
		t.Fatalf("unexpected test strategy: %s", strategy)
	}

	if boundary != expectedBoundary {
		t.Fatalf(
			"unexpected split boundary for %s: got %d, want %d",
			strategy,
			boundary,
			expectedBoundary,
		)
	}

	t.Logf("original record: %d bytes", len(original))
	t.Logf("first record: %d bytes", len(first))
	t.Logf("second record: %d bytes", len(second))
	t.Logf("TLS split boundary: %d", boundary)
}

func TestForwardClientTrafficFragmentsTLS(t *testing.T) {
	tests := []struct {
		name     string
		strategy tlsfrag.Strategy
	}{
		{
			name:     "SNI midpoint",
			strategy: tlsfrag.StrategySNIMidpoint,
		},
		{
			name:     "before SNI",
			strategy: tlsfrag.StrategyBeforeSNI,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testForwardClientTrafficFragmentsTLS(t, tt.strategy)
		})
	}
}

func TestForwardClientTrafficPreservesNonTLS(t *testing.T) {
	client, proxy := net.Pipe()
	defer client.Close()
	defer proxy.Close()

	server, observer := net.Pipe()
	defer server.Close()
	defer observer.Close()

	deadline := time.Now().Add(5 * time.Second)

	for _, conn := range []net.Conn{client, proxy, server, observer} {
		if err := conn.SetDeadline(deadline); err != nil {
			t.Fatalf("set connection deadline: %v", err)
		}
	}

	forwardDone := make(chan error, 1)

	go func() {
		forwardDone <- forwardClientTraffic(proxy, server, 443)
	}()

	// Begin with a byte that is not a TLS handshake record type.
	first := []byte("G")

	writeDone := make(chan error, 1)

	go func() {
		_, err := client.Write(first)
		writeDone <- err
	}()

	receivedFirst := make([]byte, len(first))

	if _, err := io.ReadFull(observer, receivedFirst); err != nil {
		t.Fatalf("read first byte: %v", err)
	}

	if err := <-writeDone; err != nil {
		t.Fatalf("write first byte: %v", err)
	}

	// The remaining bytes must pass through normal TCP forwarding.
	remaining := []byte("ET / HTTP/1.1\r\nHost: example.com\r\n\r\n")

	go func() {
		_, err := client.Write(remaining)
		writeDone <- err
	}()

	receivedRemaining := make([]byte, len(remaining))

	if _, err := io.ReadFull(observer, receivedRemaining); err != nil {
		t.Fatalf("read remaining bytes: %v", err)
	}

	if err := <-writeDone; err != nil {
		t.Fatalf("write remaining bytes: %v", err)
	}

	received := append(receivedFirst, receivedRemaining...)
	expected := append(bytes.Clone(first), remaining...)

	if !bytes.Equal(received, expected) {
		t.Fatalf("non-TLS traffic changed:\ngot  %q\nwant %q",
			received, expected)
	}

	// The normal relay has processed the remaining bytes.
	if err := client.Close(); err != nil {
		t.Fatalf("close test client: %v", err)
	}

	if err := <-forwardDone; err != nil {
		t.Fatalf("forward non-TLS traffic: %v", err)
	}
}

func TestForwardClientTrafficRejectsIncompleteTLSHeader(t *testing.T) {
	client, proxy := net.Pipe()
	defer client.Close()
	defer proxy.Close()

	server, observer := net.Pipe()
	defer server.Close()
	defer observer.Close()

	deadline := time.Now().Add(5 * time.Second)

	for _, conn := range []net.Conn{client, proxy, server, observer} {
		if err := conn.SetDeadline(deadline); err != nil {
			t.Fatalf("set connection deadline: %v", err)
		}
	}

	forwardDone := make(chan error, 1)

	go func() {
		forwardDone <- forwardClientTraffic(proxy, server, 443)
	}()

	// Send only two bytes of the five-byte TLS record header.
	incomplete := []byte{0x16, 0x03}

	if _, err := client.Write(incomplete); err != nil {
		t.Fatalf("write incomplete TLS header: %v", err)
	}

	// End the input before the remaining header bytes arrive.
	if err := client.Close(); err != nil {
		t.Fatalf("close incomplete TLS connection: %v", err)
	}

	err := <-forwardDone

	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("expected incomplete TLS header error, got %v", err)
	}

	t.Logf("incomplete TLS record correctly rejected: %v", err)
}

func TestForwardClientTrafficTimeout(t *testing.T) {
	client, proxy := net.Pipe()
	defer client.Close()
	defer proxy.Close()

	server, observer := net.Pipe()
	defer server.Close()
	defer observer.Close()

	// Use a short timeout to keep the test fast.
	timeout := 50 * time.Millisecond

	forwardDone := make(chan error, 1)

	go func() {
		forwardDone <- forwardClientTrafficWithTimeout(
			proxy,
			server,
			443,
			timeout,
		)
	}()

	// Send only part of a TLS record header.
	// Keep the connection open to trigger a timeout, not EOF.
	if _, err := client.Write([]byte{0x16, 0x03}); err != nil {
		t.Fatalf("write incomplete TLS header: %v", err)
	}

	select {
	case err := <-forwardDone:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("expected timeout error, got %v", err)
		}

		t.Logf("incomplete TLS header timed out: %v", err)

	case <-time.After(2 * time.Second):
		t.Fatal("forwarding did not finish after the timeout")
	}
}

func TestLogRelayErrors(t *testing.T) {
	resetErr := errors.New("connection reset by peer")
	otherErr := errors.New("unexpected relay failure")
	closedErr := fmt.Errorf("read connection: %w", net.ErrClosed)

	tests := []struct {
		name       string
		firstErr   error
		secondErr  error
		wantOutput string
	}{
		{
			name: "no errors",
		},
		{
			name:       "first error only",
			firstErr:   resetErr,
			wantOutput: "TCP relay error: connection reset by peer\n",
		},
		{
			name:       "secondary closed connection",
			firstErr:   resetErr,
			secondErr:  closedErr,
			wantOutput: "TCP relay error: connection reset by peer\n",
		},
		{
			name:      "two independent errors",
			firstErr:  resetErr,
			secondErr: otherErr,
			wantOutput: "TCP relay error: connection reset by peer\n" +
				"TCP relay error: unexpected relay failure\n",
		},
		{
			name:      "second error without first failure",
			secondErr: closedErr,
			wantOutput: "TCP relay error: read connection: " +
				net.ErrClosed.Error() + "\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var output bytes.Buffer
			logger := log.New(&output, "", 0)

			logRelayErrors(logger, tt.firstErr, tt.secondErr)

			if got := output.String(); got != tt.wantOutput {
				t.Fatalf(
					"unexpected relay logs:\ngot:  %q\nwant: %q",
					got,
					tt.wantOutput,
				)
			}
		})
	}
}

func TestConnectPreservesHalfClose(t *testing.T) {
	tests := []struct {
		name     string
		fragment bool
	}{
		{
			name:     "without fragmentation",
			fragment: false,
		},
		{
			name:     "with fragmentation enabled",
			fragment: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("start target listener: %v", err)
			}
			defer target.Close()

			targetDone := make(chan error, 1)

			go func() {
				conn, err := target.Accept()
				if err != nil {
					targetDone <- err
					return
				}
				defer conn.Close()

				if err := conn.SetDeadline(
					time.Now().Add(5 * time.Second),
				); err != nil {
					targetDone <- err
					return
				}

				// Read until the client's FIN reaches the target.
				request, err := io.ReadAll(conn)
				if err != nil {
					targetDone <- err
					return
				}

				if !bytes.Equal(request, []byte("ping")) {
					targetDone <- fmt.Errorf(
						"unexpected request: %q",
						request,
					)
					return
				}

				// The response must remain possible after EOF.
				if _, err := io.WriteString(conn, "pong"); err != nil {
					targetDone <- err
					return
				}

				if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
					targetDone <- err
					return
				}

				targetDone <- nil
			}()

			proxyListener, err := net.Listen(
				"tcp4",
				"127.0.0.1:0",
			)
			if err != nil {
				t.Fatalf("start SOCKS5 listener: %v", err)
			}
			defer proxyListener.Close()

			proxyDone := make(chan struct{})

			go func() {
				defer close(proxyDone)

				conn, err := proxyListener.Accept()
				if err != nil {
					return
				}

				handleConnection(
					conn,
					testLookupIPv4,
					tt.fragment,
					tlsfrag.StrategySNIMidpoint,
				)
			}()

			client, err := net.Dial(
				"tcp4",
				proxyListener.Addr().String(),
			)
			if err != nil {
				t.Fatalf("connect to SOCKS5 proxy: %v", err)
			}
			defer client.Close()

			if err := client.SetDeadline(
				time.Now().Add(5 * time.Second),
			); err != nil {
				t.Fatalf("set client deadline: %v", err)
			}

			// SOCKS5 greeting: version 5, one method, no authentication.
			if _, err := client.Write([]byte{0x05, 0x01, 0x00}); err != nil {
				t.Fatalf("send SOCKS5 greeting: %v", err)
			}

			var methodReply [2]byte

			if _, err := io.ReadFull(
				client,
				methodReply[:],
			); err != nil {
				t.Fatalf("read authentication reply: %v", err)
			}

			if methodReply != [2]byte{0x05, 0x00} {
				t.Fatalf(
					"unexpected authentication reply: %v",
					methodReply,
				)
			}

			// CONNECT to the local TCP test server using IPv4.
			request := []byte{
				0x05, 0x01, 0x00, 0x01,
				127, 0, 0, 1,
				0x00, 0x00,
			}

			port := target.Addr().(*net.TCPAddr).Port

			binary.BigEndian.PutUint16(
				request[8:10],
				uint16(port),
			)

			if _, err := client.Write(request); err != nil {
				t.Fatalf("send SOCKS5 CONNECT: %v", err)
			}

			var connectReply [10]byte

			if _, err := io.ReadFull(
				client,
				connectReply[:],
			); err != nil {
				t.Fatalf("read SOCKS5 CONNECT reply: %v", err)
			}

			if connectReply[0] != 0x05 ||
				connectReply[1] != 0x00 ||
				connectReply[2] != 0x00 ||
				connectReply[3] != 0x01 {
				t.Fatalf(
					"unexpected CONNECT reply: %v",
					connectReply,
				)
			}

			if _, err := io.WriteString(client, "ping"); err != nil {
				t.Fatalf("send tunneled data: %v", err)
			}

			// Stop sending while keeping the receive side open.
			if err := client.(*net.TCPConn).CloseWrite(); err != nil {
				t.Fatalf("close client write direction: %v", err)
			}

			response, err := io.ReadAll(client)
			if err != nil {
				t.Fatalf("read tunneled response: %v", err)
			}

			if string(response) != "pong" {
				t.Fatalf(
					"unexpected response: got %q, want %q",
					response,
					"pong",
				)
			}

			select {
			case err := <-targetDone:
				if err != nil {
					t.Fatalf("target server: %v", err)
				}

			case <-time.After(5 * time.Second):
				t.Fatal("timed out waiting for target server")
			}

			select {
			case <-proxyDone:
				// The relay finished after both directions closed.

			case <-time.After(5 * time.Second):
				t.Fatal("SOCKS5 handler did not exit")
			}
		})
	}
}
