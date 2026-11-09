package httpproxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/badukucuk/PacketSail/internal/tlsfrag"
)

func TestConnectRejectsUnsupportedPort(t *testing.T) {
	proxy := httptest.NewServer(newHandler(
		func(context.Context, string) ([]net.IP, error) {
			t.Fatal("DNS lookup must not be called")
			return nil, nil
		},
		func(context.Context, string, string) (net.Conn, error) {
			t.Fatal("TCP dial must not be called")
			return nil, nil
		},
		true,
		tlsfrag.StrategySNIMidpoint,
	))
	defer proxy.Close()

	client := &http.Client{}

	req, err := http.NewRequest(
		http.MethodConnect,
		proxy.URL,
		nil,
	)
	if err != nil {
		t.Fatalf("create CONNECT request: %v", err)
	}

	req.Host = "example.com:80"

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("send CONNECT request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("unexpected status: got %d, want %d",
			resp.StatusCode, http.StatusForbidden)
	}
}

func TestConnectAndRelay(t *testing.T) {
	target, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("start test target: %v", err)
	}
	defer target.Close()

	targetDone := make(chan struct{})

	go func() {
		defer close(targetDone)

		conn, err := target.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		io.Copy(conn, conn)
	}()

	lookup := func(ctx context.Context, host string) ([]net.IP, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if host != "example.com" {
			return nil, fmt.Errorf("unexpected hostname: %s", host)
		}
		return []net.IP{net.IPv4(127, 0, 0, 1)}, nil
	}

	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp4" || address != "127.0.0.1:443" {
			return nil, fmt.Errorf("unexpected dial: %s %s", network, address)
		}

		var dialer net.Dialer
		return dialer.DialContext(ctx, "tcp4", target.Addr().String())
	}

	proxy := httptest.NewServer(newHandler(lookup, dial, true, tlsfrag.StrategySNIMidpoint))
	defer proxy.Close()

	client, err := net.Dial("tcp4", proxy.Listener.Addr().String())
	if err != nil {
		t.Fatalf("connect to HTTP proxy: %v", err)
	}
	defer client.Close()

	if err := client.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set test deadline: %v", err)
	}

	request := "CONNECT example.com:443 HTTP/1.1\r\n" +
		"Host: example.com:443\r\n\r\n"

	if _, err := io.WriteString(client, request); err != nil {
		t.Fatalf("send CONNECT request: %v", err)
	}

	reader := bufio.NewReader(client)

	status, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read CONNECT status: %v", err)
	}

	if !strings.HasPrefix(status, "HTTP/1.1 200 ") {
		t.Fatalf("unexpected CONNECT response: %q", status)
	}

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("read CONNECT headers: %v", err)
		}
		if line == "\r\n" {
			break
		}
	}

	// The first byte is not a TLS handshake record.
	// The relay must preserve this traffic unchanged.
	message := []byte("ping")

	if _, err := client.Write(message); err != nil {
		t.Fatalf("send tunneled data: %v", err)
	}

	received := make([]byte, len(message))
	if _, err := io.ReadFull(reader, received); err != nil {
		t.Fatalf("read tunneled response: %v", err)
	}

	if string(received) != string(message) {
		t.Fatalf("unexpected response: got %q, want %q",
			received, message)
	}

	client.Close()
	<-targetDone
}

func TestConnectDNSFailure(t *testing.T) {
	proxy := httptest.NewServer(newHandler(
		func(ctx context.Context, host string) ([]net.IP, error) {
			if host != "example.com" {
				return nil, fmt.Errorf("unexpected hostname: %s", host)
			}

			return nil, fmt.Errorf("DNS lookup failed")
		},
		func(context.Context, string, string) (net.Conn, error) {
			t.Error("dial must not be called after DNS failure")
			return nil, fmt.Errorf("unexpected dial")
		},
		true,
		tlsfrag.StrategySNIMidpoint,
	))
	defer proxy.Close()

	req, err := http.NewRequest(http.MethodConnect, proxy.URL, nil)
	if err != nil {
		t.Fatalf("create CONNECT request: %v", err)
	}

	req.Host = "example.com:443"

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("send CONNECT request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("unexpected status: got %d, want %d",
			resp.StatusCode, http.StatusBadGateway)
	}
}

func TestConnectTCPFailure(t *testing.T) {
	dialAttempts := 0

	proxy := httptest.NewServer(newHandler(
		func(ctx context.Context, host string) ([]net.IP, error) {
			return []net.IP{
				net.IPv4(192, 0, 2, 1),
				net.IPv4(192, 0, 2, 2),
			}, nil
		},
		func(ctx context.Context, network, address string) (net.Conn, error) {
			dialAttempts++
			return nil, fmt.Errorf("connection refused")
		},
		true,
		tlsfrag.StrategySNIMidpoint,
	))
	defer proxy.Close()

	req, err := http.NewRequest(http.MethodConnect, proxy.URL, nil)
	if err != nil {
		t.Fatalf("create CONNECT request: %v", err)
	}

	req.Host = "example.com:443"

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("send CONNECT request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("unexpected status: got %d, want %d",
			resp.StatusCode, http.StatusBadGateway)
	}

	if dialAttempts != 2 {
		t.Fatalf("unexpected dial attempts: got %d, want 2",
			dialAttempts)
	}
}

func TestConnectPreservesBufferedData(t *testing.T) {
	target, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("start test target: %v", err)
	}
	defer target.Close()

	received := make(chan string, 1)

	go func() {
		conn, err := target.Accept()
		if err != nil {
			received <- ""
			return
		}
		defer conn.Close()

		if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			received <- ""
			return
		}

		data := make([]byte, 4)
		if _, err := io.ReadFull(conn, data); err != nil {
			received <- ""
			return
		}

		received <- string(data)
	}()

	lookup := func(ctx context.Context, host string) ([]net.IP, error) {
		if host != "example.com" {
			return nil, fmt.Errorf("unexpected hostname: %s", host)
		}

		return []net.IP{net.IPv4(127, 0, 0, 1)}, nil
	}

	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		var dialer net.Dialer
		return dialer.DialContext(ctx, "tcp4", target.Addr().String())
	}

	proxy := httptest.NewServer(newHandler(lookup, dial, true, tlsfrag.StrategySNIMidpoint))
	defer proxy.Close()

	client, err := net.Dial("tcp4", proxy.Listener.Addr().String())
	if err != nil {
		t.Fatalf("connect to proxy: %v", err)
	}
	defer client.Close()

	if err := client.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set client deadline: %v", err)
	}

	request := "CONNECT example.com:443 HTTP/1.1\r\n" +
		"Host: example.com:443\r\n\r\n" +
		"ping"

	// Send the CONNECT request and tunnel bytes in a single write.
	if _, err := io.WriteString(client, request); err != nil {
		t.Fatalf("send CONNECT request and data: %v", err)
	}

	reader := bufio.NewReader(client)

	status, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read CONNECT status: %v", err)
	}

	if !strings.HasPrefix(status, "HTTP/1.1 200 ") {
		t.Fatalf("unexpected CONNECT response: %q", status)
	}

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("read CONNECT headers: %v", err)
		}

		if line == "\r\n" {
			break
		}
	}

	select {
	case data := <-received:
		if data != "ping" {
			t.Fatalf("unexpected tunneled data: got %q, want %q",
				data, "ping")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for tunneled data")
	}
}

func makeRealClientHello(t *testing.T) []byte {
	t.Helper()

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	tlsClient := tls.Client(clientConn, &tls.Config{
		ServerName: "updates.discord.com",
	})
	defer tlsClient.Close()

	done := make(chan struct{})

	go func() {
		defer close(done)

		// Only the ClientHello is needed, not a full TLS handshake.
		_ = tlsClient.Handshake()
	}()

	if err := serverConn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set ClientHello deadline: %v", err)
	}

	var header [5]byte

	if _, err := io.ReadFull(serverConn, header[:]); err != nil {
		t.Fatalf("read TLS record header: %v", err)
	}

	if header[0] != 0x16 {
		t.Fatalf("expected TLS handshake record, got 0x%02x", header[0])
	}

	length := int(binary.BigEndian.Uint16(header[3:5]))

	record := make([]byte, 5+length)
	copy(record, header[:])

	if _, err := io.ReadFull(serverConn, record[5:]); err != nil {
		t.Fatalf("read TLS ClientHello: %v", err)
	}

	// End the unfinished handshake so its goroutine can exit.
	serverConn.Close()
	tlsClient.Close()
	<-done

	return record
}

func testConnectFragmentsRealClientHello(t *testing.T, strategy tlsfrag.Strategy) {
	t.Helper()

	original := makeRealClientHello(t)

	// Ensure the test actually contains a parsable SNI.
	hostname, offset, err := tlsfrag.FindServerName(original)
	if err != nil {
		t.Fatalf("find ClientHello SNI: %v", err)
	}

	if hostname != "updates.discord.com" {
		t.Fatalf("unexpected SNI: %q", hostname)
	}

	expectedSplit := offset - 5

	if strategy == tlsfrag.StrategySNIMidpoint {
		expectedSplit += len(hostname) / 2
	}

	target, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("start target listener: %v", err)
	}
	defer target.Close()

	type receivedHello struct {
		payload     []byte
		firstLength int
	}

	received := make(chan receivedHello, 1)
	targetErrors := make(chan error, 1)

	go func() {
		conn, err := target.Accept()
		if err != nil {
			targetErrors <- err
			return
		}
		defer conn.Close()

		if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			targetErrors <- err
			return
		}

		// Read the two TLS records produced by PacketSail.
		var combined []byte
		var firstLength int

		for i := 0; i < 2; i++ {
			var header [5]byte

			if _, err := io.ReadFull(conn, header[:]); err != nil {
				targetErrors <- fmt.Errorf("read record %d header: %w", i+1, err)
				return
			}

			if header[0] != 0x16 {
				targetErrors <- fmt.Errorf("record %d is not a handshake record", i+1)
				return
			}

			length := int(binary.BigEndian.Uint16(header[3:5]))

			if i == 0 {
				firstLength = length
			}

			payload := make([]byte, length)
			if _, err := io.ReadFull(conn, payload); err != nil {
				targetErrors <- fmt.Errorf("read record %d payload: %w", i+1, err)
				return
			}

			combined = append(combined, payload...)
		}

		received <- receivedHello{
			payload:     combined,
			firstLength: firstLength,
		}
	}()

	lookup := func(ctx context.Context, host string) ([]net.IP, error) {
		if host != "updates.discord.com" {
			return nil, fmt.Errorf("unexpected hostname: %s", host)
		}

		return []net.IP{net.IPv4(127, 0, 0, 1)}, nil
	}

	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp4" || address != "127.0.0.1:443" {
			return nil, fmt.Errorf("unexpected destination: %s %s", network, address)
		}

		var dialer net.Dialer
		return dialer.DialContext(ctx, "tcp4", target.Addr().String())
	}

	proxy := httptest.NewServer(newHandler(lookup, dial, true, strategy))
	defer proxy.Close()

	client, err := net.Dial("tcp4", proxy.Listener.Addr().String())
	if err != nil {
		t.Fatalf("connect to HTTP proxy: %v", err)
	}
	defer client.Close()

	if err := client.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set client deadline: %v", err)
	}

	request := "CONNECT updates.discord.com:443 HTTP/1.1\r\n" +
		"Host: updates.discord.com:443\r\n\r\n"

	// Send CONNECT and ClientHello together to exercise buffered data handling.
	data := append([]byte(request), original...)

	if _, err := client.Write(data); err != nil {
		t.Fatalf("send CONNECT and ClientHello: %v", err)
	}

	reader := bufio.NewReader(client)

	response, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		t.Fatalf("unexpected CONNECT status: %d", response.StatusCode)
	}

	select {
	case result := <-received:
		// TLS record headers change, but handshake payload must remain intact.
		if !bytes.Equal(result.payload, original[5:]) {
			t.Fatal("fragmentation modified the ClientHello payload")
		}

		if result.firstLength != expectedSplit {
			t.Fatalf(
				"unexpected split position for %s: got %d, want %d",
				strategy,
				result.firstLength,
				expectedSplit,
			)
		}

	case err := <-targetErrors:
		t.Fatalf("target server failed: %v", err)

	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for fragmented ClientHello")
	}
}

func TestConnectFragmentsRealClientHello(t *testing.T) {
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
			testConnectFragmentsRealClientHello(t, tt.strategy)
		})
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
			wantOutput: "HTTP CONNECT relay error: connection reset by peer\n",
		},
		{
			name:       "secondary closed connection",
			firstErr:   resetErr,
			secondErr:  closedErr,
			wantOutput: "HTTP CONNECT relay error: connection reset by peer\n",
		},
		{
			name:      "two independent errors",
			firstErr:  resetErr,
			secondErr: otherErr,
			wantOutput: "HTTP CONNECT relay error: connection reset by peer\n" +
				"HTTP CONNECT relay error: unexpected relay failure\n",
		},
		{
			name:      "second error without first failure",
			secondErr: closedErr,
			wantOutput: "HTTP CONNECT relay error: read connection: " +
				net.ErrClosed.Error() + "\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var output bytes.Buffer

			// Use an isolated logger to avoid changing global logging.
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

				// Read until PacketSail forwards the client's FIN.
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

				// Reply after the client has stopped sending.
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

			lookup := func(
				ctx context.Context,
				host string,
			) ([]net.IP, error) {
				if host != "example.com" {
					return nil, fmt.Errorf(
						"unexpected hostname: %s",
						host,
					)
				}

				return []net.IP{net.IPv4(127, 0, 0, 1)}, nil
			}

			dial := func(
				ctx context.Context,
				network string,
				address string,
			) (net.Conn, error) {
				if network != "tcp4" ||
					address != "127.0.0.1:443" {
					return nil, fmt.Errorf(
						"unexpected destination: %s %s",
						network,
						address,
					)
				}

				var dialer net.Dialer

				return dialer.DialContext(
					ctx,
					network,
					target.Addr().String(),
				)
			}

			proxy := httptest.NewServer(newHandler(
				lookup,
				dial,
				tt.fragment,
				tlsfrag.StrategySNIMidpoint,
			))
			defer proxy.Close()

			client, err := net.Dial(
				"tcp4",
				proxy.Listener.Addr().String(),
			)
			if err != nil {
				t.Fatalf("connect to HTTP proxy: %v", err)
			}
			defer client.Close()

			if err := client.SetDeadline(
				time.Now().Add(5 * time.Second),
			); err != nil {
				t.Fatalf("set client deadline: %v", err)
			}

			connectRequest := "CONNECT example.com:443 HTTP/1.1\r\n" + "Host: example.com:443\r\n\r\n"

			if _, err := io.WriteString(
				client,
				connectRequest,
			); err != nil {
				t.Fatalf("send CONNECT request: %v", err)
			}

			reader := bufio.NewReader(client)

			response, err := http.ReadResponse(reader, nil)
			if err != nil {
				t.Fatalf("read CONNECT response: %v", err)
			}

			if response.StatusCode != http.StatusOK {
				t.Fatalf(
					"unexpected CONNECT status: %d",
					response.StatusCode,
				)
			}

			if _, err := io.WriteString(client, "ping"); err != nil {
				t.Fatalf("send tunneled request: %v", err)
			}

			// Stop sending but keep the receive direction open.
			if err := client.(*net.TCPConn).CloseWrite(); err != nil {
				t.Fatalf("close client write direction: %v", err)
			}

			// The server must still be able to send its response.
			reply, err := io.ReadAll(reader)
			if err != nil {
				t.Fatalf("read tunneled response: %v", err)
			}

			if string(reply) != "pong" {
				t.Fatalf(
					"unexpected response: got %q, want %q",
					reply,
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
		})
	}
}
