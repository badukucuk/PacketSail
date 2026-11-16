package httpproxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/badukucuk/PacketSail/internal/tlsfrag"
)

func TestShutdownClosesActiveConnectTunnel(t *testing.T) {
	// net.Pipe creates the simulated upstream connection.
	// PacketSail receives one end; the test owns the other.
	upstream, upstreamPeer := net.Pipe()
	defer upstream.Close()
	defer upstreamPeer.Close()

	h := newHandler(
		func(context.Context, string) ([]net.IP, error) {
			t.Fatal("DNS must not be called for an IP destination")
			return nil, nil
		},
		func(ctx context.Context, network, address string) (net.Conn, error) {
			if network != "tcp4" || address != "127.0.0.1:443" {
				return nil, fmt.Errorf("unexpected upstream destination: %s %s", network, address)
			}

			return upstream, nil
		},
		false,
		tlsfrag.StrategySNIMidpoint,
	)

	server, err := startWithHandler("127.0.0.1:0", h)
	if err != nil {
		t.Fatalf("start HTTP CONNECT server: %v", err)
	}

	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		_ = server.Shutdown(ctx)
	}()

	client, err := net.DialTimeout("tcp4", server.address, time.Second)
	if err != nil {
		t.Fatalf("connect to proxy: %v", err)
	}
	defer client.Close()

	if err := client.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}

	request := "CONNECT 127.0.0.1:443 HTTP/1.1\r\n" + "Host: 127.0.0.1:443\r\n\r\n"

	if _, err := io.WriteString(client, request); err != nil {
		t.Fatalf("send CONNECT request: %v", err)
	}

	reader := bufio.NewReader(client)

	status, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}

	if !strings.HasPrefix(status, "HTTP/1.1 200 ") {
		t.Fatalf("unexpected CONNECT response: %q", status)
	}

	// Read the response headers until the empty line.
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("read CONNECT headers: %v", err)
		}

		if line == "\r\n" {
			break
		}
	}

	// The tunnel must be registered before the CONNECT response.
	h.mu.Lock()
	activeBefore := len(h.tunnels)
	h.mu.Unlock()

	if activeBefore != 1 {
		t.Fatalf("active tunnels before shutdown = %d, want 1", activeBefore)
	}

	// Set the upstream read deadline before shutdown closes its peer.
	if err := upstreamPeer.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set upstream read deadline: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		t.Fatalf("shutdown HTTP CONNECT server: %v", err)
	}

	if err := server.Wait(); err != nil {
		t.Fatalf("wait for HTTP CONNECT server: %v", err)
	}

	// Closing the hijacked TCP connection must unblock its client.
	var data [1]byte
	n, err := reader.Read(data[:])

	if n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("client read after shutdown = (%d, %v), want (0, EOF)", n, err)
	}

	n, err = upstreamPeer.Read(data[:])

	if n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf(
			"upstream read after shutdown = (%d, %v), want (0, EOF)",
			n,
			err,
		)
	}

	// Shutdown must stop new TCP connections to this listener.
	another, err := net.DialTimeout("tcp4", server.address, time.Second)
	if err == nil {
		another.Close()
		t.Fatal("HTTP CONNECT listener still accepts connections")
	}
}
