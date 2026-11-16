package httpproxy

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestTunnelRegistrationAndRemoval(t *testing.T) {
	h := &handler{}

	client, clientPeer := net.Pipe()
	defer client.Close()
	defer clientPeer.Close()

	upstream, upstreamPeer := net.Pipe()
	defer upstream.Close()
	defer upstreamPeer.Close()

	if !h.registerTunnel(client, upstream) {
		t.Fatal("expected tunnel registration to succeed")
	}

	h.mu.Lock()
	count := len(h.tunnels)
	h.mu.Unlock()

	if count != 1 {
		t.Fatalf("active tunnels = %d, want 1", count)
	}

	h.unregisterTunnel(client)

	h.mu.Lock()
	count = len(h.tunnels)
	h.mu.Unlock()

	if count != 0 {
		t.Fatalf("active tunnels = %d, want 0", count)
	}
}

func TestCloseTunnelsClosesBothConnections(t *testing.T) {
	h := &handler{}

	client, clientPeer := net.Pipe()
	defer client.Close()
	defer clientPeer.Close()

	upstream, upstreamPeer := net.Pipe()
	defer upstream.Close()
	defer upstreamPeer.Close()

	if !h.registerTunnel(client, upstream) {
		t.Fatal("expected tunnel registration to succeed")
	}

	// Set deadlines before closing the connections.
	deadline := time.Now().Add(time.Second)

	if err := clientPeer.SetReadDeadline(deadline); err != nil {
		t.Fatalf("set client peer deadline: %v", err)
	}

	if err := upstreamPeer.SetReadDeadline(deadline); err != nil {
		t.Fatalf("set upstream peer deadline: %v", err)
	}

	// Shutdown must close both ends owned by the handler.
	h.closeTunnels()

	// The opposite endpoints should observe EOF rather than remaining blocked on a read.
	for name, conn := range map[string]net.Conn{
		"client":   clientPeer,
		"upstream": upstreamPeer,
	} {
		var buf [1]byte

		n, err := conn.Read(buf[:])

		if n != 0 || !errors.Is(err, io.EOF) {
			t.Fatalf(
				"%s peer read = (%d, %v), want (0, EOF)",
				name,
				n,
				err,
			)
		}
	}
}

func TestCloseTunnelsRejectsNewConnections(t *testing.T) {
	h := &handler{}

	h.closeTunnels()

	client, clientPeer := net.Pipe()
	defer client.Close()
	defer clientPeer.Close()

	upstream, upstreamPeer := net.Pipe()
	defer upstream.Close()
	defer upstreamPeer.Close()

	if h.registerTunnel(client, upstream) {
		t.Fatal("tunnel registration must fail after shutdown")
	}
}

func TestCloseTunnelsIsIdempotent(t *testing.T) {
	h := &handler{}

	client, clientPeer := net.Pipe()
	defer client.Close()
	defer clientPeer.Close()

	upstream, upstreamPeer := net.Pipe()
	defer upstream.Close()
	defer upstreamPeer.Close()

	if !h.registerTunnel(client, upstream) {
		t.Fatal("expected tunnel registration to succeed")
	}

	h.closeTunnels()
	h.closeTunnels()

	h.unregisterTunnel(client)
}

func TestFilterShutdownRelayError(t *testing.T) {
	realErr := errors.New("unexpected relay failure")

	tests := []struct {
		name         string
		err          error
		shuttingDown bool
		wantNil      bool
	}{
		{
			name:    "nil error",
			wantNil: true,
		},
		{
			name:         "closed network connection during shutdown",
			err:          net.ErrClosed,
			shuttingDown: true,
			wantNil:      true,
		},
		{
			name:         "closed pipe during shutdown",
			err:          io.ErrClosedPipe,
			shuttingDown: true,
			wantNil:      true,
		},
		{
			name:         "closed network connection while running",
			err:          net.ErrClosed,
			shuttingDown: false,
			wantNil:      false,
		},
		{
			name:         "real error during shutdown",
			err:          realErr,
			shuttingDown: true,
			wantNil:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := filterShutdownRelayError(
				tt.err,
				tt.shuttingDown,
			)

			if (got == nil) != tt.wantNil {
				t.Fatalf(
					"filterShutdownRelayError() = %v, wantNil = %t",
					got,
					tt.wantNil,
				)
			}

			if !tt.wantNil && !errors.Is(got, tt.err) {
				t.Fatalf(
					"original error was not preserved: %v",
					got,
				)
			}
		})
	}
}
