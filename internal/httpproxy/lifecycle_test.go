package httpproxy

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/badukucuk/PacketSail/internal/tlsfrag"
)

func TestStartCreatesReadyListener(t *testing.T) {
	server, err := Start(
		"127.0.0.1:0",
		false,
		tlsfrag.StrategySNIMidpoint,
		false,
	)
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := net.DialTimeout("tcp4", server.address, time.Second)
	if err != nil {
		t.Fatalf("listener is not ready: %v", err)
	}
	conn.Close()

	if err := server.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown() error = %v", err)
	}

	if err := server.Wait(); err != nil {
		t.Fatalf("Wait() error = %v", err)
	}
}

func TestStartRejectsOccupiedPort(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	server, err := Start(
		listener.Addr().String(),
		false,
		tlsfrag.StrategySNIMidpoint,
		false,
	)

	if err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

		server.Shutdown(ctx)
		server.Wait()

		t.Fatal("expected occupied port error")
	}
}

func TestShutdownStopsHTTPListener(t *testing.T) {
	server, err := Start(
		"127.0.0.1:0",
		false,
		tlsfrag.StrategySNIMidpoint,
		false,
	)
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	address := server.address

	conn, err := net.DialTimeout("tcp4", address, time.Second)
	if err != nil {
		t.Fatalf("listener is not ready: %v", err)
	}
	conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown() error = %v", err)
	}

	if err := server.Wait(); err != nil {
		t.Fatalf("Wait() error = %v", err)
	}

	conn, err = net.DialTimeout("tcp4", address, time.Second)
	if err == nil {
		conn.Close()
		t.Fatal("listener still accepts connections after shutdown")
	}

	var netErr *net.OpError
	if !errors.As(err, &netErr) {
		t.Fatalf("expected network error, got %v", err)
	}
}
