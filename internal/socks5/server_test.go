package socks5

import (
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

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

		handleConnection(conn)
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

		handleConnection(conn)
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

		handleConnection(conn)
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
