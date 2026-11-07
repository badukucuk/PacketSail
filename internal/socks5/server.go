package socks5

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"time"

	"github.com/badukucuk/PacketSail/internal/dns"
	"github.com/badukucuk/PacketSail/internal/tlsfrag"
)

// ListenAndServe starts a local SOCKS5 server and accepts TCP connections.
func ListenAndServe(address string, fragment bool) error {
	listener, err := net.Listen("tcp4", address)
	if err != nil {
		return fmt.Errorf("start SOCKS5 listener: %w", err)
	}
	defer listener.Close()

	log.Printf("SOCKS5 proxy listening on %s", listener.Addr())
	resolver := dns.NewResolver()

	for {
		conn, err := listener.Accept()
		if err != nil {
			return fmt.Errorf("accept SOCKS5 connection: %w", err)
		}

		go handleConnection(conn, resolver.LookupIPv4, fragment)
	}
}

// handleConnection processes one SOCKS5 client connection.
func handleConnection(client net.Conn, lookupIPv4 func(context.Context, string) ([]net.IP, error), fragment bool) {
	defer client.Close()

	// Limit how long a client can leave protocol negotiation unfinished.
	if err := client.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		log.Printf("set client deadline: %v", err)
		return
	}

	var greeting [2]byte
	if _, err := io.ReadFull(client, greeting[:]); err != nil {
		return
	}

	if greeting[0] != 0x05 || greeting[1] == 0 {
		return
	}

	methods := make([]byte, int(greeting[1]))
	if _, err := io.ReadFull(client, methods); err != nil {
		return
	}

	supported := false
	for _, method := range methods {
		if method == 0x00 {
			supported = true
			break
		}
	}

	if !supported {
		client.Write([]byte{0x05, 0xFF})
		return
	}

	if _, err := client.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	var request [4]byte
	if _, err := io.ReadFull(client, request[:]); err != nil {
		return
	}

	if request[0] != 0x05 || request[2] != 0x00 {
		log.Printf("invalid SOCKS5 request header")
		return
	}

	if request[1] != 0x01 {
		if err := sendReply(client, 0x07, nil); err != nil {
			log.Printf("send unsupported command reply: %v", err)
		}
		return
	}

	var host string
	var port uint16

	switch request[3] {
	case 0x01:
		// IPv4 addresses contain four address bytes followed by a two-byte port.
		var destination [6]byte
		if _, err := io.ReadFull(client, destination[:]); err != nil {
			return
		}

		host = net.IP(destination[:4]).String()
		port = binary.BigEndian.Uint16(destination[4:])

	case 0x03:
		// Domain names are prefixed by their length in bytes.
		var length [1]byte
		if _, err := io.ReadFull(client, length[:]); err != nil {
			return
		}

		if length[0] == 0 {
			if err := sendReply(client, 0x04, nil); err != nil {
				log.Printf("send empty hostname reply: %v", err)
			}
			return
		}

		domain := make([]byte, int(length[0]))
		if _, err := io.ReadFull(client, domain); err != nil {
			return
		}

		var portBytes [2]byte
		if _, err := io.ReadFull(client, portBytes[:]); err != nil {
			return
		}

		host = string(domain)
		port = binary.BigEndian.Uint16(portBytes[:])

	default:
		if err := sendReply(client, 0x08, nil); err != nil {
			log.Printf("send unsupported address type reply: %v", err)
		}
		return
	}

	var addresses []net.IP

	if request[3] == 0x03 {
		// Resolve domain names through DNS-over-HTTPS, not system DNS.
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		resolved, err := lookupIPv4(ctx, host)
		cancel()

		if err != nil {
			log.Printf("resolve %s: %v", host, err)

			if replyErr := sendReply(client, 0x04, nil); replyErr != nil {
				log.Printf("send DNS failure reply: %v", replyErr)
			}
			return
		}

		addresses = resolved
	} else {
		// IPv4 destinations already contain the target address.
		addresses = []net.IP{net.ParseIP(host).To4()}
	}

	if len(addresses) == 0 {
		log.Printf("no IPv4 addresses available for %s", host)

		if err := sendReply(client, 0x04, nil); err != nil {
			log.Printf("send missing address reply: %v", err)
		}
		return
	}

	// The SOCKS5 request has been parsed. Outbound operations have their own timeouts.
	if err := client.SetDeadline(time.Time{}); err != nil {
		log.Printf("clear client deadline: %v", err)
		return
	}

	var server net.Conn
	var lastErr error

	// Try each resolved IPv4 address until a TCP connection succeeds.
	for _, ip := range addresses {
		target := net.JoinHostPort(ip.String(), strconv.Itoa(int(port)))

		server, lastErr = net.DialTimeout("tcp4", target, 5*time.Second)
		if lastErr == nil {
			break
		}

		log.Printf("connect to %s: %v", target, lastErr)
	}

	if server == nil {
		if err := sendReply(client, 0x01, nil); err != nil {
			log.Printf("send connection failure reply: %v", err)
		}
		return
	}

	defer server.Close()

	if err := sendReply(client, 0x00, server.LocalAddr().(*net.TCPAddr)); err != nil {
		return
	}

	finished := make(chan error, 2)

	// Forward client data to the destination, fragmenting the initial ClientHello on HTTPS connections when possible.
	go func() {
		var err error

		if fragment {
			err = forwardClientTraffic(client, server, port)
		} else {
			_, err = io.Copy(server, client)
		}

		if closeErr := server.(*net.TCPConn).CloseWrite(); closeErr != nil && err == nil {
			err = closeErr
		}

		finished <- err
	}()

	// Forward responses from the destination server back to the client.
	go func() {
		_, err := io.Copy(client, server)

		if closeErr := client.(*net.TCPConn).CloseWrite(); closeErr != nil && err == nil {
			err = closeErr
		}

		finished <- err
	}()

	firstErr := <-finished

	if firstErr != nil {
		// Closing both connections unblocks the remaining transfer on failure.
		client.Close()
		server.Close()
	}

	secondErr := <-finished

	if firstErr != nil {
		log.Printf("TCP relay error: %v", firstErr)
	}

	if secondErr != nil {
		log.Printf("TCP relay error: %v", secondErr)
	}
}

const initialTLSReadTimeout = 10 * time.Second

// forwardClientTraffic forwards client data using the default TLS read timeout.
func forwardClientTraffic(client net.Conn, server net.Conn, port uint16) error {
	return forwardClientTrafficWithTimeout(
		client,
		server,
		port,
		initialTLSReadTimeout,
	)
}

// forwardClientTrafficWithTimeout forwards client data to the destination.
// On port 443, it attempts to fragment the initial ClientHello record using the specified read timeout before forwarding the remaining data.
func forwardClientTrafficWithTimeout(client net.Conn, server net.Conn, port uint16, timeout time.Duration) error {
	if port == 443 {
		if err := client.SetReadDeadline(time.Now().Add(timeout)); err != nil {
			return fmt.Errorf("set initial TLS read deadline: %w", err)
		}

		forwardErr := tlsfrag.ForwardInitialRecord(server, client)

		// Clear the temporary deadline before normal TCP forwarding.
		clearErr := client.SetReadDeadline(time.Time{})

		if forwardErr != nil {
			return fmt.Errorf("forward initial TLS record: %w", forwardErr)
		}

		if clearErr != nil {
			return fmt.Errorf("clear initial TLS read deadline: %w", clearErr)
		}
	}

	// Once the first record is processed, relay all remaining bytes unchanged.
	_, err := io.Copy(server, client)
	if err != nil {
		return fmt.Errorf("forward client traffic: %w", err)
	}

	return nil
}

// sendReply sends a SOCKS5 response with an IPv4 bind address.
func sendReply(client net.Conn, status byte, addr *net.TCPAddr) error {
	reply := make([]byte, 10)

	reply[0] = 0x05
	reply[1] = status
	reply[2] = 0x00
	reply[3] = 0x01

	if addr != nil {
		copy(reply[4:8], addr.IP.To4())
		binary.BigEndian.PutUint16(reply[8:10], uint16(addr.Port))
	}

	n, err := client.Write(reply)
	if err != nil {
		return fmt.Errorf("send SOCKS5 reply: %w", err)
	}

	if n != len(reply) {
		return io.ErrShortWrite
	}

	return nil
}
