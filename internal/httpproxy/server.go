package httpproxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/badukucuk/PacketSail/internal/dns"
	"github.com/badukucuk/PacketSail/internal/tlsfrag"
)

const (
	dnsTimeout        = 8 * time.Second
	connectTimeout    = 5 * time.Second
	initialTLSTimeout = 10 * time.Second
)

type lookupFunc func(context.Context, string) ([]net.IP, error)
type dialFunc func(context.Context, string, string) (net.Conn, error)

type handler struct {
	lookup   lookupFunc
	dial     dialFunc
	fragment bool
	strategy tlsfrag.Strategy
}

// ListenAndServe starts the local HTTP CONNECT proxy.
func ListenAndServe(address string, fragment bool, strategy tlsfrag.Strategy) error {
	resolver := dns.NewResolver()
	dialer := &net.Dialer{Timeout: connectTimeout}

	server := &http.Server{
		Addr:              address,
		Handler:           newHandler(resolver.LookupIPv4, dialer.DialContext, fragment, strategy),
		ReadHeaderTimeout: 10 * time.Second,
	}

	log.Printf("HTTP CONNECT proxy listening on %s", address)

	if err := server.ListenAndServe(); err != nil {
		return fmt.Errorf("serve HTTP CONNECT proxy: %w", err)
	}

	return nil
}

// newHandler creates a CONNECT handler with injectable network operations.
func newHandler(lookup lookupFunc, dial dialFunc, fragment bool, strategy tlsfrag.Strategy) http.Handler {
	return &handler{
		lookup:   lookup,
		dial:     dial,
		fragment: fragment,
		strategy: strategy,
	}
}

// ServeHTTP validates CONNECT requests and establishes a TCP tunnel.
func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		http.Error(w, "CONNECT method required", http.StatusMethodNotAllowed)
		return
	}

	host, port, err := net.SplitHostPort(r.Host)
	if err != nil || host == "" {
		http.Error(w, "invalid CONNECT destination", http.StatusBadRequest)
		return
	}

	// Restrict the initial implementation to HTTPS destinations.
	if port != "443" {
		http.Error(w, "CONNECT port not allowed", http.StatusForbidden)
		return
	}

	var addresses []net.IP

	if ip := net.ParseIP(host); ip != nil {
		ipv4 := ip.To4()
		if ipv4 == nil {
			http.Error(w, "IPv6 destinations are not supported", http.StatusBadRequest)
			return
		}

		addresses = []net.IP{ipv4}
	} else {
		ctx, cancel := context.WithTimeout(r.Context(), dnsTimeout)
		addresses, err = h.lookup(ctx, host)
		cancel()

		if err != nil || len(addresses) == 0 {
			http.Error(w, "destination DNS lookup failed", http.StatusBadGateway)
			return
		}
	}

	var upstream net.Conn

	for _, ip := range addresses {
		if ip.To4() == nil {
			continue
		}

		target := net.JoinHostPort(ip.String(), port)

		ctx, cancel := context.WithTimeout(r.Context(), connectTimeout)
		upstream, err = h.dial(ctx, "tcp4", target)
		cancel()

		if err == nil {
			break
		}
	}

	if upstream == nil {
		http.Error(w, "destination connection failed", http.StatusBadGateway)
		return
	}
	defer upstream.Close()

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "HTTP connection hijacking unavailable", http.StatusInternalServerError)
		return
	}

	client, buffered, err := hijacker.Hijack()
	if err != nil {
		log.Printf("hijack CONNECT connection: %v", err)
		return
	}
	defer client.Close()

	// A successful CONNECT response marks the start of the raw TCP tunnel.
	if _, err := buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	if err := buffered.Flush(); err != nil {
		return
	}

	finished := make(chan error, 2)

	go func() {
		var forwardErr error

		if h.fragment {
			// Buffered bytes may include the beginning of ClientHello.
			// Reading from buffered.Reader ensures they are not lost.
			if err := client.SetReadDeadline(time.Now().Add(initialTLSTimeout)); err != nil {
				forwardErr = err
			} else {
				forwardErr = tlsfrag.ForwardInitialRecordWithStrategy(upstream, buffered.Reader, h.strategy)
				clearErr := client.SetReadDeadline(time.Time{})

				if forwardErr == nil {
					forwardErr = clearErr
				}
			}
		}

		if forwardErr == nil {
			_, forwardErr = io.Copy(upstream, buffered.Reader)
		}

		if tcp, ok := upstream.(*net.TCPConn); ok {
			if err := tcp.CloseWrite(); err != nil && forwardErr == nil {
				forwardErr = err
			}
		}

		finished <- forwardErr
	}()

	go func() {
		_, forwardErr := io.Copy(client, upstream)

		if tcp, ok := client.(*net.TCPConn); ok {
			if err := tcp.CloseWrite(); err != nil && forwardErr == nil {
				forwardErr = err
			}
		}

		finished <- forwardErr
	}()

	firstErr := <-finished

	if firstErr != nil {
		// Stop the other relay direction after a transfer failure.
		client.Close()
		upstream.Close()
	}

	secondErr := <-finished

	logRelayErrors(log.Default(), firstErr, secondErr)
}

// logRelayErrors reports transfer failures while suppressing a
// secondary closed-connection error caused by stopping the relay.
func logRelayErrors(logger *log.Logger, firstErr, secondErr error) {
	if firstErr != nil {
		logger.Printf("HTTP CONNECT relay error: %v", firstErr)
	}

	if secondErr == nil {
		return
	}

	// The first failure caused both connections to close.
	// A subsequent net.ErrClosed is an expected consequence.
	if firstErr != nil && errors.Is(secondErr, net.ErrClosed) {
		return
	}

	logger.Printf("HTTP CONNECT relay error: %v", secondErr)
}
