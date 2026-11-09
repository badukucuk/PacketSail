package httpproxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
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

	debug  bool
	nextID atomic.Uint64
}

// ListenAndServe starts the local HTTP CONNECT proxy.
func ListenAndServe(address string, fragment bool, strategy tlsfrag.Strategy, debug bool) error {
	resolver := dns.NewResolver()
	dialer := &net.Dialer{Timeout: connectTimeout}

	h := newHandler(
		resolver.LookupIPv4,
		dialer.DialContext,
		fragment,
		strategy,
	)
	h.debug = debug

	server := &http.Server{
		Addr:              address,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
	}

	log.Printf("HTTP CONNECT proxy listening on %s", address)

	if err := server.ListenAndServe(); err != nil {
		return fmt.Errorf("serve HTTP CONNECT proxy: %w", err)
	}

	return nil
}

// debugf logs CONNECT events when diagnostics are enabled.
func (h *handler) debugf(id uint64, format string, args ...any) {
	if !h.debug {
		return
	}

	log.Printf("[CONNECT %d] "+format, append([]any{id}, args...)...)
}

// newHandler creates a CONNECT handler with injectable network operations.
func newHandler(lookup lookupFunc, dial dialFunc, fragment bool, strategy tlsfrag.Strategy) *handler {
	return &handler{
		lookup:   lookup,
		dial:     dial,
		fragment: fragment,
		strategy: strategy,
	}
}

// Allow standard HTTPS connections and the additional TLS ports
// used by Discord's voice infrastructure.
func isAllowedConnectDestination(host, port string) bool {
	if port == "443" {
		return true
	}

	// Additional ports must remain restricted to Discord media hosts.
	if !strings.HasSuffix(strings.ToLower(host), ".discord.media") {
		return false
	}

	switch port {
	case "2053", "2083", "2087", "2096", "8443":
		return true
	default:
		return false
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

	id := h.nextID.Add(1)
	started := time.Now()

	h.debugf(id, "requested: %s, client: %s", r.Host, r.RemoteAddr)

	if !isAllowedConnectDestination(host, port) {
		h.debugf(id, "rejected: destination not allowed")

		http.Error(w, "CONNECT destination not allowed", http.StatusForbidden)
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
			h.debugf(id, "DNS lookup failed: %v", err)
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
			h.debugf(id, "upstream connected: %s", target)
			break
		}

		h.debugf(id, "upstream dial failed: %s: %v", target, err)
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

	h.debugf(id, "tunnel established")

	type relayResult struct {
		direction string
		err       error
	}

	finished := make(chan relayResult, 2)

	go func() {
		var forwardErr error

		if h.fragment {
			// Buffered bytes may include the beginning of ClientHello.
			// Reading from buffered.Reader ensures they are not lost.
			if err := client.SetReadDeadline(time.Now().Add(initialTLSTimeout)); err != nil {
				forwardErr = err
			} else {
				forwardErr = tlsfrag.ForwardInitialRecordWithStrategy(upstream, buffered.Reader, h.strategy)

				if forwardErr == nil {
					h.debugf(id, "initial TLS record forwarded: %s", h.strategy)
				} else {
					h.debugf(id, "initial TLS record failed: %v", forwardErr)
				}

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

		finished <- relayResult{direction: "client-to-server", err: forwardErr}
	}()

	go func() {
		_, forwardErr := io.Copy(client, upstream)

		if tcp, ok := client.(*net.TCPConn); ok {
			if err := tcp.CloseWrite(); err != nil && forwardErr == nil {
				forwardErr = err
			}
		}

		finished <- relayResult{direction: "server-to-client", err: forwardErr}
	}()

	first := <-finished

	if first.err != nil {
		// Stop the other relay direction after a transfer failure.
		client.Close()
		upstream.Close()
	}

	second := <-finished

	logRelayErrors(log.Default(), first.err, second.err)

	h.debugf(
		id,
		"tunnel closed after %s: %s=%v, %s=%v",
		time.Since(started).Round(time.Millisecond),
		first.direction,
		first.err,
		second.direction,
		second.err,
	)
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
