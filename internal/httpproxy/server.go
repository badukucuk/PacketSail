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
	"sync"
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

	// Protect active CONNECT tunnels against concurrent access.
	mu      sync.Mutex
	closing bool
	tunnels map[net.Conn]net.Conn
}

// Server owns a running HTTP CONNECT listener.
type Server struct {
	httpServer *http.Server
	handler    *handler
	address    string
	done       chan error
}

// Start creates the production HTTP CONNECT handler and listener.
func Start(address string, fragment bool, strategy tlsfrag.Strategy, debug bool) (*Server, error) {
	resolver := dns.NewResolver()
	dialer := &net.Dialer{Timeout: connectTimeout}

	h := newHandler(
		resolver.LookupIPv4,
		dialer.DialContext,
		fragment,
		strategy,
	)
	h.debug = debug

	return startWithHandler(address, h)
}

// startWithHandler starts a real TCP listener using the supplied handler.
// Tests can supply controlled DNS and connection behavior.
func startWithHandler(address string, h *handler) (*Server, error) {
	listener, err := net.Listen("tcp4", address)
	if err != nil {
		return nil, fmt.Errorf("listen for HTTP CONNECT proxy: %w", err)
	}

	httpServer := &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
	}

	server := &Server{
		httpServer: httpServer,
		handler:    h,
		address:    listener.Addr().String(),
		done:       make(chan error, 1),
	}

	go func() {
		err := httpServer.Serve(listener)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}

		server.done <- err
	}()

	log.Printf("HTTP CONNECT proxy listening on %s", listener.Addr())

	return server, nil
}

// Wait blocks until the HTTP server stops.
// It must be called only once per Server.
func (server *Server) Wait() error {
	if err := <-server.done; err != nil {
		return fmt.Errorf("serve HTTP CONNECT proxy: %w", err)
	}

	return nil
}

// Shutdown closes active CONNECT tunnels and stops the HTTP listener.
func (server *Server) Shutdown(ctx context.Context) error {
	// Hijacked connections are not closed by http.Server.Shutdown.
	// Close them explicitly before stopping the HTTP server.
	server.handler.closeTunnels()

	if err := server.httpServer.Shutdown(ctx); err != nil {
		return fmt.Errorf("shut down HTTP CONNECT proxy: %w", err)
	}

	return nil
}

// ListenAndServe preserves the existing blocking API.
func ListenAndServe(address string, fragment bool, strategy tlsfrag.Strategy, debug bool) error {
	server, err := Start(address, fragment, strategy, debug)
	if err != nil {
		return err
	}

	return server.Wait()
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

// registerTunnel tracks both ends of a CONNECT tunnel.
// New tunnels are rejected once shutdown has started.
func (h *handler) registerTunnel(client, upstream net.Conn) bool {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.closing {
		return false
	}

	if h.tunnels == nil {
		h.tunnels = make(map[net.Conn]net.Conn)
	}

	h.tunnels[client] = upstream
	return true
}

// unregisterTunnel removes a tunnel after its relay has finished.
func (h *handler) unregisterTunnel(client net.Conn) {
	h.mu.Lock()
	defer h.mu.Unlock()

	delete(h.tunnels, client)
}

// closeTunnels stops new tunnel registration and closes both connections of every currently tracked tunnel.
func (h *handler) closeTunnels() {
	h.mu.Lock()

	h.closing = true

	type tunnel struct {
		client   net.Conn
		upstream net.Conn
	}

	active := make([]tunnel, 0, len(h.tunnels))

	for client, upstream := range h.tunnels {
		active = append(active, tunnel{
			client:   client,
			upstream: upstream,
		})
	}

	h.mu.Unlock()

	// Never hold the mutex while closing network connections.
	for _, connection := range active {
		connection.client.Close()
		connection.upstream.Close()
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

	// Track the tunnel before sending the successful CONNECT response.
	// If shutdown has begun, both connections are closed by their defers.
	if !h.registerTunnel(client, upstream) {
		return
	}
	defer h.unregisterTunnel(client)

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

	h.mu.Lock()
	shuttingDown := h.closing
	h.mu.Unlock()

	// Closing tracked tunnels interrupts active TCP reads and writes.
	// These errors are expected during an intentional shutdown.
	first.err = filterShutdownRelayError(first.err, shuttingDown)
	second.err = filterShutdownRelayError(second.err, shuttingDown)

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

// filterShutdownRelayError suppresses connection errors caused by intentionally closing active tunnels during server shutdown.
func filterShutdownRelayError(err error, shuttingDown bool) error {
	if err == nil || !shuttingDown {
		return err
	}

	if errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe) {
		return nil
	}

	return err
}
