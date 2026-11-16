package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/badukucuk/PacketSail/internal/httpproxy"
	"github.com/badukucuk/PacketSail/internal/instance"
	"github.com/badukucuk/PacketSail/internal/macosproxy"
	"github.com/badukucuk/PacketSail/internal/socks5"
	"github.com/badukucuk/PacketSail/internal/tlsfrag"
)

const version = "v0.1.0"

func main() {
	os.Exit(run())
}

func run() (exitCode int) {
	showVersion := flag.Bool("version", false, "Print version information")
	proxy := flag.Bool("proxy", false, "Start the local SOCKS5 proxy")
	httpProxy := flag.Bool("http-proxy", false, "Start the local HTTP CONNECT proxy")
	recoverProxy := flag.Bool("recover-proxy", false, "Restore macOS HTTPS proxy settings from a previous PacketSail backup")
	noAutoProxy := flag.Bool("no-auto-proxy", false, "Do not automatically configure the macOS HTTPS system proxy")
	fragment := flag.Bool("fragment", false, "Enable experimental TLS ClientHello fragmentation")
	debug := flag.Bool("debug", false, "Log HTTP CONNECT connection diagnostics")

	fragmentStrategy := flag.String(
		"fragment-strategy",
		string(tlsfrag.StrategySNIMidpoint),
		"TLS fragmentation strategy: sni-midpoint, before-sni, or dual-split",
	)

	flag.Parse()

	if args := flag.Args(); len(args) > 0 {
		fmt.Fprintf(os.Stderr, "Error: unexpected argument(s): %q\n", args)
		fmt.Fprintln(os.Stderr, "Run 'packetsail --help' for usage information.")
		return 2
	}

	if *fragment && !*proxy && !*httpProxy {
		fmt.Fprintln(os.Stderr, "Error: --fragment requires --proxy or --http-proxy")
		return 2
	}

	strategy := tlsfrag.Strategy(*fragmentStrategy)

	switch strategy {
	case tlsfrag.StrategySNIMidpoint, tlsfrag.StrategyBeforeSNI, tlsfrag.StrategyDualSplit:
	default:
		fmt.Fprintf(os.Stderr, "Error: unsupported fragmentation strategy: %q\n", *fragmentStrategy)
		fmt.Fprintln(os.Stderr, "Supported strategies: sni-midpoint, before-sni, dual-split")
		return 2
	}

	strategySpecified := false

	flag.Visit(func(f *flag.Flag) {
		if f.Name == "fragment-strategy" {
			strategySpecified = true
		}
	})

	if strategySpecified && !*fragment {
		fmt.Fprintln(os.Stderr, "Error: --fragment-strategy requires --fragment")
		return 2
	}

	if *showVersion {
		fmt.Println("PacketSail", version)
		return 0
	}

	if !*proxy && !*httpProxy && !*recoverProxy {
		flag.Usage()
		return 0
	}

	if *noAutoProxy && !*httpProxy {
		fmt.Fprintln(os.Stderr, "Error: --no-auto-proxy requires --http-proxy")
		return 2
	}

	if *recoverProxy &&
		(*proxy || *httpProxy || *fragment || *debug ||
			strategySpecified || *noAutoProxy) {
		fmt.Fprintln(os.Stderr, "Error: --recover-proxy cannot be combined with proxy server options")
		return 2
	}

	// Hold the application-wide lock before starting any proxy listener.
	lock, err := instance.Acquire()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: cannot start PacketSail: %v\n", err)
		return 1
	}

	// Release the lock on every normal return path, including errors.
	defer func() {
		if err := lock.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: release PacketSail lock: %v\n", err)
			exitCode = 1
		}
	}()

	// Recover previous HTTPS proxy settings without starting a proxy server.
	if *recoverProxy {
		if err := macosproxy.Recover(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: recover macOS HTTPS proxy settings: %v\n", err)
			return 1
		}

		fmt.Println("macOS HTTPS proxy settings restored successfully.")
		return 0
	}

	// Cancel the context when PacketSail receives a shutdown signal.
	ctx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()

	// Each enabled proxy runs in its own goroutine.
	errors := make(chan error, 2)

	if *proxy {
		go func() {
			errors <- socks5.ListenAndServe(
				"127.0.0.1:9876",
				*fragment,
				strategy,
			)
		}()
	}

	if *httpProxy {
		// The listener must be ready before changing system proxy settings.
		httpServer, err := httpproxy.Start(
			"127.0.0.1:9877",
			*fragment,
			strategy,
			*debug,
		)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: start HTTP CONNECT proxy: %v\n", err)
			return 1
		}

		// Registered first so HTTP shutdown runs after HTTPS proxy restoration.
		defer func() {
			shutdownCtx, cancel := context.WithTimeout(
				context.Background(),
				5*time.Second,
			)
			defer cancel()

			if err := httpServer.Shutdown(shutdownCtx); err != nil {
				fmt.Fprintf(os.Stderr, "Error: stop HTTP CONNECT proxy: %v\n", err)
				exitCode = 1
			}
		}()

		go func() {
			errors <- httpServer.Wait()
		}()

		if !*noAutoProxy {
			session, err := macosproxy.Start()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: automatically configure macOS HTTPS proxy: %v\n", err)
				fmt.Fprintln(os.Stderr, "Check the macOS HTTPS proxy settings if connectivity is affected.")
				fmt.Fprintln(os.Stderr, "If a recovery backup remains, stop PacketSail and run --recover-proxy.")
				fmt.Fprintln(os.Stderr, "Use --no-auto-proxy only when you intend to manage the system proxy manually.")
				return 1
			}

			// Go executes defers in reverse order. Restore system settings
			// while the HTTP CONNECT listener is still available.
			defer func() {
				if err := session.Stop(); err != nil {
					fmt.Fprintf(os.Stderr, "Error: restore macOS HTTPS proxy: %v\n", err)

					exitCode = 1
				}
			}()
		}

	}

	select {
	case <-ctx.Done():
		fmt.Println("\nPacketSail shutting down...")
		return 0

	case err := <-errors:
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: proxy server stopped: %v\n", err)
		} else {
			fmt.Fprintln(os.Stderr, "Error: proxy server stopped unexpectedly")
		}
		return 1
	}
}
