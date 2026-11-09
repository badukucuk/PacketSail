package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/badukucuk/PacketSail/internal/httpproxy"
	"github.com/badukucuk/PacketSail/internal/socks5"
	"github.com/badukucuk/PacketSail/internal/tlsfrag"
)

const version = "v0.1.0"

func main() {
	showVersion := flag.Bool("version", false, "Print version information")
	proxy := flag.Bool("proxy", false, "Start the local SOCKS5 proxy")
	httpProxy := flag.Bool("http-proxy", false, "Start the local HTTP CONNECT proxy")
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
		os.Exit(2)
	}

	if *fragment && !*proxy && !*httpProxy {
		fmt.Fprintln(os.Stderr, "Error: --fragment requires --proxy or --http-proxy")
		os.Exit(2)
	}

	strategy := tlsfrag.Strategy(*fragmentStrategy)

	switch strategy {
	case tlsfrag.StrategySNIMidpoint, tlsfrag.StrategyBeforeSNI, tlsfrag.StrategyDualSplit:
	default:
		fmt.Fprintf(
			os.Stderr,
			"Error: unsupported fragmentation strategy: %q\n",
			*fragmentStrategy,
		)
		fmt.Fprintln(
			os.Stderr,
			"Supported strategies: sni-midpoint, before-sni, dual-split",
		)
		os.Exit(2)
	}

	strategySpecified := false

	flag.Visit(func(f *flag.Flag) {
		if f.Name == "fragment-strategy" {
			strategySpecified = true
		}
	})

	if strategySpecified && !*fragment {
		fmt.Fprintln(
			os.Stderr,
			"Error: --fragment-strategy requires --fragment",
		)
		os.Exit(2)
	}

	if *showVersion {
		fmt.Println("PacketSail", version)
		return
	}

	if !*proxy && !*httpProxy {
		flag.Usage()
		return
	}

	// Each proxy runs independently so both listeners can be active.
	// Any listener failure terminates the application with an error.
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
		go func() {
			errors <- httpproxy.ListenAndServe(
				"127.0.0.1:9877",
				*fragment,
				strategy,
				*debug,
			)
		}()
	}

	// A proxy listener should not stop during normal operation.
	if err := <-errors; err != nil {
		fmt.Fprintf(os.Stderr, "Error: proxy server stopped: %v\n", err)
	} else {
		fmt.Fprintln(os.Stderr, "Error: proxy server stopped unexpectedly")
	}

	os.Exit(1)
}
