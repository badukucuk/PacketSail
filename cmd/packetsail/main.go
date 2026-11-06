package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/badukucuk/PacketSail/internal/socks5"
)

func main() {
	version := flag.Bool("version", false, "Print version information")
	proxy := flag.Bool("proxy", false, "Start the local SOCKS5 proxy")

	flag.Parse()

	if args := flag.Args(); len(args) > 0 {
		fmt.Fprintf(os.Stderr, "Error: unexpected argument(s): %q\n", args)
		fmt.Fprintln(os.Stderr, "Run 'packetsail --help' for usage information.")
		os.Exit(2)
	}

	if *version {
		fmt.Println("PacketSail dev")
		return
	}

	if *proxy {
		if err := socks5.ListenAndServe("127.0.0.1:9876"); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	flag.Usage()
}
