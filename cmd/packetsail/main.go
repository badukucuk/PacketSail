package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	version := flag.Bool("version", false, "Print version information")

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

	flag.Usage()
}
