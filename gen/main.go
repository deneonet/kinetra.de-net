package main

import (
	"flag"
	"fmt"

	"kinetra.de/net/cert"
)

func main() {
	version := flag.Int("v", 0x01, "Certificate And Root Key version")
	flag.Parse()

	fmt.Printf("Generating for version: %d\n", *version)

	if err := cert.GenerateCertificateChain(*version, "s.cert", "root.key"); err != nil {
		panic(err)
	}
}
