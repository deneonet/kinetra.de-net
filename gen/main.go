package main

import (
	"flag"
	"fmt"

	"github.com/deneonet/knet/cert"
)

func main() {
	version := flag.Int("v", 0x01, "Server certificate and client root key version.")
	flag.Parse()

	fmt.Printf("Generating for version: %d\n", *version)

	if err := cert.GenerateCertificateChain(*version, "server.kc", "client.kr"); err != nil {
		panic(err)
	}
}
