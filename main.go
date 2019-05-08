package main

import (
	"crypto/x509"
	"encoding/pem"
	"flag"
	"io/ioutil"
	"log"
)

func main() {
	log.SetFlags(0)

	flag.Parse()

	if flag.NArg() < 2 {
		flag.Usage()
		log.Printf("    verify-certificate SERVER_NAME CERT.pem ROOTS.pem")
		log.Fatalf("\nERROR You MUST pass at least the SERVER_NAME CERT.pem positional arguments")
	}

	serverName := flag.Arg(0)

	certPEM, err := ioutil.ReadFile(flag.Arg(1))
	if err != nil {
		log.Fatalf("failed to read certificate %s: %v", flag.Arg(1), err)
	}
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		log.Fatalf("failed to parse certificate PEM from %s", flag.Arg(1))
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatalf("failed to parse certificate from %s: %v", flag.Arg(1), err)
	}

	roots := x509.NewCertPool()
	if flag.NArg() > 2 {
		rootsPEM, err := ioutil.ReadFile(flag.Arg(2))
		if err != nil {
			log.Fatalf("failed to read roots %s: %v", flag.Arg(2), err)
		}
		ok := roots.AppendCertsFromPEM([]byte(rootsPEM))
		if !ok {
			log.Fatalf("failed to parse roots certificate")
		}
	} else {
		roots = nil
	}

	opts := x509.VerifyOptions{
		DNSName: serverName,
		Roots:   roots,
	}

	chains, err := cert.Verify(opts)
	if err != nil {
		log.Fatalf("failed to verify certificate: %v", err)
	}

	log.Printf("verification succeeded")

	for i, chain := range chains {
		for _, certificate := range chain {
			log.Printf("Chain=%d Subject=%s", i, certificate.Subject)
		}
	}
}
