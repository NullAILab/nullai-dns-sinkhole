// dns-sinkhole — Self-hosted DNS sinkhole that blocks malware domains.
//
// Usage:
//
//	./dns-sinkhole [flags]
//
// Flags:
//
//	--port        DNS listen port (default: 5353; use 53 for system DNS, requires root)
//	--upstream    Upstream resolver (default: 1.1.1.1:53)
//	--blocklists  Directory of hosts-format blocklist files (default: ./blocklists)
//	--block       Block a single domain and exit
//	--allow       Allow a single domain and exit
//	--version     Print version and exit
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/NullAILab/nullai-dns-sinkhole/pkg/blocker"
	"github.com/NullAILab/nullai-dns-sinkhole/pkg/server"
)

const version = "1.0.0"

func main() {
	var (
		port       = flag.Int("port", 5353, "DNS listen port")
		upstream   = flag.String("upstream", "1.1.1.1:53", "Upstream DNS resolver")
		blockDir   = flag.String("blocklists", "blocklists", "Directory of blocklist files")
		blockDomain = flag.String("block", "", "Block a single domain")
		allowDomain = flag.String("allow", "", "Allow a single domain")
		ver        = flag.Bool("version", false, "Print version and exit")
		verbose    = flag.Bool("v", false, "Verbose query logging")
	)
	flag.Parse()

	if *ver {
		fmt.Printf("dns-sinkhole %s — NullAI Lab\n", version)
		os.Exit(0)
	}

	b := blocker.New()

	// Load blocklists from directory
	if _, err := os.Stat(*blockDir); err == nil {
		n, err := b.LoadDir(*blockDir)
		if err != nil {
			log.Printf("[WARN] Could not load blocklists from %s: %v", *blockDir, err)
		} else {
			log.Printf("[*] Loaded %d blocked domains from %s", n, *blockDir)
		}
	}

	// One-shot CLI operations
	if *blockDomain != "" {
		b.Block(*blockDomain)
		log.Printf("[+] Blocked: %s", *blockDomain)
	}
	if *allowDomain != "" {
		b.Allow(*allowDomain)
		log.Printf("[+] Allowed: %s", *allowDomain)
	}

	addr := fmt.Sprintf(":%d", *port)
	h := server.NewHandler(b, *upstream)

	if *verbose {
		h.OnQuery = func(r server.QueryResult) {
			status := "ALLOW"
			if r.Blocked {
				status = "BLOCK"
			}
			log.Printf("[%s] %s (%.2fms)", status, r.Domain, float64(r.Latency.Microseconds())/1000)
		}
	} else {
		h.OnQuery = func(r server.QueryResult) {
			if r.Blocked {
				log.Printf("[BLOCK] %s", r.Domain)
			}
		}
	}

	s := server.NewServer(addr, h)
	if err := s.Start(); err != nil {
		log.Fatalf("[!] Failed to start DNS server: %v", err)
	}

	log.Printf("[*] DNS Sinkhole %s — NullAI Lab", version)
	log.Printf("[*] Listening on %s | Upstream: %s | Blocked domains: %d",
		addr, *upstream, b.BlockCount())
	log.Printf("[*] Press Ctrl+C to stop")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Printf("[*] Shutting down...")
	s.Shutdown()
}
