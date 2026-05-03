// Package blocker provides an in-memory domain blocklist.
//
// Domains are stored in a hash map (exact match only; subdomain blocking is
// handled by the caller normalising the query to strip a leading dot).
// A separate allow-list overrides the block-list so operators can whitelist
// legitimate domains caught by an overly broad blocklist.
package blocker

import (
	"bufio"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Blocker holds an in-memory block/allow list and provides thread-safe lookups.
type Blocker struct {
	mu      sync.RWMutex
	blocked map[string]bool
	allowed map[string]bool
}

// New returns an empty, ready-to-use Blocker.
func New() *Blocker {
	return &Blocker{
		blocked: make(map[string]bool),
		allowed: make(map[string]bool),
	}
}

// ─── Mutation ──────────────────────────────────────────────────────────────

// Block adds domain to the blocklist.
func (b *Blocker) Block(domain string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.blocked[normalise(domain)] = true
}

// Unblock removes domain from the blocklist.
func (b *Blocker) Unblock(domain string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.blocked, normalise(domain))
}

// Allow adds domain to the allow-list, overriding any block entry.
func (b *Blocker) Allow(domain string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.allowed[normalise(domain)] = true
}

// ─── Query ────────────────────────────────────────────────────────────────

// IsBlocked reports whether domain is blocked (and not explicitly allowed).
func (b *Blocker) IsBlocked(domain string) bool {
	d := normalise(domain)
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.allowed[d] {
		return false
	}
	return b.blocked[d]
}

// BlockCount returns the number of entries in the blocklist.
func (b *Blocker) BlockCount() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.blocked)
}

// AllowCount returns the number of entries in the allow-list.
func (b *Blocker) AllowCount() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.allowed)
}

// ─── Loading ─────────────────────────────────────────────────────────────

// LoadReader parses a hosts-format stream and adds every blocked domain.
// Returns the number of domains added.
//
// Supported formats:
//
//	0.0.0.0 malware.example.com
//	127.0.0.1 ads.example.com
//	# comment line
//	malware.example.com             (bare domain, no IP prefix)
func (b *Blocker) LoadReader(r io.Reader) int {
	var added int
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		var domain string
		switch len(fields) {
		case 1:
			domain = fields[0]
		case 2:
			// "0.0.0.0 domain" or "127.0.0.1 domain"
			domain = fields[1]
		default:
			continue
		}
		norm := normalise(domain)
		if norm == "" || norm == "localhost" {
			continue
		}
		b.mu.Lock()
		b.blocked[norm] = true
		b.mu.Unlock()
		added++
	}
	return added
}

// LoadFile opens path and calls LoadReader.
func (b *Blocker) LoadFile(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	return b.LoadReader(f), nil
}

// LoadDir loads every file in dir that has no extension or a .txt extension.
func (b *Blocker) LoadDir(dir string) (int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, err
	}
	var total int
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		ext := filepath.Ext(e.Name())
		if ext != "" && ext != ".txt" {
			continue
		}
		n, err := b.LoadFile(filepath.Join(dir, e.Name()))
		if err == nil {
			total += n
		}
	}
	return total, nil
}

// ─── Internal ─────────────────────────────────────────────────────────────

// normalise lower-cases and strips a trailing dot (FQDN form).
func normalise(domain string) string {
	d := strings.ToLower(strings.TrimSpace(domain))
	return strings.TrimSuffix(d, ".")
}
