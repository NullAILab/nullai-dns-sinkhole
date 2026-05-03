# Architecture Notes — DNS Sinkhole

## Why miekg/dns

The Go stdlib `net` package provides only a resolver client, not a server.
`miekg/dns` is the standard Go DNS library used by CoreDNS, k8s-dns, and
many production tools.  It handles the wire protocol, message parsing,
and connection management.

## Blocker package — no miekg dependency

`pkg/blocker` has zero external dependencies.  Its tests run without any
DNS infrastructure.  This isolation keeps the core business logic (blocklist
management) testable on any platform.

## Exact-match only

The blocker uses exact domain matching.  A block of `evil.com` does NOT
automatically block `sub.evil.com`.  This is intentional:
- Wildcard matching requires more complex data structures (trie)
- False positives from wildcard blocks are difficult to diagnose
- Operators can add specific subdomains to the blocklist explicitly

A future extension could add a `WildcardBlock(domain)` method that walks
the label hierarchy during lookup.

## 0.0.0.0 vs NXDOMAIN

For blocked A queries, the sinkhole returns `0.0.0.0` rather than NXDOMAIN.
- NXDOMAIN: client stops trying but may log a DNS error that confuses users
- 0.0.0.0: client attempts a TCP connection to 0.0.0.0, which fails at
  connect() immediately — clean failure with no user-visible error in many apps

For non-A queries (AAAA, MX, TXT) on blocked domains, NXDOMAIN is returned
since there is no equivalent null IP for other record types.

## Thread safety

`Blocker` uses a `sync.RWMutex`.  `RLock` allows concurrent readers; `Lock`
is taken only for writes (`Block`, `Allow`, `Unblock`, `LoadReader`).  In a
production sinkhole, reads (lookups) vastly outnumber writes (list updates),
so RWMutex is more efficient than a plain Mutex.

## Server goroutine model

`Start()` launches two goroutines (UDP + TCP) and waits 50 ms for them to
bind.  If either goroutine fails within that window (e.g. port in use), the
error is returned immediately.  After 50 ms, the function returns nil and the
goroutines run independently until `Shutdown()` is called.

## go.sum commitment

`go.sum` is committed alongside `go.mod` to ensure reproducible builds.
The `miekg/dns` library is widely used and its hash is verifiable via the
Go module proxy.
