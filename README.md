# DNS Sinkhole

Malware relies on DNS to find its C2 servers.  Block the DNS query and the
malware can't beacon, can't receive commands, and can't exfiltrate data —
regardless of what firewall rules are in place.  This Go DNS server loads
standard hosts-format blocklists, returns `0.0.0.0` for any blocked domain,
and forwards all other queries to an upstream resolver.  Add it as your
network's DNS server to stop malware domains at the DNS layer.

> **Language:** Go 1.21+ &nbsp;|&nbsp; **Library:** miekg/dns &nbsp;|&nbsp; **Platform:** Linux / macOS / Windows

---

## Who This Is For

| Audience | Use case |
|----------|----------|
| **Network administrators** | Block malware and ad domains for an entire network |
| **Homelab operators** | Run a Pi-hole-style sinkhole without third-party software |
| **Students** | Learn DNS protocol internals by building a resolver |
| **Security engineers** | Integrate DNS-level blocking into a defence-in-depth strategy |

---

## Project Structure

```
21-dns-sinkhole/
├── LICENSE
├── README.md
├── .gitignore
├── go.mod / go.sum
├── main.go                      ← CLI entry point
├── pkg/
│   ├── blocker/
│   │   ├── blocker.go           ← In-memory blocklist (thread-safe)
│   │   └── blocker_test.go      ← 18 unit tests
│   └── server/
│       └── server.go            ← DNS handler + UDP/TCP server
├── blocklists/
│   └── malware.txt              ← Sample blocklist (replace with real feeds)
└── docs/
    └── NOTES.md
```

---

## Setup

```bash
git clone https://github.com/NullAILab/nullai-dns-sinkhole.git
cd nullai-dns-sinkhole
go build -o dns-sinkhole .
```

---

## Usage

### Start on a test port (no root needed)

```bash
./dns-sinkhole --port 5353 --upstream 1.1.1.1:53 --blocklists blocklists/
```

### Test with dig

```bash
# Should resolve normally
dig google.com @127.0.0.1 -p 5353

# Should return 0.0.0.0 (blocked)
dig malware-c2-example.ru @127.0.0.1 -p 5353
```

### Start as system DNS (port 53, requires root)

```bash
sudo ./dns-sinkhole --port 53 --upstream 1.1.1.1:53
```

### Block or allow a single domain at runtime

```bash
./dns-sinkhole --block ads.tracking-company.net
./dns-sinkhole --allow safe-cdn.example.com
```

### Verbose query logging

```bash
./dns-sinkhole --port 5353 -v
```

---

## Example Output

```
[*] Loaded 10 blocked domains from blocklists
[*] DNS Sinkhole 1.0.0 — NullAI Lab
[*] Listening on :5353 | Upstream: 1.1.1.1:53 | Blocked domains: 10
[BLOCK] malware-c2-example.ru.
[BLOCK] botnet-beacon.example.net.
```

---

## How It Works

### Query flow

```
Client DNS query
      ↓
Sinkhole: IsBlocked(domain)?
      │
    YES → Return 0.0.0.0 A record (or NXDOMAIN for non-A queries)
      │    Client connection to 0.0.0.0 fails immediately
      │
    NO  → Forward to upstream (1.1.1.1:53)
           ↓
           Return real IP to client
```

### Blocklist format

Standard Pi-hole / hosts format is supported:

```
0.0.0.0 malware.example.com
127.0.0.1 tracker.example.com
bare-domain.example.com
# comment lines ignored
```

---

## Recommended Real Blocklists

| Source | Focus | URL |
|--------|-------|-----|
| StevenBlack/hosts | Ads + malware | github.com/StevenBlack/hosts |
| URLhaus | Live malware | urlhaus.abuse.ch/downloads/hostfile/ |
| Feodo Tracker | Botnet C2 | feodotracker.abuse.ch |
| OISD | All categories | oisd.nl |

---

## Running the Tests

```bash
go test ./pkg/... -v
```

Expected: **18 tests passed** (blocker package).

---

## Learning Objectives

- [ ] How DNS queries work at the packet level (UDP/TCP)
- [ ] How Pi-hole and DNS sinkholes intercept and block queries
- [ ] How malware uses DNS for C2 and exfiltration
- [ ] How to write concurrent Go network servers
- [ ] DNS response codes: NXDOMAIN, SERVFAIL, NOERROR
- [ ] Network-level defence vs endpoint-level defence

---

## References

- [RFC 1035 — DNS Protocol](https://tools.ietf.org/html/rfc1035)
- [miekg/dns library](https://github.com/miekg/dns)
- [Pi-hole project](https://pi-hole.net/)
- [MITRE ATT&CK T1071.004 — DNS](https://attack.mitre.org/techniques/T1071/004/)

---

## License

MIT — see [LICENSE](LICENSE).

---

*NullAI Lab — DNS Sinkhole*
