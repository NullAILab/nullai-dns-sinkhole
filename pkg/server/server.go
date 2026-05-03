// Package server implements a DNS sinkhole server using miekg/dns.
//
// Incoming queries are checked against the Blocker; blocked domains get an
// NXDOMAIN response (or a 0.0.0.0 A record depending on --sinkhole-ip).
// Allowed queries are forwarded to the configured upstream resolver.
package server

import (
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"

	"github.com/NullAILab/nullai-dns-sinkhole/pkg/blocker"
)

// QueryResult represents the outcome of a single DNS query.
type QueryResult struct {
	Domain   string
	Blocked  bool
	Upstream string
	Latency  time.Duration
}

// Handler is the dns.Handler implementation for the sinkhole.
type Handler struct {
	Blocker    *blocker.Blocker
	Upstream   string        // e.g. "1.1.1.1:53"
	SinkholeIP net.IP        // IP returned for blocked domains (default: 0.0.0.0)
	Timeout    time.Duration // upstream query timeout
	OnQuery    func(QueryResult)
}

// NewHandler returns a Handler with sensible defaults.
func NewHandler(b *blocker.Blocker, upstream string) *Handler {
	return &Handler{
		Blocker:    b,
		Upstream:   upstream,
		SinkholeIP: net.IPv4zero,
		Timeout:    3 * time.Second,
		OnQuery:    func(QueryResult) {},
	}
}

// ServeDNS implements dns.Handler.
func (h *Handler) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	if len(req.Question) == 0 {
		dns.HandleFailed(w, req)
		return
	}

	q := req.Question[0]
	domain := dns.Fqdn(q.Name)
	bare := q.Name

	start := time.Now()

	if h.Blocker.IsBlocked(bare) {
		h.sinkhole(w, req, q, bare)
		h.OnQuery(QueryResult{Domain: bare, Blocked: true, Latency: time.Since(start)})
		return
	}

	resp, err := h.forward(req)
	latency := time.Since(start)
	if err != nil || resp == nil {
		dns.HandleFailed(w, req)
		h.OnQuery(QueryResult{Domain: bare, Blocked: false, Upstream: h.Upstream, Latency: latency})
		return
	}
	resp.SetReply(req)
	_ = w.WriteMsg(resp)
	_ = domain // used implicitly via Fqdn
	h.OnQuery(QueryResult{Domain: bare, Blocked: false, Upstream: h.Upstream, Latency: latency})
}

// sinkhole sends an NXDOMAIN (or 0.0.0.0 A record) for blocked domains.
func (h *Handler) sinkhole(w dns.ResponseWriter, req *dns.Msg, q dns.Question, domain string) {
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.RecursionAvailable = true

	if q.Qtype == dns.TypeA {
		// Return 0.0.0.0 — client's connection attempt fails immediately
		rr := &dns.A{
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    60,
			},
			A: h.SinkholeIP,
		}
		resp.Answer = append(resp.Answer, rr)
	} else {
		// For non-A queries, return NXDOMAIN
		resp.SetRcode(req, dns.RcodeNameError)
	}
	_ = w.WriteMsg(resp)
}

// forward proxies a query to the upstream resolver.
func (h *Handler) forward(req *dns.Msg) (*dns.Msg, error) {
	c := &dns.Client{Timeout: h.Timeout}
	resp, _, err := c.Exchange(req, h.Upstream)
	return resp, err
}

// Server wraps the miekg/dns server for UDP and TCP.
type Server struct {
	Addr    string
	Handler *Handler
	udp     *dns.Server
	tcp     *dns.Server
}

// NewServer returns a Server bound to addr (e.g. ":5353").
func NewServer(addr string, handler *Handler) *Server {
	return &Server{Addr: addr, Handler: handler}
}

// Start launches UDP and TCP DNS servers on s.Addr.
func (s *Server) Start() error {
	s.udp = &dns.Server{Addr: s.Addr, Net: "udp", Handler: s.Handler}
	s.tcp = &dns.Server{Addr: s.Addr, Net: "tcp", Handler: s.Handler}

	errCh := make(chan error, 2)
	go func() { errCh <- s.udp.ListenAndServe() }()
	go func() { errCh <- s.tcp.ListenAndServe() }()

	// Give servers a moment to bind; surface any immediate bind error.
	select {
	case err := <-errCh:
		return fmt.Errorf("dns server failed to start: %w", err)
	case <-time.After(50 * time.Millisecond):
		return nil
	}
}

// Shutdown gracefully stops both servers.
func (s *Server) Shutdown() {
	if s.udp != nil {
		_ = s.udp.Shutdown()
	}
	if s.tcp != nil {
		_ = s.tcp.Shutdown()
	}
}
