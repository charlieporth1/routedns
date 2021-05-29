package rdns

import (
	"context"
	"errors"
	"net"
	"strconv"
	"time"

	"github.com/miekg/dns"
)

// FastestTCP first resolves the query with the upstream resolver, then
// performs TCP connection tests with the response IPs to determine which
// IP responds the fastest. This IP is then returned in the response.
// This should be used in combination with a Cache to avoid the TCP
// connection overhead on every query.
type FastestTCP struct {
	id       string
	resolver Resolver
	opt      FastestTCPOptions
	port     string
}

var _ Resolver = &FastestTCP{}

// FastestTCPOptions contain settings for a resolver that filters responses
// based on TCP connection probes.
type FastestTCPOptions struct {
	// Port number to use for TCP probes, default 443
	Port int
}

// NewFastestTCP returns a new instance of a TCP probe resolver
func NewFastestTCP(id string, resolver Resolver, opt FastestTCPOptions) *FastestTCP {
	port := strconv.Itoa(opt.Port)
	if port == "0" {
		port = "443"
	}
	return &FastestTCP{
		id:       id,
		resolver: resolver,
		opt:      opt,
		port:     port,
	}
}

// Resolve a DNS query using a random resolver.
func (r *FastestTCP) Resolve(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
	log := logger(r.id, q, ci)
	a, err := r.resolver.Resolve(q, ci)
	if err != nil {
		return a, err
	}
	question := q.Question[0]

	// Don't need to do anything if the query wasn't for an IP
	if question.Qtype != dns.TypeA && question.Qtype != dns.TypeAAAA {
		return a, nil
	}

	// Extract the IP responses
	var ipRRs []dns.RR
	for _, rr := range a.Answer {
		if rr.Header().Rrtype == question.Qtype {
			ipRRs = append(ipRRs, rr)
		}
	}

	// If there's only one IP in the response, nothing to probe
	if len(ipRRs) < 2 {
		return a, nil
	}

	// Send TCP probes to all, if anything returns an error, just return
	// the original response rather than trying to be clever and pick one.
	log.Debugf("sending %d tcp probes", len(ipRRs))
	first, err := r.probe(ipRRs)
	if err != nil {
		log.WithError(err).Debug("tcp probe failed")
		return a, nil
	}

	a.Answer = []dns.RR{first}
	return a, nil
}

func (r *FastestTCP) String() string {
	return r.id
}

// Probes all IPs and returns the RR with the fastest responding IP.
func (r *FastestTCP) probe(rrs []dns.RR) (dns.RR, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	type result struct {
		rr  dns.RR
		err error
	}

	// Open up net.Dial for every IP in the set
	resultCh := make(chan result)
	for _, rr := range rrs {
		var d net.Dialer
		go func(rr dns.RR) {
			var (
				c   net.Conn
				err error
			)
			switch record := rr.(type) {
			case *dns.A:
				c, err = d.DialContext(ctx, "tcp4", net.JoinHostPort(record.A.String(), r.port))
			case *dns.AAAA:
				c, err = d.DialContext(ctx, "tcp6", net.JoinHostPort(record.AAAA.String(), r.port))
			default:
				err = errors.New("unexpected resource type")
			}
			if c != nil {
				c.Close()
			}
			resultCh <- result{rr: rr, err: err}
		}(rr)
	}

	// Wait for the first one that comes back. There's no logic here to
	// skip the first if it failed and the second one succeeded. Whatever
	// comes back first is returned.
	select {
	case res := <-resultCh:
		return res.rr, res.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
