package rdns

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/jtacoma/uritemplates"
	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/http3"
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/http2"
)

// DoHClientOptions contains options used by the DNS-over-HTTP resolver.
type DoHClientOptions struct {
	// Query method, either GET or POST. If empty, POST is used.
	Method string

	// Bootstrap address - IP to use for the service instead of looking up
	// the service's hostname with potentially plain DNS.
	BootstrapAddr string

	// Transport protocol to run HTTPS over. "quic" or "tcp", defaults to "tcp".
	Transport string

	// Local IP to use for outbound connections. If nil, a local address is chosen.
	LocalAddr net.IP

	TLSConfig *tls.Config
}

// DoHClient is a DNS-over-HTTP resolver with support fot HTTP/2.
type DoHClient struct {
	id       string
	endpoint string
	template *uritemplates.UriTemplate
	client   *http.Client
	opt      DoHClientOptions
	metrics  *ListenerMetrics
}

var _ Resolver = &DoHClient{}

func NewDoHClient(id, endpoint string, opt DoHClientOptions) (*DoHClient, error) {
	// Parse the URL template
	template, err := uritemplates.Parse(endpoint)
	if err != nil {
		return nil, err
	}

	var tr http.RoundTripper
	switch opt.Transport {
	case "tcp", "":
		tr, err = dohTcpTransport(opt)
	case "quic":
		tr, err = dohQuicTransport(opt)
	default:
		err = fmt.Errorf("unknown protocol: '%s'", opt.Transport)
	}
	if err != nil {
		return nil, err
	}

	client := &http.Client{
		Transport: tr,
	}

	if opt.Method == "" {
		opt.Method = "POST"
	}
	if opt.Method != "POST" && opt.Method != "GET" {
		return nil, fmt.Errorf("unsupported method '%s'", opt.Method)
	}

	return &DoHClient{
		id:       id,
		endpoint: endpoint,
		template: template,
		client:   client,
		opt:      opt,
		metrics:  NewListenerMetrics("client", id),
	}, nil
}

// Resolve a DNS query.
func (d *DoHClient) Resolve(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
	logger(d.id, q, ci).WithFields(logrus.Fields{
		"resolver": d.endpoint,
		"protocol": "doh",
		"method":   d.opt.Method,
	}).Debug("querying upstream resolver")

	// Add padding before sending the query over HTTPS
	padQuery(q)

	d.metrics.query.Add(1)
	switch d.opt.Method {
	case "POST":
		return d.ResolvePOST(q)
	case "GET":
		return d.ResolveGET(q)
	}
	return nil, errors.New("unsupported method")
}

// ResolvePOST resolves a DNS query via DNS-over-HTTP using the POST method.
func (d *DoHClient) ResolvePOST(q *dns.Msg) (*dns.Msg, error) {
	// Pack the DNS query into wire format
	b, err := q.Pack()
	if err != nil {
		d.metrics.err.Add("pack", 1)
		return nil, err
	}
	// The URL could be a template. Process it without values since POST doesn't use variables in the URL.
	u, err := d.template.Expand(map[string]interface{}{})
	if err != nil {
		d.metrics.err.Add("template", 1)
		return nil, err
	}
	req, err := http.NewRequest("POST", u, bytes.NewReader(b))
	if err != nil {
		d.metrics.err.Add("http", 1)
		return nil, err
	}
	req.Header.Add("accept", "application/dns-message")
	req.Header.Add("content-type", "application/dns-message")
	resp, err := d.client.Do(req)
	if err != nil {
		d.metrics.err.Add("post", 1)
		return nil, err
	}
	defer resp.Body.Close()
	return d.responseFromHTTP(resp)
}

// ResolveGET resolves a DNS query via DNS-over-HTTP using the GET method.
func (d *DoHClient) ResolveGET(q *dns.Msg) (*dns.Msg, error) {
	// Pack the DNS query into wire format
	b, err := q.Pack()
	if err != nil {
		d.metrics.err.Add("pack", 1)
		return nil, err
	}
	// Encode the query as base64url without padding
	b64 := base64.RawURLEncoding.EncodeToString(b)

	// The URL must be a template. Process it with the "dns" param containing the encoded query.
	u, err := d.template.Expand(map[string]interface{}{"dns": b64})
	if err != nil {
		d.metrics.err.Add("template", 1)
		return nil, err
	}
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		d.metrics.err.Add("http", 1)
		return nil, err
	}
	req.Header.Add("accept", "application/dns-message")
	resp, err := d.client.Do(req)
	if err != nil {
		d.metrics.err.Add("get", 1)
		return nil, err
	}
	defer resp.Body.Close()
	return d.responseFromHTTP(resp)
}

func (d *DoHClient) String() string {
	return d.id
}

// Check the HTTP response status code and parse out the response DNS message.
func (d *DoHClient) responseFromHTTP(resp *http.Response) (*dns.Msg, error) {
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		d.metrics.err.Add(fmt.Sprintf("http%d", resp.StatusCode), 1)
		return nil, fmt.Errorf("unexpected status code %d", resp.StatusCode)
	}
	rb, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		d.metrics.err.Add("read", 1)
		return nil, err
	}
	a := new(dns.Msg)
	err = a.Unpack(rb)
	if err != nil {
		d.metrics.err.Add("unpack", 1)
	} else {
		d.metrics.response.Add(rCode(a), 1)
	}
	return a, err
}

func dohTcpTransport(opt DoHClientOptions) (http.RoundTripper, error) {
	tr := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		TLSClientConfig:       opt.TLSConfig,
		DisableCompression:    true,
		ResponseHeaderTimeout: 10 * time.Second,
		IdleConnTimeout:       30 * time.Second,
	}
	// If we're using a custom tls.Config, HTTP2 isn't enabled by default in
	// the HTTP library. Turn it on for this transport.
	if tr.TLSClientConfig != nil {
		if err := http2.ConfigureTransport(tr); err != nil {
			return nil, err
		}
	}

	// Use a custom dialer if a bootstrap address or local address was provided
	if opt.BootstrapAddr != "" || opt.LocalAddr != nil {
		d := net.Dialer{LocalAddr: &net.TCPAddr{IP: opt.LocalAddr}}
		tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			if opt.BootstrapAddr != "" {
				_, port, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}
				addr = net.JoinHostPort(opt.BootstrapAddr, port)
			}
			return d.DialContext(ctx, network, addr)
		}
	}
	return tr, nil
}

func dohQuicTransport(opt DoHClientOptions) (http.RoundTripper, error) {
	tr := &http3.RoundTripper{
		TLSClientConfig: opt.TLSConfig,
		QuicConfig: &quic.Config{
			TokenStore: quic.NewLRUTokenStore(10, 10),
		},
		Dial: func(network, addr string, tlsConfig *tls.Config, config *quic.Config) (quic.EarlySession, error) {
			hostname, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			if opt.BootstrapAddr != "" {
				tlsConfig = tlsConfig.Clone()
				tlsConfig.ServerName = hostname
				addr = net.JoinHostPort(opt.BootstrapAddr, port)
			}
			return newQuicSession(hostname, addr, opt.LocalAddr, tlsConfig, config)
		},
	}
	return tr, nil
}

// QUIC session that automatically restarts when it's used after having timed out. Needed
// since the quic-go RoundTripper doesn't have any session management and timed out
// sessions aren't restarted. This one doesn't support Early sessions, and instead just
// uses a regular session.
type quicSession struct {
	quic.Session

	hostname  string
	rAddr     string
	lAddr     net.IP
	tlsConfig *tls.Config
	config    *quic.Config
	mu        sync.Mutex

	expiredContext context.Context
}

func newQuicSession(hostname, rAddr string, lAddr net.IP, tlsConfig *tls.Config, config *quic.Config) (quic.EarlySession, error) {
	session, err := quicDial(hostname, rAddr, lAddr, tlsConfig, config)
	if err != nil {
		return nil, err
	}
	expired, cancel := context.WithCancel(context.Background())
	cancel()

	return &quicSession{
		hostname:       hostname,
		rAddr:          rAddr,
		lAddr:          lAddr,
		tlsConfig:      tlsConfig,
		config:         config,
		Session:        session,
		expiredContext: expired,
	}, nil
}

func (s *quicSession) HandshakeComplete() context.Context {
	return s.expiredContext
}

func (s *quicSession) OpenStreamSync(ctx context.Context) (quic.Stream, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	stream, err := s.Session.OpenStreamSync(ctx)
	if err != nil {
		_ = s.Session.CloseWithError(quic.ErrorCode(DOQNoError), "")
		var session quic.Session
		session, err = quicDial(s.hostname, s.rAddr, s.lAddr, s.tlsConfig, s.config)
		if err != nil {
			return nil, err
		}
		s.Session = session
		stream, err = s.Session.OpenStreamSync(ctx)
	}
	return stream, err
}

func (s *quicSession) OpenStream() (quic.Stream, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	stream, err := s.Session.OpenStream()
	if err != nil {
		_ = s.Session.CloseWithError(quic.ErrorCode(DOQNoError), "")
		var session quic.Session
		session, err = quicDial(s.hostname, s.rAddr, s.lAddr, s.tlsConfig, s.config)
		if err != nil {
			return nil, err
		}
		s.Session = session
		stream, err = s.Session.OpenStream()
	}
	return stream, err
}

func (s *quicSession) NextSession() quic.Session {
	return nil
}

func quicDial(hostname, rAddr string, lAddr net.IP, tlsConfig *tls.Config, config *quic.Config) (quic.Session, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", rAddr)
	if err != nil {
		return nil, err
	}
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: lAddr, Port: 0})
	if err != nil {
		return nil, err
	}
	return quic.Dial(udpConn, udpAddr, hostname, tlsConfig, config)
}
