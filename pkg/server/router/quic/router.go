package quic

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/traefik/traefik/v2/pkg/log"
	quicmuxer "github.com/traefik/traefik/v2/pkg/muxer/quic"
	"github.com/traefik/traefik/v2/pkg/quic"
)

const defaultBufSize = 4096

type Router struct {
	muxerHTTPS quicmuxer.Muxer

	// Forwarder handlers.
	// httpForwarder handles all HTTP requests.
	httpForwarder quic.Handler
	// httpsForwarder handles (indirectly through muxerHTTPS, or directly) all HTTPS requests.
	httpsForwarder quic.Handler

	// Neither is used directly, but they are held here, and recreated on config reload,
	// so that they can be passed to the Switcher at the end of the config reload phase.
	httpHandler  http.Handler
	httpsHandler http.Handler

	// TLS configs.
	httpsTLSConfig *tls.Config // default TLS config
	// hostHTTPTLSConfig contains TLS configs keyed by SNI.
	// A nil config is the hint to set up a brokenTLSRouter.
	hostHTTPTLSConfig map[string]*tls.Config // TLS configs keyed by SNI
}

func NewRouter() (*Router, error) {
	muxHTTPS, err := quicmuxer.NewMuxer()
	if err != nil {
		return nil, err
	}

	return &Router{
		muxerHTTPS: *muxHTTPS,
	}, nil
}

// GetTLSGetClientInfo is called after a ClientHello is received from a client.
func (r *Router) GetTLSGetClientInfo() func(info *tls.ClientHelloInfo) (*tls.Config, error) {
	return func(info *tls.ClientHelloInfo) (*tls.Config, error) {
		log.Debug(info.ServerName)
		if tlsConfig, ok := r.hostHTTPTLSConfig[info.ServerName]; ok {
			return tlsConfig, nil
		}

		return r.httpsTLSConfig, nil
	}
}

func (r *Router) ServeQUIC(conn net.Conn) {
	br := bufio.NewReader(conn)
	hello, err := clientHelloInfo(br)
	if err != nil {
		conn.Close()
		return
	}

	// Remove read/write deadline and delegate this to underlying tcp server
	err = conn.SetReadDeadline(time.Time{})
	if err != nil {
		log.WithoutContext().Errorf("Error while setting read deadline: %v", err)
	}

	err = conn.SetWriteDeadline(time.Time{})
	if err != nil {
		log.WithoutContext().Errorf("Error while setting write deadline: %v", err)
	}

	connData, err := quicmuxer.NewConnData(hello.serverName, conn, hello.protos)
	if err != nil {
		log.WithoutContext().Errorf("Error while reading QUIC connection data: %v", err)
		conn.Close()
		return
	}

	if !hello.isTLS {
		switch {
		case r.httpForwarder != nil:
			r.httpForwarder.ServeQUIC(getPeekedConn(conn, hello.peeked))
		default:
			conn.Close()
		}
		return
	}

	// For real, the handler eventually used for HTTPS is (almost) always the same:
	// it is the httpsForwarder that is used for all HTTPS connections that match
	// (which is also incidentally the same used in the last block below for 404s).
	// The added value from doing Match is to find and use the specific TLS config
	// (wrapped inside the returned handler) requested for the given HostSNI.
	handlerHTTPS, catchAllHTTPS := r.muxerHTTPS.Match(connData)
	if handlerHTTPS != nil && !catchAllHTTPS {
		// In order not to depart from the behavior in 2.6,
		// we only allow an HTTPS router to take precedence over a TCP-TLS router if it is _not_ an HostSNI(*) router
		// (so basically any router that has a specific HostSNI based rule).
		handlerHTTPS.ServeQUIC(getPeekedConn(conn, hello.peeked))
		return
	}

	// Fallback on HTTPS catchAll.
	// We end up here for e.g. an HTTPS router that only has a PathPrefix rule,
	// which under the scenes is counted as an HostSNI(*) rule.
	if handlerHTTPS != nil {
		handlerHTTPS.ServeQUIC(getPeekedConn(conn, hello.peeked))
		return
	}

	if r.httpsForwarder != nil {
		r.httpsForwarder.ServeQUIC(getPeekedConn(conn, hello.peeked))
		return
	}

	conn.Close()
}

// AddHTTPTLSConfig defines a handler for a given sniHost and sets the matching tlsConfig.
func (r *Router) AddHTTPTLSConfig(sniHost string, config *tls.Config) {
	if r.hostHTTPTLSConfig == nil {
		r.hostHTTPTLSConfig = map[string]*tls.Config{}
	}

	r.hostHTTPTLSConfig[sniHost] = config
}

// GetHTTPHandler gets the attached http handler.
func (r *Router) GetHTTPHandler() http.Handler {
	return r.httpHandler
}

// GetHTTPSHandler gets the attached https handler.
func (r *Router) GetHTTPSHandler() http.Handler {
	return r.httpsHandler
}

// SetHTTPHandler attaches http handlers on the router.
func (r *Router) SetHTTPHandler(handler http.Handler) {
	r.httpHandler = handler
}

// SetHTTPSHandler attaches https handlers on the router.
func (r *Router) SetHTTPSHandler(handler http.Handler, config *tls.Config) {
	r.httpsHandler = handler
	r.httpsTLSConfig = config
}

// SetHTTPForwarder sets the quic handler that will forward the connections to an http handler.
func (r *Router) SetHTTPForwarder(handler quic.Handler) {
	r.httpForwarder = handler
}

// brokenTLSRouter is associated to a Host(SNI) rule for which we know the TLS conf is broken.
// It is used to make sure any attempt to connect to that hostname is closed,
// since we cannot proceed with the intended TLS conf.
type brokenTLSRouter struct{}

// ServeQUIC instantly closes the connection.
func (t *brokenTLSRouter) ServeQUIC(conn net.Conn) {
	_ = conn.Close()
}

// SetHTTPSForwarder sets the quic handler that will forward the TLS connections to an HTTP handler.
// It also sets up each TLS handler (with its TLS config) for each Host(SNI) rule we previously kept track of.
// It sets up a special handler that closes the connection if a TLS config is nil.
func (r *Router) SetHTTPSForwarder(handler quic.Handler) {
	for sniHost, tlsConf := range r.hostHTTPTLSConfig {
		var quicHandler quic.Handler
		if tlsConf == nil {
			quicHandler = &brokenTLSRouter{}
		} else {
			quicHandler = &quic.TLSHandler{
				Next:   handler,
				Config: tlsConf,
			}
		}

		// muxerHTTPS only contains single HostSNI rules (and no other kind of rules),
		// so there's no need for specifying a priority for them.
		err := r.muxerHTTPS.AddRoute("HostSNI(`"+sniHost+"`)", 0, quicHandler)
		if err != nil {
			log.WithoutContext().Errorf("Error while adding route for host: %v", err)
		}
	}

	if r.httpsTLSConfig == nil {
		r.httpsForwarder = &brokenTLSRouter{}
		return
	}

	r.httpsForwarder = &quic.TLSHandler{
		Next:   handler,
		Config: r.httpsTLSConfig,
	}
}

// peekedConn is a connection proxy that handles Peeked bytes.
type peekedConn struct {
	// Peeked are the bytes that have been read from Conn for the purposes of route matching,
	// but have not yet been consumed by Read calls.
	// It set to nil by Read when fully consumed.
	Peeked []byte

	// Conn is the underlying connection.
	// It can be type asserted against *net.TCPConn or other types as needed.
	// It should not be read from directly unless Peeked is nil.
	net.Conn
}

// Read reads bytes from the connection (using the buffer prior to actually reading).
func (c *peekedConn) Read(p []byte) (n int, err error) {
	if len(c.Peeked) > 0 {
		n = copy(p, c.Peeked)
		c.Peeked = c.Peeked[n:]
		if len(c.Peeked) == 0 {
			c.Peeked = nil
		}
		return n, nil
	}
	return c.Conn.Read(p)
}

// getPeekedConn creates a connection proxy with a peeked string.
func getPeekedConn(conn net.Conn, peeked string) net.Conn {
	conn = &peekedConn{
		Peeked: []byte(peeked),
		Conn:   conn,
	}

	return conn
}

type clientHello struct {
	serverName string   // SNI server name
	protos     []string // ALPN protocols list
	isTLS      bool     // whether we are a TLS handshake
	peeked     string   // the bytes peeked from the hello while getting the info
}

// clientHelloInfo returns various data from the clientHello handshake,
// without consuming any bytes from br.
// It returns an error if it can't peek the first byte from the connection.
func clientHelloInfo(br *bufio.Reader) (*clientHello, error) {
	hdr, err := br.Peek(1)
	if err != nil {
		var opErr *net.OpError
		if !errors.Is(err, io.EOF) && (!errors.As(err, &opErr) || opErr.Timeout()) {
			log.WithoutContext().Errorf("Error while Peeking first byte: %s", err)
		}
		return nil, err
	}

	// No valid TLS record has a type of 0x80, however SSLv2 handshakes start with an uint16 length
	// where the MSB is set and the first record is always < 256 bytes long.
	// Therefore, typ == 0x80 strongly suggests an SSLv2 client.
	const recordTypeSSLv2 = 0x80
	const recordTypeHandshake = 0x16
	if hdr[0] != recordTypeHandshake {
		if hdr[0] == recordTypeSSLv2 {
			// we consider SSLv2 as TLS, and it will be refused by real TLS handshake.
			return &clientHello{
				isTLS:  true,
				peeked: getPeeked(br),
			}, nil
		}
		return &clientHello{
			peeked: getPeeked(br),
		}, nil // Not TLS.
	}

	const recordHeaderLen = 5
	hdr, err = br.Peek(recordHeaderLen)
	if err != nil {
		log.Errorf("Error while Peeking hello: %s", err)
		return &clientHello{
			peeked: getPeeked(br),
		}, nil
	}

	recLen := int(hdr[3])<<8 | int(hdr[4]) // ignoring version in hdr[1:3]

	if recordHeaderLen+recLen > defaultBufSize {
		br = bufio.NewReaderSize(br, recordHeaderLen+recLen)
	}

	helloBytes, err := br.Peek(recordHeaderLen + recLen)
	if err != nil {
		log.Errorf("Error while Hello: %s", err)
		return &clientHello{
			isTLS:  true,
			peeked: getPeeked(br),
		}, nil
	}

	sni := ""
	var protos []string
	server := tls.Server(helloSniffConn{r: bytes.NewReader(helloBytes)}, &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			sni = hello.ServerName
			protos = hello.SupportedProtos
			return nil, nil
		},
	})
	_ = server.Handshake()

	return &clientHello{
		serverName: sni,
		isTLS:      true,
		peeked:     getPeeked(br),
		protos:     protos,
	}, nil
}

func getPeeked(br *bufio.Reader) string {
	peeked, err := br.Peek(br.Buffered())
	if err != nil {
		log.Errorf("Could not get anything: %s", err)
		return ""
	}
	return string(peeked)
}

// helloSniffConn is a net.Conn that reads from r, fails on Writes,
// and crashes otherwise.
type helloSniffConn struct {
	r        io.Reader
	net.Conn // nil; crash on any unexpected use
}

// Read reads from the underlying reader.
func (c helloSniffConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// Write crashes all the time.
func (helloSniffConn) Write(p []byte) (int, error) { return 0, io.EOF }
