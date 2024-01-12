package quic

import (
	"crypto/tls"
	"net"
)

// TLSHandler handles TLS connections.
type TLSHandler struct {
	Next   Handler
	Config *tls.Config
}

// ServeQUIC terminates the TLS connection.
func (t *TLSHandler) ServeQUIC(conn net.Conn) {
	t.Next.ServeQUIC(tls.Server(conn, t.Config))
}
