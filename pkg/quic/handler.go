package quic

import "net"

// Handler is the QUIC counterpart of the usual HTTP handler.
type Handler interface {
	ServeQUIC(conn net.Conn)
}

// The HandlerFunc type is an adapter to allow the use of ordinary functions as handlers.
type HandlerFunc func(conn net.Conn)

// ServeQUIC implements the Handler interface for QUIC.
func (f HandlerFunc) ServeQUIC(conn net.Conn) {
	f(conn)
}
