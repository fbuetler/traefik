package udp

import (
	"net"

	"github.com/traefik/traefik/v2/pkg/safe"
)

// HandlerSwitcher is a switcher implementation of the Handler interface.
type HandlerSwitcher struct {
	handler safe.Safe
}

// ServeUDP implements the Handler interface.
func (s *HandlerSwitcher) ServeUDP(conn net.Conn) {
	handler := s.handler.Get()
	h, ok := handler.(Handler)
	if ok {
		h.ServeUDP(conn)
	} else {
		conn.Close()
	}
}

// Switch replaces s handler with the given handler.
func (s *HandlerSwitcher) Switch(handler Handler) {
	s.handler.Set(handler)
}
