package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"

	"github.com/netsec-ethz/scion-apps/pkg/pan"
	"github.com/netsec-ethz/scion-apps/pkg/quicutil"
	"github.com/netsec-ethz/scion-apps/pkg/shttp"

	"github.com/traefik/traefik/v2/pkg/config/static"
	"github.com/traefik/traefik/v2/pkg/log"
	tcprouter "github.com/traefik/traefik/v2/pkg/server/router/tcp"
)

type scionServer struct {
	*shttp.Server

	scionListener net.Listener
	strictScion   string

	lock   sync.RWMutex
	getter func(info *tls.ClientHelloInfo) (*tls.Config, error)
}

func newSCIONServer(ctx context.Context, configuration *static.EntryPoint, httpsServer *httpServer) (*scionServer, error) {
	if configuration.SCION == nil {
		return nil, nil
	}

	listener, err := listen(configuration.GetAddress())
	if err != nil {
		return nil, fmt.Errorf("starting listener: %w", err)
	}

	scion := &scionServer{
		scionListener: listener,
		strictScion:   configuration.SCION.StrictScion,
		getter: func(info *tls.ClientHelloInfo) (*tls.Config, error) {
			return nil, errors.New("no tls config")
		},
	}

	scion.Server = &shttp.Server{
		Server: &http.Server{
			Addr:      configuration.GetAddress(),
			Handler:   httpsServer.Server.(*http.Server).Handler,
			TLSConfig: &tls.Config{GetConfigForClient: scion.getGetConfigForClient},
		},
	}

	previousHandler := httpsServer.Server.(*http.Server).Handler
	httpsServer.Server.(*http.Server).Handler = http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if err := scion.setScionHeaders(rw.Header()); err != nil {
			log.FromContext(ctx).Errorf("Failed to set SCION headers: %v", err)
		}

		previousHandler.ServeHTTP(rw, req)
	})

	return scion, nil
}

func (s *scionServer) Start() error {
	return s.Server.Server.Serve(s.scionListener)
}

func (s *scionServer) Switch(rt *tcprouter.Router) {
	s.lock.Lock()
	defer s.lock.Unlock()

	s.getter = rt.GetTLSGetClientInfo()
}

func (s *scionServer) Shutdown(_ context.Context) error {
	// TODO: use s.Server.CloseGracefully() when available.
	return s.Server.Close()
}

func (s *scionServer) getGetConfigForClient(info *tls.ClientHelloInfo) (*tls.Config, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()

	return s.getter(info)
}

// ErrNoStrictScion is the error returned by setScionHeaders when no strict SCION value was found to be announced.
var ErrNoStrictScion = errors.New("server is listening for SCION but does not announce its address to be discovered")

// inspired by quic-go/http3/server.SetQuicHeaders
// https://github.com/quic-go/quic-go/blob/v0.39.1/http3/server.go#L681-L691
func (s *scionServer) setScionHeaders(hdr http.Header) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	if s.strictScion == "" {
		return ErrNoStrictScion
	}

	if hdr.Get("Strict-SCION") == "" {
		hdr.Set("Strict-SCION", s.strictScion)
	}

	return nil
}

// Copied from scion-apps/pkg/shttp
// https://github.com/netsec-ethz/scion-apps/blob/v0.5.0/pkg/shttp/server.go#L86-L100
func listen(addr string) (net.Listener, error) {
	tlsCfg := &tls.Config{
		NextProtos:   []string{quicutil.SingleStreamProto},
		Certificates: quicutil.MustGenerateSelfSignedCert(),
	}
	laddr, err := pan.ParseOptionalIPPort(addr)
	if err != nil {
		return nil, err
	}
	quicListener, err := pan.ListenQUIC(context.Background(), laddr, nil, tlsCfg, nil)
	if err != nil {
		return nil, err
	}
	return quicutil.SingleStreamListener{Listener: quicListener}, nil
}
