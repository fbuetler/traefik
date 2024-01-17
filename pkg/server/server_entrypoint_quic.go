package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/netsec-ethz/scion-apps/pkg/pan"
	"github.com/netsec-ethz/scion-apps/pkg/quicutil"
	"github.com/scaleway/scaleway-sdk-go/logger"

	"github.com/traefik/traefik/v2/pkg/config/static"
	"github.com/traefik/traefik/v2/pkg/log"
	"github.com/traefik/traefik/v2/pkg/middlewares/requestdecorator"
	"github.com/traefik/traefik/v2/pkg/quic"
	"github.com/traefik/traefik/v2/pkg/safe"
	"github.com/traefik/traefik/v2/pkg/server/router"
	quicrouter "github.com/traefik/traefik/v2/pkg/server/router/quic"
	"github.com/traefik/traefik/v2/pkg/types"
)

type stoppableListener interface {
	Accept() (net.Conn, error)
	Addr() net.Addr
	Shutdown(graceTimeout time.Duration) error
	Close() error
}

// QUICEntryPoints maps QUIC entry points by their names.
type QUICEntryPoints map[string]*QUICEntryPoint

// NewQUICEntryPoints returns all the QUIC entry points, keyed by name.
func NewQUICEntryPoints(cfg static.EntryPoints, hostResolverConfig *types.HostResolverConfig) (QUICEntryPoints, error) {
	entryPoints := make(QUICEntryPoints)
	for entryPointName, entryPoint := range cfg {
		protocol, err := entryPoint.GetProtocol()
		if err != nil {
			return nil, fmt.Errorf("error while building entryPoint %s: %w", entryPointName, err)
		}

		if protocol != "quic" {
			continue
		}

		ctx := log.With(context.Background(), log.Str(log.EntryPointName, entryPointName))

		ep, err := NewQUICEntryPoint(ctx, entryPoint, hostResolverConfig)
		if err != nil {
			return nil, fmt.Errorf("error while building entryPoint %s: %w", entryPointName, err)
		}
		entryPoints[entryPointName] = ep
	}
	return entryPoints, nil
}

// Start commences the listening for all the entry points.
func (eps QUICEntryPoints) Start() {
	for entryPointName, ep := range eps {
		ctx := log.With(context.Background(), log.Str(log.EntryPointName, entryPointName))
		go ep.Start(ctx)
	}
}

// Stop makes all the entry points stop listening, and release associated resources.
func (eps QUICEntryPoints) Stop() {
	var wg sync.WaitGroup

	for epn, ep := range eps {
		wg.Add(1)

		go func(entryPointName string, entryPoint *QUICEntryPoint) {
			defer wg.Done()

			ctx := log.With(context.Background(), log.Str(log.EntryPointName, entryPointName))
			entryPoint.Shutdown(ctx)

			log.FromContext(ctx).Debugf("Entry point %s closed", entryPointName)
		}(epn, ep)
	}

	wg.Wait()
}

// Switch swaps out all the given handlers in their associated entrypoints.
func (eps QUICEntryPoints) Switch(routersQUIC map[string]*quicrouter.Router) {
	for epName, rt := range routersQUIC {
		if ep, ok := eps[epName]; ok {
			ep.SwitchRouter(rt)
			continue
		}
		log.WithoutContext().Errorf("EntryPoint %q does not exist", epName)
	}
}

// QUICEntryPoint is an entry point where we listen for QUIC packets.
type QUICEntryPoint struct {
	listener               stoppableListener
	switcher               *quic.HandlerSwitcher
	tracker                *connectionTracker
	transportConfiguration *static.EntryPointsTransport
	httpServer             *httpServer
	httpsServer            *httpServer
}

// NewQUICEntryPoint returns a QUIC entry point.
func NewQUICEntryPoint(ctx context.Context, cfg *static.EntryPoint, hostResolverConfig *types.HostResolverConfig) (*QUICEntryPoint, error) {
	tracker := newConnectionTracker()

	listener, err := buildQUICListener(ctx, cfg)
	if err != nil {
		return nil, err
	}

	rt := &quicrouter.Router{}

	reqDecorator := requestdecorator.New(hostResolverConfig)

	httpServer, err := createHttpServerWithQUICListener(ctx, listener, cfg, true, reqDecorator)
	if err != nil {
		return nil, fmt.Errorf("error preparing http server: %w", err)
	}

	rt.SetHTTPForwarder(httpServer.QUICForwarder)

	httpsServer, err := createHttpServerWithQUICListener(ctx, listener, cfg, false, reqDecorator)
	if err != nil {
		return nil, fmt.Errorf("error preparing https server: %w", err)
	}

	rt.SetHTTPSForwarder(httpsServer.QUICForwarder)

	quicSwitcher := &quic.HandlerSwitcher{}
	quicSwitcher.Switch(rt)

	return &QUICEntryPoint{
		listener:               listener,
		switcher:               quicSwitcher,
		tracker:                tracker,
		transportConfiguration: cfg.Transport,
		httpServer:             httpServer,
		httpsServer:            httpsServer,
	}, nil
}

func newTrackedQUICConnection(conn net.Conn, tracker *connectionTracker) *trackedQUICConnection {
	tracker.AddConnection(conn)
	return &trackedQUICConnection{
		Conn:    conn,
		tracker: tracker,
	}
}

type trackedQUICConnection struct {
	tracker *connectionTracker
	net.Conn
}

func (t *trackedQUICConnection) Close() error {
	t.tracker.RemoveConnection(t.Conn)
	return t.Conn.Close()
}

// Start commences the listening for ep.
func (ep *QUICEntryPoint) Start(ctx context.Context) {
	log.FromContext(ctx).Debug("Start QUIC Server")
	for {
		conn, err := ep.listener.Accept()
		if err != nil {
			// Only errClosedListener can happen that's why we return
			return
		}

		safe.Go(func() {
			// Enforce read/write deadlines at the connection level,
			// because when we're peeking the first byte to determine whether we are doing TLS,
			// the deadlines at the server level are not taken into account.
			if ep.transportConfiguration.RespondingTimeouts.ReadTimeout > 0 {
				err := conn.SetReadDeadline(time.Now().Add(time.Duration(ep.transportConfiguration.RespondingTimeouts.ReadTimeout)))
				if err != nil {
					logger.Errorf("Error while setting read deadline: %v", err)
				}
			}

			if ep.transportConfiguration.RespondingTimeouts.WriteTimeout > 0 {
				err = conn.SetWriteDeadline(time.Now().Add(time.Duration(ep.transportConfiguration.RespondingTimeouts.WriteTimeout)))
				if err != nil {
					logger.Errorf("Error while setting write deadline: %v", err)
				}
			}

			ep.switcher.ServeQUIC(newTrackedQUICConnection(conn, ep.tracker))
		})
	}
}

// Shutdown closes ep's listener. It eventually closes all "sessions" and
// releases associated resources, but only after it has waited for a graceTimeout,
// if any was configured.
func (ep *QUICEntryPoint) Shutdown(ctx context.Context) {
	logger := log.FromContext(ctx)

	reqAcceptGraceTimeOut := time.Duration(ep.transportConfiguration.LifeCycle.RequestAcceptGraceTimeout)
	if reqAcceptGraceTimeOut > 0 {
		logger.Infof("Waiting %s for incoming requests to cease", reqAcceptGraceTimeOut)
		time.Sleep(reqAcceptGraceTimeOut)
	}

	graceTimeOut := time.Duration(ep.transportConfiguration.LifeCycle.GraceTimeOut)
	ctx, cancel := context.WithTimeout(ctx, graceTimeOut)
	logger.Debugf("Waiting %s seconds before killing connections.", graceTimeOut)

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		err := ep.listener.Shutdown(graceTimeOut)
		if err == nil {
			return
		}
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			logger.Debugf("Listener failed to shutdown within deadline because: %s", err)
			if err = ep.listener.Close(); err != nil {
				logger.Error(err)
			}
			return
		}
		logger.Error(err)
		// We expect Close to fail again because Shutdown most likely failed when trying to close a listener.
		// We still call it however, to make sure that all connections get closed as well.
		ep.listener.Close()
	}()

	shutdownServer := func(server stoppable) {
		defer wg.Done()
		err := server.Shutdown(ctx)
		if err == nil {
			return
		}
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			logger.Debugf("Server failed to shutdown within deadline because: %s", err)
			if err = server.Close(); err != nil {
				logger.Error(err)
			}
			return
		}
		logger.Error(err)
		// We expect Close to fail again because Shutdown most likely failed when trying to close a listener.
		// We still call it however, to make sure that all connections get closed as well.
		server.Close()
	}

	if ep.httpServer.Server != nil {
		wg.Add(1)
		go shutdownServer(ep.httpServer.Server)
	}

	if ep.httpsServer.Server != nil {
		wg.Add(1)
		go shutdownServer(ep.httpsServer.Server)
	}

	if ep.tracker != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := ep.tracker.Shutdown(ctx)
			if err == nil {
				return
			}
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				logger.Debugf("Tracker failed to shutdown before deadline because: %s", err)
			}
			logger.Error(err)
			ep.tracker.Close()
		}()
	}

	wg.Wait()
	cancel()
}

// Switch replaces ep's handler with the one given as argument.
func (ep *QUICEntryPoint) SwitchRouter(rt *quicrouter.Router) {
	rt.SetHTTPForwarder(ep.httpServer.QUICForwarder)

	httpHandler := rt.GetHTTPHandler()
	if httpHandler == nil {
		httpHandler = router.BuildDefaultHTTPRouter()
	}

	ep.httpServer.Switcher.UpdateHandler(httpHandler)

	rt.SetHTTPSForwarder(ep.httpsServer.QUICForwarder)

	httpsHandler := rt.GetHTTPSHandler()
	if httpsHandler == nil {
		httpsHandler = router.BuildDefaultHTTPRouter()
	}

	ep.httpsServer.Switcher.UpdateHandler(httpsHandler)

	ep.switcher.Switch(rt)
}

// scionListener implements stoppableListener
type scionListener struct {
	net.Listener
}

func (s *scionListener) Shutdown(grateTimeOut time.Duration) error { return s.Close() }

var ErrQuicNotImplemented = errors.New("server does not implement QUIC without SCION")

func buildQUICListener(ctx context.Context, cfg *static.EntryPoint) (stoppableListener, error) {
	if cfg.SCION == nil {
		return nil, ErrQuicNotImplemented
	}

	listener, err := listenSCION(cfg.GetAddress())
	if err != nil {
		return nil, err
	}
	if cfg.ProxyProtocol != nil {
		listener, err = buildProxyProtocolListener(ctx, cfg, listener)
		if err != nil {
			return nil, fmt.Errorf("error creating proxy protocol listener: %w", err)
		}
	}
	return &scionListener{listener}, nil

}

// Copied from scion-apps/pkg/shttp
// https://github.com/netsec-ethz/scion-apps/blob/v0.5.0/pkg/shttp/server.go#L86-L100
func listenSCION(addr string) (net.Listener, error) {
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

type quicForwarder struct {
	net.Listener
	connChan chan net.Conn
	errChan  chan error
}

func newQUICForwarder(ln net.Listener) *quicForwarder {
	return &quicForwarder{
		Listener: ln,
		connChan: make(chan net.Conn),
		errChan:  make(chan error),
	}
}

// ServeQUIC uses the connection to serve it later in "Accept".
func (h *quicForwarder) ServeQUIC(conn net.Conn) {
	fmt.Println("3: quicForwarder/ServeQUIC")
	h.connChan <- conn
}

// Accept retrieves a served connection in ServeQUIC.
func (h *quicForwarder) Accept() (net.Conn, error) {
	select {
	case conn := <-h.connChan:
		return conn, nil
	case err := <-h.errChan:
		return nil, err
	}
}

func createHttpServerWithQUICListener(ctx context.Context, ln net.Listener, configuration *static.EntryPoint, withH2c bool, reqDecorator *requestdecorator.RequestDecorator) (*httpServer, error) {
	listener := newQUICForwarder(ln)

	httpServer, err := createHTTPServer(ctx, listener, configuration, true, reqDecorator, nil)
	if err != nil {
		return nil, fmt.Errorf("error preparing http server: %w", err)
	}
	httpServer.QUICForwarder = listener

	return httpServer, nil
}
