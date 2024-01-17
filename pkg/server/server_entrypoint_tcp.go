package server

import (
	"context"
	"errors"
	"fmt"
	stdlog "log"
	"net"
	"net/url"
	"sync"
	"syscall"
	"time"

	"github.com/pires/go-proxyproto"
	"github.com/sirupsen/logrus"

	"github.com/traefik/traefik/v2/pkg/config/static"
	"github.com/traefik/traefik/v2/pkg/log"
	"github.com/traefik/traefik/v2/pkg/middlewares/requestdecorator"
	"github.com/traefik/traefik/v2/pkg/safe"
	"github.com/traefik/traefik/v2/pkg/server/router"
	tcprouter "github.com/traefik/traefik/v2/pkg/server/router/tcp"
	"github.com/traefik/traefik/v2/pkg/tcp"
	"github.com/traefik/traefik/v2/pkg/types"
)

var httpServerLogger = stdlog.New(log.WithoutContext().WriterLevel(logrus.DebugLevel), "", 0)

type tcpForwarder struct {
	net.Listener
	connChan chan net.Conn
	errChan  chan error
}

func newTCPForwarder(ln net.Listener) *tcpForwarder {
	return &tcpForwarder{
		Listener: ln,
		connChan: make(chan net.Conn),
		errChan:  make(chan error),
	}
}

// ServeTCP uses the connection to serve it later in "Accept".
func (h *tcpForwarder) ServeTCP(conn tcp.WriteCloser) {
	h.connChan <- conn
}

// Accept retrieves a served connection in ServeTCP.
func (h *tcpForwarder) Accept() (net.Conn, error) {
	select {
	case conn := <-h.connChan:
		return conn, nil
	case err := <-h.errChan:
		return nil, err
	}
}

// TCPEntryPoints holds a map of TCPEntryPoint (the entrypoint names being the keys).
type TCPEntryPoints map[string]*TCPEntryPoint

// NewTCPEntryPoints creates a new TCPEntryPoints.
func NewTCPEntryPoints(entryPointsConfig static.EntryPoints, hostResolverConfig *types.HostResolverConfig, scion *static.SCION) (TCPEntryPoints, error) {
	serverEntryPointsTCP := make(TCPEntryPoints)
	for entryPointName, config := range entryPointsConfig {
		protocol, err := config.GetProtocol()
		if err != nil {
			return nil, fmt.Errorf("error while building entryPoint %s: %w", entryPointName, err)
		}

		if protocol != "tcp" {
			continue
		}

		ctx := log.With(context.Background(), log.Str(log.EntryPointName, entryPointName))

		serverEntryPointsTCP[entryPointName], err = NewTCPEntryPoint(ctx, config, hostResolverConfig, scion)
		if err != nil {
			return nil, fmt.Errorf("error while building entryPoint %s: %w", entryPointName, err)
		}
	}
	return serverEntryPointsTCP, nil
}

// Start the server entry points.
func (eps TCPEntryPoints) Start() {
	for entryPointName, serverEntryPoint := range eps {
		ctx := log.With(context.Background(), log.Str(log.EntryPointName, entryPointName))
		go serverEntryPoint.Start(ctx)
	}
}

// Stop the server entry points.
func (eps TCPEntryPoints) Stop() {
	var wg sync.WaitGroup

	for epn, ep := range eps {
		wg.Add(1)

		go func(entryPointName string, entryPoint *TCPEntryPoint) {
			defer wg.Done()

			ctx := log.With(context.Background(), log.Str(log.EntryPointName, entryPointName))
			entryPoint.Shutdown(ctx)

			log.FromContext(ctx).Debugf("Entry point %s closed", entryPointName)
		}(epn, ep)
	}

	wg.Wait()
}

// Switch the TCP routers.
func (eps TCPEntryPoints) Switch(routersTCP map[string]*tcprouter.Router) {
	for entryPointName, rt := range routersTCP {
		eps[entryPointName].SwitchRouter(rt)
	}
}

// TCPEntryPoint is the TCP server.
type TCPEntryPoint struct {
	listener               net.Listener
	switcher               *tcp.HandlerSwitcher
	transportConfiguration *static.EntryPointsTransport
	tracker                *connectionTracker
	httpServer             *httpServer
	httpsServer            *httpServer

	http3Server *http3server
}

// NewTCPEntryPoint creates a new TCPEntryPoint.
func NewTCPEntryPoint(ctx context.Context, configuration *static.EntryPoint, hostResolverConfig *types.HostResolverConfig, scion *static.SCION) (*TCPEntryPoint, error) {
	tracker := newConnectionTracker()

	listener, err := buildTCPListener(ctx, configuration)
	if err != nil {
		return nil, fmt.Errorf("error preparing server: %w", err)
	}

	rt := &tcprouter.Router{}

	reqDecorator := requestdecorator.New(hostResolverConfig)

	httpServer, err := createHttpServerWithTCPListener(ctx, listener, configuration, true, reqDecorator, scion)
	if err != nil {
		return nil, fmt.Errorf("error preparing http server: %w", err)
	}

	rt.SetHTTPForwarder(httpServer.TCPForwarder)

	httpsServer, err := createHttpServerWithTCPListener(ctx, listener, configuration, false, reqDecorator, scion)
	if err != nil {
		return nil, fmt.Errorf("error preparing https server: %w", err)
	}

	h3Server, err := newHTTP3Server(ctx, configuration, httpsServer)
	if err != nil {
		return nil, fmt.Errorf("error preparing http3 server: %w", err)
	}

	rt.SetHTTPSForwarder(httpsServer.TCPForwarder)

	tcpSwitcher := &tcp.HandlerSwitcher{}
	tcpSwitcher.Switch(rt)

	return &TCPEntryPoint{
		listener:               listener,
		switcher:               tcpSwitcher,
		transportConfiguration: configuration.Transport,
		tracker:                tracker,
		httpServer:             httpServer,
		httpsServer:            httpsServer,
		http3Server:            h3Server,
	}, nil
}

// Start starts the TCP server.
func (e *TCPEntryPoint) Start(ctx context.Context) {
	logger := log.FromContext(ctx)
	logger.Debug("Starting TCP Server")

	if e.http3Server != nil {
		go func() { _ = e.http3Server.Start() }()
	}

	for {
		conn, err := e.listener.Accept()
		if err != nil {
			logger.Error(err)

			var opErr *net.OpError
			if errors.As(err, &opErr) && opErr.Temporary() {
				continue
			}

			var urlErr *url.Error
			if errors.As(err, &urlErr) && urlErr.Temporary() {
				continue
			}

			e.httpServer.TCPForwarder.errChan <- err
			e.httpsServer.TCPForwarder.errChan <- err

			return
		}

		writeCloser, err := writeCloser(conn)
		if err != nil {
			panic(err)
		}

		safe.Go(func() {
			// Enforce read/write deadlines at the connection level,
			// because when we're peeking the first byte to determine whether we are doing TLS,
			// the deadlines at the server level are not taken into account.
			if e.transportConfiguration.RespondingTimeouts.ReadTimeout > 0 {
				err := writeCloser.SetReadDeadline(time.Now().Add(time.Duration(e.transportConfiguration.RespondingTimeouts.ReadTimeout)))
				if err != nil {
					logger.Errorf("Error while setting read deadline: %v", err)
				}
			}

			if e.transportConfiguration.RespondingTimeouts.WriteTimeout > 0 {
				err = writeCloser.SetWriteDeadline(time.Now().Add(time.Duration(e.transportConfiguration.RespondingTimeouts.WriteTimeout)))
				if err != nil {
					logger.Errorf("Error while setting write deadline: %v", err)
				}
			}

			e.switcher.ServeTCP(newTrackedTCPConnection(writeCloser, e.tracker))
		})
	}
}

// Shutdown stops the TCP connections.
func (e *TCPEntryPoint) Shutdown(ctx context.Context) {
	logger := log.FromContext(ctx)

	reqAcceptGraceTimeOut := time.Duration(e.transportConfiguration.LifeCycle.RequestAcceptGraceTimeout)
	if reqAcceptGraceTimeOut > 0 {
		logger.Infof("Waiting %s for incoming requests to cease", reqAcceptGraceTimeOut)
		time.Sleep(reqAcceptGraceTimeOut)
	}

	graceTimeOut := time.Duration(e.transportConfiguration.LifeCycle.GraceTimeOut)
	ctx, cancel := context.WithTimeout(ctx, graceTimeOut)
	logger.Debugf("Waiting %s seconds before killing connections.", graceTimeOut)

	var wg sync.WaitGroup

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

	if e.httpServer.Server != nil {
		wg.Add(1)
		go shutdownServer(e.httpServer.Server)
	}

	if e.httpsServer.Server != nil {
		wg.Add(1)
		go shutdownServer(e.httpsServer.Server)

		if e.http3Server != nil {
			wg.Add(1)
			go shutdownServer(e.http3Server)
		}
	}

	if e.tracker != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := e.tracker.Shutdown(ctx)
			if err == nil {
				return
			}
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				logger.Debugf("Server failed to shutdown before deadline because: %s", err)
			}
			e.tracker.Close()
		}()
	}

	wg.Wait()
	cancel()
}

// SwitchRouter switches the TCP router handler.
func (e *TCPEntryPoint) SwitchRouter(rt *tcprouter.Router) {
	rt.SetHTTPForwarder(e.httpServer.TCPForwarder)

	httpHandler := rt.GetHTTPHandler()
	if httpHandler == nil {
		httpHandler = router.BuildDefaultHTTPRouter()
	}

	e.httpServer.Switcher.UpdateHandler(httpHandler)

	rt.SetHTTPSForwarder(e.httpsServer.TCPForwarder)

	httpsHandler := rt.GetHTTPSHandler()
	if httpsHandler == nil {
		httpsHandler = router.BuildDefaultHTTPRouter()
	}

	e.httpsServer.Switcher.UpdateHandler(httpsHandler)

	e.switcher.Switch(rt)

	if e.http3Server != nil {
		e.http3Server.Switch(rt)
	}
}

// writeCloserWrapper wraps together a connection, and the concrete underlying
// connection type that was found to satisfy WriteCloser.
type writeCloserWrapper struct {
	net.Conn
	writeCloser tcp.WriteCloser
}

func (c *writeCloserWrapper) CloseWrite() error {
	return c.writeCloser.CloseWrite()
}

// writeCloser returns the given connection, augmented with the WriteCloser
// implementation, if any was found within the underlying conn.
func writeCloser(conn net.Conn) (tcp.WriteCloser, error) {
	switch typedConn := conn.(type) {
	case *proxyproto.Conn:
		underlying, ok := typedConn.TCPConn()
		if !ok {
			return nil, fmt.Errorf("underlying connection is not a tcp connection")
		}
		return &writeCloserWrapper{writeCloser: underlying, Conn: typedConn}, nil
	case *net.TCPConn:
		return typedConn, nil
	default:
		return nil, fmt.Errorf("unknown connection type %T", typedConn)
	}
}

// tcpKeepAliveListener sets TCP keep-alive timeouts on accepted
// connections.
type tcpKeepAliveListener struct {
	*net.TCPListener
}

func (ln tcpKeepAliveListener) Accept() (net.Conn, error) {
	tc, err := ln.AcceptTCP()
	if err != nil {
		return nil, err
	}

	if err := tc.SetKeepAlive(true); err != nil {
		return nil, err
	}

	if err := tc.SetKeepAlivePeriod(3 * time.Minute); err != nil {
		// Some systems, such as OpenBSD, have no user-settable per-socket TCP
		// keepalive options.
		if !errors.Is(err, syscall.ENOPROTOOPT) {
			return nil, err
		}
	}

	return tc, nil
}

func buildTCPListener(ctx context.Context, entryPoint *static.EntryPoint) (net.Listener, error) {
	listener, err := net.Listen("tcp", entryPoint.GetAddress())
	if err != nil {
		return nil, fmt.Errorf("error opening listener: %w", err)
	}

	listener = tcpKeepAliveListener{listener.(*net.TCPListener)}

	if entryPoint.ProxyProtocol != nil {
		listener, err = buildProxyProtocolListener(ctx, entryPoint, listener)
		if err != nil {
			return nil, fmt.Errorf("error creating proxy protocol listener: %w", err)
		}
	}
	return listener, nil
}

func createHttpServerWithTCPListener(ctx context.Context, ln net.Listener, configuration *static.EntryPoint, withH2c bool, reqDecorator *requestdecorator.RequestDecorator, scion *static.SCION) (*httpServer, error) {
	listener := newTCPForwarder(ln)

	httpServer, err := createHTTPServer(ctx, listener, configuration, true, reqDecorator, scion)
	if err != nil {
		return nil, fmt.Errorf("error preparing http server: %w", err)
	}
	httpServer.TCPForwarder = listener

	return httpServer, nil
}

func newTrackedTCPConnection(conn tcp.WriteCloser, tracker *connectionTracker) *trackedTCPConnection {
	tracker.AddConnection(conn)
	return &trackedTCPConnection{
		WriteCloser: conn,
		tracker:     tracker,
	}
}

type trackedTCPConnection struct {
	tracker *connectionTracker
	tcp.WriteCloser
}

func (t *trackedTCPConnection) Close() error {
	t.tracker.RemoveConnection(t.WriteCloser)
	return t.WriteCloser.Close()
}
