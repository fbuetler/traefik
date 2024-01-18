package quic

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"

	"github.com/traefik/traefik/v2/pkg/config/runtime"
	"github.com/traefik/traefik/v2/pkg/log"
	"github.com/traefik/traefik/v2/pkg/middlewares/snicheck"
	httpmuxer "github.com/traefik/traefik/v2/pkg/muxer/http"
	"github.com/traefik/traefik/v2/pkg/server/provider"
	traefiktls "github.com/traefik/traefik/v2/pkg/tls"
)

// NewManager Creates a new Manager.
func NewManager(conf *runtime.Configuration,
	httpHandlers map[string]http.Handler,
	httpsHandlers map[string]http.Handler,
	tlsManager *traefiktls.Manager,
) *Manager {
	return &Manager{
		httpHandlers:  httpHandlers,
		httpsHandlers: httpsHandlers,
		tlsManager:    tlsManager,
		conf:          conf,
	}
}

// Manager is a route/router manager.
type Manager struct {
	httpHandlers  map[string]http.Handler
	httpsHandlers map[string]http.Handler
	tlsManager    *traefiktls.Manager
	conf          *runtime.Configuration
}

func (m *Manager) getHTTPRouters(ctx context.Context, entryPoints []string, tls bool) map[string]map[string]*runtime.RouterInfo {
	if m.conf != nil {
		return m.conf.GetHTTPRoutersByEntryPoints(ctx, entryPoints, tls, false)
	}

	return make(map[string]map[string]*runtime.RouterInfo)
}

// BuildHandlers builds the handlers for the given entrypoints.
func (m *Manager) BuildHandlers(rootCtx context.Context, entryPoints []string) map[string]*Router {
	entryPointsRoutersHTTP := m.getHTTPRouters(rootCtx, entryPoints, true)

	entryPointHandlers := make(map[string]*Router)
	for _, entryPointName := range entryPoints {
		entryPointName := entryPointName

		ctx := log.With(rootCtx, log.Str(log.EntryPointName, entryPointName))
		handler, err := m.buildEntryPointHandlers(ctx, entryPointsRoutersHTTP[entryPointName], m.httpHandlers[entryPointName], m.httpsHandlers[entryPointName])
		if err != nil {
			log.FromContext(ctx).Error(err)
			continue
		}
		entryPointHandlers[entryPointName] = handler
	}
	return entryPointHandlers
}

type nameAndConfig struct {
	routerName string // just so we have it as additional information when logging
	TLSConfig  *tls.Config
}

func (m *Manager) buildEntryPointHandlers(ctx context.Context, configsHTTP map[string]*runtime.RouterInfo, handlerHTTP, handlerHTTPS http.Handler) (*Router, error) {
	// Build a new Router.
	router, err := NewRouter()
	if err != nil {
		return nil, err
	}

	router.SetHTTPHandler(handlerHTTP)

	// Even though the error is seemingly ignored (aside from logging it),
	// we actually rely later on the fact that a tls config is nil (which happens when an error is returned) to take special steps
	// when assigning a handler to a route.
	defaultTLSConf, err := m.tlsManager.Get(traefiktls.DefaultTLSStoreName, traefiktls.DefaultTLSConfigName)
	if err != nil {
		log.FromContext(ctx).Errorf("Error during the build of the default TLS configuration: %v", err)
	}

	// Keyed by domain. The source of truth for doing SNI checking (domain fronting).
	// As soon as there's (at least) two different tlsOptions found for the same domain,
	// we set the value to the default TLS conf.
	tlsOptionsForHost := map[string]string{}

	// Keyed by domain, then by options reference.
	// The actual source of truth for what TLS options will actually be used for the connection.
	// As opposed to tlsOptionsForHost, it keeps track of all the (different) TLS
	// options that occur for a given host name, so that later on we can set relevant
	// errors and logging for all the routers concerned (i.e. wrongly configured).
	tlsOptionsForHostSNI := map[string]map[string]nameAndConfig{}

	for routerHTTPName, routerHTTPConfig := range configsHTTP {
		if routerHTTPConfig.TLS == nil {
			continue
		}

		ctxRouter := log.With(provider.AddInContext(ctx, routerHTTPName), log.Str(log.RouterName, routerHTTPName))
		logger := log.FromContext(ctxRouter)

		tlsOptionsName := traefiktls.DefaultTLSConfigName
		if len(routerHTTPConfig.TLS.Options) > 0 && routerHTTPConfig.TLS.Options != traefiktls.DefaultTLSConfigName {
			tlsOptionsName = provider.GetQualifiedName(ctxRouter, routerHTTPConfig.TLS.Options)
		}

		domains, err := httpmuxer.ParseDomains(routerHTTPConfig.Rule)
		if err != nil {
			routerErr := fmt.Errorf("invalid rule %s, error: %w", routerHTTPConfig.Rule, err)
			routerHTTPConfig.AddError(routerErr, true)
			logger.Error(routerErr)
			continue
		}

		if len(domains) == 0 {
			// Extra Host(*) rule, for HTTPS routers with no Host rule,
			// and for requests for which the SNI does not match _any_ of the other existing routers Host.
			// This is only about choosing the TLS configuration.
			// The actual routing will be done further on by the HTTPS handler.
			// See examples below.
			router.AddHTTPTLSConfig("*", defaultTLSConf)

			// The server name (from a Host(SNI) rule) is the only parameter (available in HTTP routing rules) on which we can map a TLS config,
			// because it is the only one accessible before decryption (we obtain it during the ClientHello).
			// Therefore, when a router has no Host rule, it does not make any sense to specify some TLS options.
			// Consequently, when it comes to deciding what TLS config will be used,
			// for a request that will match an HTTPS router with no Host rule,
			// the result will depend on the _others_ existing routers (their Host rule, to be precise), and the TLS options associated with them,
			// even though they don't match the incoming request. Consider the following examples:

			//	# conf1
			//	httpRouter1:
			//		rule: PathPrefix("/foo")
			//	# Wherever the request comes from, the TLS config used will be the default one, because of the Host(*) fallback.

			//	# conf2
			//	httpRouter1:
			//		rule: PathPrefix("/foo")
			//
			//	httpRouter2:
			//		rule: Host("foo.com") && PathPrefix("/bar")
			//		tlsoptions: myTLSOptions
			//	# When a request for "/foo" comes, even though it won't be routed by httpRouter2,
			//	# if its SNI is set to foo.com, myTLSOptions will be used for the TLS connection.
			//	# Otherwise, it will fallback to the default TLS config.
			logger.Warnf("No domain found in rule %v, the TLS options applied for this router will depend on the SNI of each request", routerHTTPConfig.Rule)
		}

		// Even though the error is seemingly ignored (aside from logging it),
		// we actually rely later on the fact that a tls config is nil (which happens when an error is returned) to take special steps
		// when assigning a handler to a route.
		tlsConf, tlsConfErr := m.tlsManager.Get(traefiktls.DefaultTLSStoreName, tlsOptionsName)
		if tlsConfErr != nil {
			// Note: we do not call AddError here because we already did so when buildRouterHandler errored for the same reason.
			logger.Error(tlsConfErr)
		}

		for _, domain := range domains {
			// domain is already in lower case thanks to the domain parsing
			if tlsOptionsForHostSNI[domain] == nil {
				tlsOptionsForHostSNI[domain] = make(map[string]nameAndConfig)
			}
			tlsOptionsForHostSNI[domain][tlsOptionsName] = nameAndConfig{
				routerName: routerHTTPName,
				TLSConfig:  tlsConf,
			}

			if name, ok := tlsOptionsForHost[domain]; ok && name != tlsOptionsName {
				// Different tlsOptions on the same domain, so fallback to default
				tlsOptionsForHost[domain] = traefiktls.DefaultTLSConfigName
			} else {
				tlsOptionsForHost[domain] = tlsOptionsName
			}
		}
	}

	sniCheck := snicheck.New(tlsOptionsForHost, handlerHTTPS)

	// Keep in mind that defaultTLSConf might be nil here.
	router.SetHTTPSHandler(sniCheck, defaultTLSConf)

	logger := log.FromContext(ctx)
	for hostSNI, tlsConfigs := range tlsOptionsForHostSNI {
		if len(tlsConfigs) == 1 {
			var optionsName string
			var config *tls.Config
			for k, v := range tlsConfigs {
				optionsName = k
				config = v.TLSConfig
				break
			}

			if config == nil {
				// we use nil config as a signal to insert a handler
				// that enforces that TLS connection attempts to the corresponding (broken) router should fail.
				logger.Debugf("Adding special closing route for %s because broken TLS options %s", hostSNI, optionsName)
				router.AddHTTPTLSConfig(hostSNI, nil)
				continue
			}

			logger.Debugf("Adding route for %s with TLS options %s", hostSNI, optionsName)
			router.AddHTTPTLSConfig(hostSNI, config)
			continue
		}

		// multiple tlsConfigs

		routers := make([]string, 0, len(tlsConfigs))
		for _, v := range tlsConfigs {
			configsHTTP[v.routerName].AddError(fmt.Errorf("found different TLS options for routers on the same host %v, so using the default TLS options instead", hostSNI), false)
			routers = append(routers, v.routerName)
		}

		logger.Warnf("Found different TLS options for routers on the same host %v, so using the default TLS options instead for these routers: %#v", hostSNI, routers)
		if defaultTLSConf == nil {
			logger.Debugf("Adding special closing route for %s because broken default TLS options", hostSNI)
		}

		router.AddHTTPTLSConfig(hostSNI, defaultTLSConf)
	}

	return router, nil
}
