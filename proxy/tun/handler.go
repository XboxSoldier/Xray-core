package tun

import (
	"context"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	c "github.com/xtls/xray-core/common/ctx"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// Handler is managing object that tie together tun interface, ip stack and dispatch connections to the routing
type Handler struct {
	ctx             context.Context
	config          *Config
	tun             Tun
	stack           Stack
	routeManager    RouteManager
	policyManager   policy.Manager
	dispatcher      routing.Dispatcher
	tag             string
	sniffingRequest session.SniffingRequest
}

// ConnectionHandler interface with the only method that stack is going to push new connections to
type ConnectionHandler interface {
	HandleConnection(conn net.Conn, destination net.Destination)
}

// Handler implements ConnectionHandler
var _ ConnectionHandler = (*Handler)(nil)

func (t *Handler) policy() policy.Session {
	p := t.policyManager.ForLevel(t.config.UserLevel)
	return p
}

// Init the Handler instance with necessary parameters
func (t *Handler) Init(ctx context.Context, pm policy.Manager, dispatcher routing.Dispatcher) error {
	var err error

	// Retrieve tag and sniffing config from context (set by AlwaysOnInboundHandler)
	if inbound := session.InboundFromContext(ctx); inbound != nil {
		t.tag = inbound.Tag
	}
	if content := session.ContentFromContext(ctx); content != nil {
		t.sniffingRequest = content.SniffingRequest
	}

	t.ctx = core.ToBackgroundDetachedContext(ctx)
	t.policyManager = pm
	t.dispatcher = dispatcher

	tunName := t.config.Name
	tunOptions := TunOptions{
		Name: tunName,
		MTU:  t.config.MTU,
	}
	tunInterface, err := NewTun(tunOptions)
	if err != nil {
		return err
	}
	t.tun = tunInterface

	errors.LogInfo(t.ctx, tunName, " created")

	tunStackOptions := StackOptions{
		Tun:         tunInterface,
		IdleTimeout: pm.ForLevel(t.config.UserLevel).Timeouts.ConnectionIdle,
	}
	tunStack, err := NewStack(t.ctx, tunStackOptions, t)
	if err != nil {
		_ = tunInterface.Close()
		return err
	}

	err = tunStack.Start()
	if err != nil {
		_ = tunStack.Close()
		_ = tunInterface.Close()
		return err
	}

	err = tunInterface.Start()
	if err != nil {
		_ = tunStack.Close()
		_ = tunInterface.Close()
		return err
	}

	t.stack = tunStack

	// Set up auto-route if enabled
	if t.config.AutoRoute {
		routeOpts, err := t.buildRouteOptions()
		if err != nil {
			errors.LogWarning(t.ctx, "failed to build route options: ", err)
		} else {
			routeManager, err := NewRouteManager(t.ctx, routeOpts)
			if err != nil {
				errors.LogWarning(t.ctx, "failed to create route manager: ", err)
			} else {
				if err := routeManager.SetRoutes(); err != nil {
					errors.LogWarning(t.ctx, "failed to set routes: ", err)
					_ = routeManager.Close()
				} else {
					t.routeManager = routeManager
				}
			}
		}
	}

	errors.LogInfo(t.ctx, tunName, " up")
	return nil
}

// buildRouteOptions constructs RouteOptions from the config
func (t *Handler) buildRouteOptions() (RouteOptions, error) {
	routeAddrs, err := ParsePrefixes(t.config.RouteAddress)
	if err != nil {
		return RouteOptions{}, errors.New("invalid route_address").Base(err)
	}

	routeExcludeAddrs, err := ParsePrefixes(t.config.RouteExcludeAddress)
	if err != nil {
		return RouteOptions{}, errors.New("invalid route_exclude_address").Base(err)
	}

	inet4Addr, err := ParseAddress(t.config.Inet4Address)
	if err != nil {
		return RouteOptions{}, errors.New("invalid inet4_address").Base(err)
	}

	inet6Addr, err := ParseAddress(t.config.Inet6Address)
	if err != nil {
		return RouteOptions{}, errors.New("invalid inet6_address").Base(err)
	}

	return RouteOptions{
		InterfaceName:       t.config.Name,
		AutoRoute:           t.config.AutoRoute,
		RouteAddress:        routeAddrs,
		RouteExcludeAddress: routeExcludeAddrs,
		StrictRoute:         t.config.StrictRoute,
		TableIndex:          int(t.config.TableIndex),
		Inet4Address:        inet4Addr,
		Inet6Address:        inet6Addr,
		DisableDNSHijack:    t.config.DisableDnsHijack,
	}, nil
}

// HandleConnection pass the connection coming from the ip stack to the routing dispatcher
func (t *Handler) HandleConnection(conn net.Conn, destination net.Destination) {
	// when handling is done with any outcome, always signal back to the incoming connection
	// to close, send completion packets back to the network, and cleanup
	defer conn.Close()

	sid := session.NewID()
	ctx := c.ContextWithID(t.ctx, sid)

	source := net.DestinationFromAddr(conn.RemoteAddr())
	inbound := session.Inbound{
		Name:          "tun",
		Tag:           t.tag,
		CanSpliceCopy: 3,
		Source:        source,
		User: &protocol.MemoryUser{
			Level: t.config.UserLevel,
		},
	}

	ctx = session.ContextWithInbound(ctx, &inbound)
	ctx = session.ContextWithContent(ctx, &session.Content{
		SniffingRequest: t.sniffingRequest,
	})
	ctx = session.SubContextFromMuxInbound(ctx)

	ctx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
		From:   inbound.Source,
		To:     destination,
		Status: log.AccessAccepted,
		Reason: "",
	})
	errors.LogInfo(ctx, "processing from ", source, " to ", destination)

	link := &transport.Link{
		Reader: &buf.TimeoutWrapperReader{Reader: buf.NewReader(conn)},
		Writer: buf.NewWriter(conn),
	}
	if err := t.dispatcher.DispatchLink(ctx, destination, link); err != nil {
		errors.LogError(ctx, errors.New("connection closed").Base(err))
	}
}

// Network implements proxy.Inbound
// and exists only to comply to proxy interface, declaring it doesn't listen on any network,
// making the process not open any port for this inbound (input will be network interface)
func (t *Handler) Network() []net.Network {
	return []net.Network{}
}

// Process implements proxy.Inbound
// and exists only to comply to proxy interface, which should never get any inputs due to no listening ports
func (t *Handler) Process(ctx context.Context, network net.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	return nil
}

// Close implements common.Closable
func (t *Handler) Close() error {
	// Clean up routes first (before closing the TUN interface)
	if t.routeManager != nil {
		if err := t.routeManager.UnsetRoutes(); err != nil {
			errors.LogWarning(t.ctx, "failed to unset routes: ", err)
		}
		if err := t.routeManager.Close(); err != nil {
			errors.LogWarning(t.ctx, "failed to close route manager: ", err)
		}
		t.routeManager = nil
	}

	// Close the stack
	if t.stack != nil {
		_ = t.stack.Close()
		t.stack = nil
	}

	// Close the TUN interface
	if t.tun != nil {
		_ = t.tun.Close()
		t.tun = nil
	}

	errors.LogInfo(t.ctx, "TUN handler closed")
	return nil
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		t := &Handler{config: config.(*Config)}
		err := core.RequireFeatures(ctx, func(pm policy.Manager, dispatcher routing.Dispatcher) error {
			return t.Init(ctx, pm, dispatcher)
		})
		return t, err
	}))
}
