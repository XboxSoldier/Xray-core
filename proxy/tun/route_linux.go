//go:build linux && !android

package tun

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"

	"github.com/vishvananda/netlink"
	"github.com/xtls/xray-core/common/errors"
	"golang.org/x/sys/unix"
)

const (
	// Default routing table index for TUN auto-route
	defaultTableIndex = 2024
	// Default rule priority
	defaultRulePriority = 9000
)

var (
	tableIndexCounter = defaultTableIndex
	tableIndexMutex   sync.Mutex
)

// allocateTableIndex allocates a unique routing table index
func allocateTableIndex() int {
	tableIndexMutex.Lock()
	defer tableIndexMutex.Unlock()
	idx := tableIndexCounter
	tableIndexCounter++
	return idx
}

// linuxRouteManager implements RouteManager for Linux
type linuxRouteManager struct {
	ctx     context.Context
	handle  *netlink.Handle
	link    netlink.Link
	options RouteOptions
	routes  []*netlink.Route
	rules   []*netlink.Rule
	addrs   []netlink.Addr
}

// NewRouteManager creates a new RouteManager for Linux
func NewRouteManager(ctx context.Context, options RouteOptions) (RouteManager, error) {
	if !options.AutoRoute {
		return &noopRouteManager{}, nil
	}

	handle, err := netlink.NewHandle()
	if err != nil {
		return nil, fmt.Errorf("failed to create netlink handle: %w", err)
	}

	link, err := netlink.LinkByName(options.InterfaceName)
	if err != nil {
		handle.Close()
		return nil, fmt.Errorf("failed to find link %s: %w", options.InterfaceName, err)
	}

	options.InterfaceIndex = link.Attrs().Index

	// Allocate table index if not specified
	if options.TableIndex == 0 {
		options.TableIndex = allocateTableIndex()
	}

	m := &linuxRouteManager{
		ctx:     ctx,
		handle:  handle,
		link:    link,
		options: options,
	}

	return m, nil
}

// SetRoutes configures routes for TUN interface
func (m *linuxRouteManager) SetRoutes() error {
	// Configure TUN interface address if specified
	if err := m.setupAddresses(); err != nil {
		return err
	}

	// Disable reverse path filter for TUN interface
	if err := m.disableRPFilter(); err != nil {
		errors.LogWarning(m.ctx, "failed to disable rp_filter: ", err)
	}

	// Build route prefixes
	routePrefixes, err := BuildRouteRanges(m.options.RouteAddress, m.options.RouteExcludeAddress)
	if err != nil {
		return fmt.Errorf("failed to build route ranges: %w", err)
	}

	// Add routes
	if err := m.addRoutes(routePrefixes); err != nil {
		return err
	}

	// Add policy routing rules
	if err := m.addRules(); err != nil {
		return err
	}

	errors.LogInfo(m.ctx, "auto-route configured for ", m.options.InterfaceName,
		" with ", len(m.routes), " routes and ", len(m.rules), " rules")

	return nil
}

// setupAddresses configures IP addresses on TUN interface
func (m *linuxRouteManager) setupAddresses() error {
	inet4 := m.options.Inet4Address
	inet6 := m.options.Inet6Address

	// Use defaults if not specified
	if !inet4.IsValid() {
		inet4 = DefaultInet4Address
	}
	if !inet6.IsValid() {
		inet6 = DefaultInet6Address
	}

	// Add IPv4 address
	if inet4.IsValid() {
		addr := netlink.Addr{
			IPNet: prefixToIPNet(inet4),
		}
		if err := m.handle.AddrAdd(m.link, &addr); err != nil {
			if !os.IsExist(err) {
				return fmt.Errorf("failed to add IPv4 address: %w", err)
			}
		}
		m.addrs = append(m.addrs, addr)
	}

	// Add IPv6 address
	if inet6.IsValid() {
		addr := netlink.Addr{
			IPNet: prefixToIPNet(inet6),
		}
		if err := m.handle.AddrAdd(m.link, &addr); err != nil {
			if !os.IsExist(err) {
				return fmt.Errorf("failed to add IPv6 address: %w", err)
			}
		}
		m.addrs = append(m.addrs, addr)
	}

	return nil
}

// disableRPFilter disables reverse path filtering for TUN interface
func (m *linuxRouteManager) disableRPFilter() error {
	paths := []string{
		"/proc/sys/net/ipv4/conf/all/rp_filter",
		"/proc/sys/net/ipv4/conf/" + m.options.InterfaceName + "/rp_filter",
	}

	for _, path := range paths {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			continue
		}
		if err := os.WriteFile(path, []byte("0"), 0o644); err != nil {
			return fmt.Errorf("failed to write %s: %w", path, err)
		}
	}

	return nil
}

// addRoutes adds routes to the routing table
func (m *linuxRouteManager) addRoutes(prefixes []netip.Prefix) error {
	for _, prefix := range prefixes {
		route := &netlink.Route{
			LinkIndex: m.options.InterfaceIndex,
			Dst:       prefixToIPNet(prefix),
			Table:     m.options.TableIndex,
			Scope:     netlink.SCOPE_UNIVERSE,
		}

		if err := m.handle.RouteAdd(route); err != nil {
			if !os.IsExist(err) {
				return fmt.Errorf("failed to add route %s: %w", prefix, err)
			}
		}
		m.routes = append(m.routes, route)
	}

	return nil
}

// addRules adds policy routing rules
func (m *linuxRouteManager) addRules() error {
	// Add IPv4 rule
	rule4 := netlink.NewRule()
	rule4.Table = m.options.TableIndex
	rule4.Family = unix.AF_INET
	rule4.Priority = defaultRulePriority

	if err := m.handle.RuleAdd(rule4); err != nil {
		if !os.IsExist(err) {
			return fmt.Errorf("failed to add IPv4 rule: %w", err)
		}
	}
	m.rules = append(m.rules, rule4)

	// Add IPv6 rule
	rule6 := netlink.NewRule()
	rule6.Table = m.options.TableIndex
	rule6.Family = unix.AF_INET6
	rule6.Priority = defaultRulePriority

	if err := m.handle.RuleAdd(rule6); err != nil {
		if !os.IsExist(err) {
			return fmt.Errorf("failed to add IPv6 rule: %w", err)
		}
	}
	m.rules = append(m.rules, rule6)

	// If strict route is enabled, add suppress rules
	if m.options.StrictRoute {
		if err := m.addSuppressRules(); err != nil {
			return err
		}
	}

	return nil
}

// addSuppressRules adds suppress_prefixlength rules for strict routing
func (m *linuxRouteManager) addSuppressRules() error {
	// Suppress rules with lower priority to handle local traffic
	suppressRule4 := netlink.NewRule()
	suppressRule4.Table = unix.RT_TABLE_MAIN
	suppressRule4.Family = unix.AF_INET
	suppressRule4.Priority = defaultRulePriority - 1
	suppressRule4.SuppressPrefixlen = 0

	if err := m.handle.RuleAdd(suppressRule4); err != nil {
		if !os.IsExist(err) {
			return fmt.Errorf("failed to add IPv4 suppress rule: %w", err)
		}
	}
	m.rules = append(m.rules, suppressRule4)

	suppressRule6 := netlink.NewRule()
	suppressRule6.Table = unix.RT_TABLE_MAIN
	suppressRule6.Family = unix.AF_INET6
	suppressRule6.Priority = defaultRulePriority - 1
	suppressRule6.SuppressPrefixlen = 0

	if err := m.handle.RuleAdd(suppressRule6); err != nil {
		if !os.IsExist(err) {
			return fmt.Errorf("failed to add IPv6 suppress rule: %w", err)
		}
	}
	m.rules = append(m.rules, suppressRule6)

	return nil
}

// UnsetRoutes removes configured routes
func (m *linuxRouteManager) UnsetRoutes() error {
	var errs []error

	// Remove rules in reverse order
	for i := len(m.rules) - 1; i >= 0; i-- {
		if err := m.handle.RuleDel(m.rules[i]); err != nil {
			errs = append(errs, fmt.Errorf("failed to delete rule: %w", err))
		}
	}
	m.rules = nil

	// Remove routes in reverse order
	for i := len(m.routes) - 1; i >= 0; i-- {
		if err := m.handle.RouteDel(m.routes[i]); err != nil {
			errs = append(errs, fmt.Errorf("failed to delete route %s: %w", m.routes[i].Dst, err))
		}
	}
	m.routes = nil

	// Remove addresses
	for _, addr := range m.addrs {
		if err := m.handle.AddrDel(m.link, &addr); err != nil {
			// Ignore errors for address removal as they may already be gone
			errors.LogDebug(m.ctx, "failed to delete address: ", err)
		}
	}
	m.addrs = nil

	if len(errs) > 0 {
		return fmt.Errorf("errors during route cleanup: %v", errs)
	}

	errors.LogInfo(m.ctx, "auto-route cleaned up for ", m.options.InterfaceName)
	return nil
}

// Close cleans up resources
func (m *linuxRouteManager) Close() error {
	if m.handle != nil {
		m.handle.Close()
		m.handle = nil
	}
	return nil
}

// prefixToIPNet converts netip.Prefix to *net.IPNet
func prefixToIPNet(prefix netip.Prefix) *net.IPNet {
	return &net.IPNet{
		IP:   prefix.Addr().AsSlice(),
		Mask: net.CIDRMask(prefix.Bits(), prefix.Addr().BitLen()),
	}
}
