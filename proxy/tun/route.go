package tun

import (
	"net/netip"

	"go4.org/netipx"
)

// RouteManager manages system route table for TUN interface
type RouteManager interface {
	// SetRoutes configures routes for TUN interface
	SetRoutes() error
	// UnsetRoutes removes configured routes
	UnsetRoutes() error
	// Close cleans up resources
	Close() error
}

// RouteOptions contains configuration for route management
type RouteOptions struct {
	// InterfaceName is the name of TUN interface
	InterfaceName string
	// InterfaceIndex is the index of TUN interface (set after creation)
	InterfaceIndex int
	// AutoRoute enables automatic route configuration
	AutoRoute bool
	// RouteAddress specifies custom route prefixes
	RouteAddress []netip.Prefix
	// RouteExcludeAddress specifies prefixes to exclude from routing
	RouteExcludeAddress []netip.Prefix
	// StrictRoute enables strict routing mode
	StrictRoute bool
	// TableIndex specifies the routing table index (Linux only, 0 = auto)
	TableIndex int
	// Inet4Address is the IPv4 address for TUN interface
	Inet4Address netip.Prefix
	// Inet6Address is the IPv6 address for TUN interface
	Inet6Address netip.Prefix
	// DisableDNSHijack disables DNS leak prevention (Windows only)
	DisableDNSHijack bool
}

// Default TUN interface addresses
var (
	DefaultInet4Address = netip.MustParsePrefix("172.19.0.1/30")
	DefaultInet6Address = netip.MustParsePrefix("fdfe:dcba:9876::1/126")
)

// Default split routes - these avoid replacing the system default route directly
// by using two more specific routes that together cover all addresses
var (
	// IPv4 split routes: 0.0.0.0/1 and 128.0.0.0/1
	DefaultIPv4Routes = []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/1"),
		netip.MustParsePrefix("128.0.0.0/1"),
	}
	// IPv6 split routes: ::/1 and 8000::/1
	DefaultIPv6Routes = []netip.Prefix{
		netip.MustParsePrefix("::/1"),
		netip.MustParsePrefix("8000::/1"),
	}
)

// BuildRouteRanges builds the final route prefixes by combining include and exclude addresses
func BuildRouteRanges(includeAddresses, excludeAddresses []netip.Prefix) ([]netip.Prefix, error) {
	if len(includeAddresses) == 0 {
		// Use default split routes if no custom routes specified
		includeAddresses = append(DefaultIPv4Routes, DefaultIPv6Routes...)
	}

	if len(excludeAddresses) == 0 {
		return includeAddresses, nil
	}

	// Build IP set from include addresses
	var builder netipx.IPSetBuilder
	for _, prefix := range includeAddresses {
		builder.AddPrefix(prefix)
	}

	// Remove exclude addresses
	for _, prefix := range excludeAddresses {
		builder.RemovePrefix(prefix)
	}

	set, err := builder.IPSet()
	if err != nil {
		return nil, err
	}

	return set.Prefixes(), nil
}

// ParsePrefixes parses a slice of CIDR strings into netip.Prefix slice
func ParsePrefixes(cidrs []string) ([]netip.Prefix, error) {
	if len(cidrs) == 0 {
		return nil, nil
	}

	prefixes := make([]netip.Prefix, 0, len(cidrs))
	for _, cidr := range cidrs {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return nil, err
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes, nil
}

// ParseAddress parses an address string (with or without prefix length)
func ParseAddress(addr string) (netip.Prefix, error) {
	if addr == "" {
		return netip.Prefix{}, nil
	}

	// Try parsing as prefix first (with /xx)
	prefix, err := netip.ParsePrefix(addr)
	if err == nil {
		return prefix, nil
	}

	// Try parsing as address (without /xx), add default prefix length
	ip, err := netip.ParseAddr(addr)
	if err != nil {
		return netip.Prefix{}, err
	}

	if ip.Is4() {
		return netip.PrefixFrom(ip, 32), nil
	}
	return netip.PrefixFrom(ip, 128), nil
}

// SplitPrefixesByFamily separates prefixes into IPv4 and IPv6 groups
func SplitPrefixesByFamily(prefixes []netip.Prefix) (ipv4, ipv6 []netip.Prefix) {
	for _, prefix := range prefixes {
		if prefix.Addr().Is4() {
			ipv4 = append(ipv4, prefix)
		} else {
			ipv6 = append(ipv6, prefix)
		}
	}
	return
}

// noopRouteManager is a no-op implementation for when auto-route is disabled or unsupported
type noopRouteManager struct{}

func (m *noopRouteManager) SetRoutes() error   { return nil }
func (m *noopRouteManager) UnsetRoutes() error { return nil }
func (m *noopRouteManager) Close() error       { return nil }
