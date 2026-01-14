//go:build windows

package tun

import (
	"context"
	"fmt"
	"net/netip"
	"unsafe"

	"github.com/xtls/xray-core/common/errors"
	"golang.org/x/sys/windows"
)

// LUID represents a locally unique identifier for a network interface
type LUID uint64

// MIB_IPFORWARD_ROW2 represents a route entry
type MIB_IPFORWARD_ROW2 struct {
	InterfaceLuid        LUID
	InterfaceIndex       uint32
	DestinationPrefix    IP_ADDRESS_PREFIX
	NextHop              SOCKADDR_INET
	SitePrefixLength     uint8
	ValidLifetime        uint32
	PreferredLifetime    uint32
	Metric               uint32
	Protocol             uint32
	Loopback             uint8
	AutoconfigureAddress uint8
	Publish              uint8
	Immortal             uint8
	Age                  uint32
	Origin               uint32
}

// IP_ADDRESS_PREFIX represents an IP address prefix
type IP_ADDRESS_PREFIX struct {
	Prefix       SOCKADDR_INET
	PrefixLength uint8
	_            [3]byte // padding
}

// SOCKADDR_INET is a union type for IPv4/IPv6 socket addresses
type SOCKADDR_INET struct {
	Family uint16
	Data   [26]byte // Large enough for both IPv4 and IPv6
}

var (
	modiphlpapi = windows.NewLazySystemDLL("iphlpapi.dll")

	procCreateIpForwardEntry2         = modiphlpapi.NewProc("CreateIpForwardEntry2")
	procDeleteIpForwardEntry2         = modiphlpapi.NewProc("DeleteIpForwardEntry2")
	procInitializeIpForwardEntry      = modiphlpapi.NewProc("InitializeIpForwardEntry")
	procConvertInterfaceAliasToLuid   = modiphlpapi.NewProc("ConvertInterfaceAliasToLuid")
	procConvertInterfaceIndexToLuid   = modiphlpapi.NewProc("ConvertInterfaceIndexToLuid")
	procConvertInterfaceLuidToIndex   = modiphlpapi.NewProc("ConvertInterfaceLuidToIndex")
	procGetUnicastIpAddressTable      = modiphlpapi.NewProc("GetUnicastIpAddressTable")
	procCreateUnicastIpAddressEntry   = modiphlpapi.NewProc("CreateUnicastIpAddressEntry")
	procDeleteUnicastIpAddressEntry   = modiphlpapi.NewProc("DeleteUnicastIpAddressEntry")
	procInitializeUnicastIpAddressRow = modiphlpapi.NewProc("InitializeUnicastIpAddressRow")
	procFreeMibTable                  = modiphlpapi.NewProc("FreeMibTable")
)

// windowsRouteManager implements RouteManager for Windows
type windowsRouteManager struct {
	ctx        context.Context
	options    RouteOptions
	luid       LUID
	routes     []MIB_IPFORWARD_ROW2
	wfpManager *wfpManager
}

// NewRouteManager creates a new RouteManager for Windows
func NewRouteManager(ctx context.Context, options RouteOptions) (RouteManager, error) {
	if !options.AutoRoute {
		return &noopRouteManager{}, nil
	}

	// Use provided LUID or look up by name
	var luid LUID
	if options.InterfaceLUID != 0 {
		luid = LUID(options.InterfaceLUID)
		errors.LogDebug(ctx, "using provided interface LUID: ", options.InterfaceLUID)
	} else {
		var err error
		luid, err = getInterfaceLUID(options.InterfaceName)
		if err != nil {
			return nil, fmt.Errorf("failed to get interface LUID: %w", err)
		}
	}

	m := &windowsRouteManager{
		ctx:     ctx,
		options: options,
		luid:    luid,
	}

	// Initialize WFP manager for DNS leak prevention
	if !options.DisableDNSHijack {
		wfp, err := newWFPManager(ctx, luid)
		if err != nil {
			errors.LogWarning(ctx, "failed to initialize WFP manager: ", err)
		} else {
			m.wfpManager = wfp
		}
	}

	return m, nil
}

// SetRoutes configures routes for TUN interface
func (m *windowsRouteManager) SetRoutes() error {
	// Build route prefixes
	routePrefixes, err := BuildRouteRanges(m.options.RouteAddress, m.options.RouteExcludeAddress)
	if err != nil {
		return fmt.Errorf("failed to build route ranges: %w", err)
	}

	// Get interface index for logging
	var ifIndex uint32
	procConvertInterfaceLuidToIndex.Call(uintptr(m.luid), uintptr(unsafe.Pointer(&ifIndex)))

	// Add routes
	for _, prefix := range routePrefixes {
		route, err := m.createRoute(prefix)
		if err != nil {
			return fmt.Errorf("failed to create route for %s: %w", prefix, err)
		}

		ret, _, _ := procCreateIpForwardEntry2.Call(uintptr(unsafe.Pointer(&route)))
		if ret != 0 && ret != uintptr(windows.ERROR_OBJECT_ALREADY_EXISTS) {
			return fmt.Errorf("failed to add route %s: error code %d", prefix, ret)
		}

		m.routes = append(m.routes, route)
	}

	// Enable DNS leak prevention
	if m.wfpManager != nil {
		if err := m.wfpManager.EnableDNSProtection(); err != nil {
			errors.LogWarning(m.ctx, "failed to enable DNS protection: ", err)
		}
	}

	errors.LogInfo(m.ctx, "auto-route configured for ", m.options.InterfaceName,
		" with ", len(m.routes), " routes")

	return nil
}

// createRoute creates a MIB_IPFORWARD_ROW2 for the given prefix
func (m *windowsRouteManager) createRoute(prefix netip.Prefix) (MIB_IPFORWARD_ROW2, error) {
	var row MIB_IPFORWARD_ROW2

	// Initialize the row
	procInitializeIpForwardEntry.Call(uintptr(unsafe.Pointer(&row)))

	row.InterfaceLuid = m.luid
	row.DestinationPrefix = prefixToAddressPrefix(prefix)
	row.NextHop = getGatewayAddress(prefix.Addr().Is4())
	row.Metric = 0   // Use automatic metric
	row.Protocol = 3 // MIB_IPPROTO_NETMGMT

	return row, nil
}

// UnsetRoutes removes configured routes
func (m *windowsRouteManager) UnsetRoutes() error {
	var errs []error

	// Disable DNS protection first
	if m.wfpManager != nil {
		if err := m.wfpManager.DisableDNSProtection(); err != nil {
			errs = append(errs, fmt.Errorf("failed to disable DNS protection: %w", err))
		}
	}

	// Remove routes in reverse order
	for i := len(m.routes) - 1; i >= 0; i-- {
		ret, _, _ := procDeleteIpForwardEntry2.Call(uintptr(unsafe.Pointer(&m.routes[i])))
		if ret != 0 && ret != uintptr(windows.ERROR_NOT_FOUND) {
			errs = append(errs, fmt.Errorf("failed to delete route: error code %d", ret))
		}
	}
	m.routes = nil

	if len(errs) > 0 {
		return fmt.Errorf("errors during route cleanup: %v", errs)
	}

	errors.LogInfo(m.ctx, "auto-route cleaned up for ", m.options.InterfaceName)
	return nil
}

// Close cleans up resources
func (m *windowsRouteManager) Close() error {
	if m.wfpManager != nil {
		m.wfpManager.Close()
		m.wfpManager = nil
	}
	return nil
}

// getInterfaceLUID gets the LUID for an interface by name
func getInterfaceLUID(name string) (LUID, error) {
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}

	var luid LUID
	ret, _, _ := procConvertInterfaceAliasToLuid.Call(
		uintptr(unsafe.Pointer(namePtr)),
		uintptr(unsafe.Pointer(&luid)),
	)
	if ret != 0 {
		return 0, fmt.Errorf("ConvertInterfaceAliasToLuid failed: %d", ret)
	}

	return luid, nil
}

// prefixToAddressPrefix converts netip.Prefix to IP_ADDRESS_PREFIX
func prefixToAddressPrefix(prefix netip.Prefix) IP_ADDRESS_PREFIX {
	var ap IP_ADDRESS_PREFIX
	ap.PrefixLength = uint8(prefix.Bits())

	addr := prefix.Addr()
	if addr.Is4() {
		ap.Prefix.Family = windows.AF_INET
		copy(ap.Prefix.Data[2:6], addr.AsSlice())
	} else {
		ap.Prefix.Family = windows.AF_INET6
		copy(ap.Prefix.Data[6:22], addr.AsSlice())
	}

	return ap
}

// getGatewayAddress returns an empty gateway address (on-link route)
func getGatewayAddress(isIPv4 bool) SOCKADDR_INET {
	var sa SOCKADDR_INET
	if isIPv4 {
		sa.Family = windows.AF_INET
	} else {
		sa.Family = windows.AF_INET6
	}
	return sa
}
