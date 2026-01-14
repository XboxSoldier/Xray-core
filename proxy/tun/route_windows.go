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

// MIB_UNICASTIPADDRESS_ROW represents a unicast IP address entry
type MIB_UNICASTIPADDRESS_ROW struct {
	Address            SOCKADDR_INET
	InterfaceLuid      LUID
	InterfaceIndex     uint32
	PrefixOrigin       uint32
	SuffixOrigin       uint32
	ValidLifetime      uint32
	PreferredLifetime  uint32
	OnLinkPrefixLength uint8
	SkipAsSource       uint8
	DadState           uint32
	ScopeId            uint32
	CreationTimeStamp  uint64
}

// windowsRouteManager implements RouteManager for Windows
type windowsRouteManager struct {
	ctx           context.Context
	options       RouteOptions
	luid          LUID
	routes        []MIB_IPFORWARD_ROW2
	wfpManager    *wfpManager
	configuredIPs []SOCKADDR_INET
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
	// Enable process protection FIRST - this prevents traffic loop
	// by excluding xray's own traffic from TUN routing
	if m.wfpManager != nil {
		if err := m.wfpManager.EnableProcessProtection(); err != nil {
			errors.LogWarning(m.ctx, "failed to enable process protection: ", err)
		}
	}

	// Configure IP addresses
	if err := m.configureIPAddresses(); err != nil {
		return fmt.Errorf("failed to configure IP addresses: %w", err)
	}

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
	if m.wfpManager != nil && !m.options.DisableDNSHijack {
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

// configureIPAddresses sets up IP addresses on the TUN interface
func (m *windowsRouteManager) configureIPAddresses() error {
	// Configure IPv4 address
	inet4Addr := m.options.Inet4Address
	if !inet4Addr.IsValid() {
		inet4Addr = DefaultInet4Address
	}
	if inet4Addr.IsValid() {
		if err := m.addIPAddress(inet4Addr); err != nil {
			return fmt.Errorf("failed to add IPv4 address %s: %w", inet4Addr, err)
		}
		errors.LogInfo(m.ctx, "configured IPv4 address ", inet4Addr, " on TUN interface")
	}

	// Configure IPv6 address
	inet6Addr := m.options.Inet6Address
	if !inet6Addr.IsValid() {
		inet6Addr = DefaultInet6Address
	}
	if inet6Addr.IsValid() {
		if err := m.addIPAddress(inet6Addr); err != nil {
			// IPv6 may not be available, just log warning
			errors.LogWarning(m.ctx, "failed to add IPv6 address ", inet6Addr, ": ", err)
		} else {
			errors.LogInfo(m.ctx, "configured IPv6 address ", inet6Addr, " on TUN interface")
		}
	}

	return nil
}

// addIPAddress adds an IP address to the TUN interface
func (m *windowsRouteManager) addIPAddress(prefix netip.Prefix) error {
	var row MIB_UNICASTIPADDRESS_ROW

	// Initialize the row
	procInitializeUnicastIpAddressRow.Call(uintptr(unsafe.Pointer(&row)))

	row.InterfaceLuid = m.luid
	row.OnLinkPrefixLength = uint8(prefix.Bits())
	row.PrefixOrigin = 1  // IpPrefixOriginManual
	row.SuffixOrigin = 1  // IpSuffixOriginManual
	row.ValidLifetime = 0xFFFFFFFF
	row.PreferredLifetime = 0xFFFFFFFF
	row.SkipAsSource = 0

	addr := prefix.Addr()
	if addr.Is4() {
		row.Address.Family = windows.AF_INET
		copy(row.Address.Data[2:6], addr.AsSlice())
	} else {
		row.Address.Family = windows.AF_INET6
		copy(row.Address.Data[6:22], addr.AsSlice())
	}

	ret, _, _ := procCreateUnicastIpAddressEntry.Call(uintptr(unsafe.Pointer(&row)))
	if ret != 0 && ret != uintptr(windows.ERROR_OBJECT_ALREADY_EXISTS) {
		return fmt.Errorf("CreateUnicastIpAddressEntry failed: error code %d", ret)
	}

	m.configuredIPs = append(m.configuredIPs, row.Address)
	return nil
}

// unconfigureIPAddresses removes IP addresses from the TUN interface
func (m *windowsRouteManager) unconfigureIPAddresses() error {
	var errs []error
	for _, addr := range m.configuredIPs {
		var row MIB_UNICASTIPADDRESS_ROW
		procInitializeUnicastIpAddressRow.Call(uintptr(unsafe.Pointer(&row)))
		row.InterfaceLuid = m.luid
		row.Address = addr

		ret, _, _ := procDeleteUnicastIpAddressEntry.Call(uintptr(unsafe.Pointer(&row)))
		if ret != 0 && ret != uintptr(windows.ERROR_NOT_FOUND) {
			errs = append(errs, fmt.Errorf("DeleteUnicastIpAddressEntry failed: error code %d", ret))
		}
	}
	m.configuredIPs = nil

	if len(errs) > 0 {
		return fmt.Errorf("errors during IP address cleanup: %v", errs)
	}
	return nil
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

	// Remove IP addresses
	if err := m.unconfigureIPAddresses(); err != nil {
		errs = append(errs, err)
	}

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
