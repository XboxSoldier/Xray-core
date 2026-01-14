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
	_                    [3]byte // padding for 4-byte alignment of ValidLifetime
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

// ScopeLevelCount is the number of scope levels
const ScopeLevelCount = 16

var (
	modiphlpapi = windows.NewLazySystemDLL("iphlpapi.dll")

	procCreateIpForwardEntry2       = modiphlpapi.NewProc("CreateIpForwardEntry2")
	procDeleteIpForwardEntry2       = modiphlpapi.NewProc("DeleteIpForwardEntry2")
	procConvertInterfaceAliasToLuid = modiphlpapi.NewProc("ConvertInterfaceAliasToLuid")
	procConvertInterfaceIndexToLuid = modiphlpapi.NewProc("ConvertInterfaceIndexToLuid")
	procConvertInterfaceLuidToIndex = modiphlpapi.NewProc("ConvertInterfaceLuidToIndex")
	procGetUnicastIpAddressTable    = modiphlpapi.NewProc("GetUnicastIpAddressTable")
	procCreateUnicastIpAddressEntry = modiphlpapi.NewProc("CreateUnicastIpAddressEntry")
	procDeleteUnicastIpAddressEntry = modiphlpapi.NewProc("DeleteUnicastIpAddressEntry")
	procFreeMibTable                = modiphlpapi.NewProc("FreeMibTable")
	procGetIpInterfaceEntry         = modiphlpapi.NewProc("GetIpInterfaceEntry")
	procSetIpInterfaceEntry         = modiphlpapi.NewProc("SetIpInterfaceEntry")
	procInitializeIpInterfaceEntry  = modiphlpapi.NewProc("InitializeIpInterfaceEntry")
)

// MIB_UNICASTIPADDRESS_ROW represents a unicast IP address entry
type MIB_UNICASTIPADDRESS_ROW struct {
	Address            SOCKADDR_INET
	_                  [4]byte // padding for 8-byte alignment of InterfaceLuid
	InterfaceLuid      LUID
	InterfaceIndex     uint32
	PrefixOrigin       uint32
	SuffixOrigin       uint32
	ValidLifetime      uint32
	PreferredLifetime  uint32
	OnLinkPrefixLength uint8
	SkipAsSource       uint8
	_2                 [2]byte // padding for 4-byte alignment of DadState
	DadState           uint32
	ScopeId            uint32
	CreationTimeStamp  uint64
}

// MIB_IPINTERFACE_ROW represents IP interface management information
// Reference: https://learn.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-mib_ipinterface_row
type MIB_IPINTERFACE_ROW struct {
	Family                               uint16
	_1                                   [6]byte // padding for 8-byte alignment of InterfaceLuid
	InterfaceLuid                        LUID
	InterfaceIndex                       uint32
	MaxReassemblySize                    uint32
	InterfaceIdentifier                  uint64
	MinRouterAdvertisementInterval       uint32
	MaxRouterAdvertisementInterval       uint32
	AdvertisingEnabled                   uint8
	ForwardingEnabled                    uint8
	WeakHostSend                         uint8
	WeakHostReceive                      uint8
	UseAutomaticMetric                   uint8
	UseNeighborUnreachabilityDetection   uint8
	ManagedAddressConfigurationSupported uint8
	OtherStatefulConfigurationSupported  uint8
	AdvertiseDefaultRoute                uint8
	_2                                   [3]byte // padding for 4-byte alignment of RouterDiscoveryBehavior
	RouterDiscoveryBehavior              uint32  // NL_ROUTER_DISCOVERY_BEHAVIOR enum
	DadTransmits                         uint32
	BaseReachableTime                    uint32
	RetransmitTime                       uint32
	PathMtuDiscoveryTimeout              uint32
	LinkLocalAddressBehavior             uint32 // NL_LINK_LOCAL_ADDRESS_BEHAVIOR enum
	LinkLocalAddressTimeout              uint32
	ZoneIndices                          [ScopeLevelCount]uint32
	SitePrefixLength                     uint32
	Metric                               uint32
	NlMtu                                uint32
	Connected                            uint8
	SupportsWakeUpPatterns               uint8
	SupportsNeighborDiscovery            uint8
	SupportsRouterDiscovery              uint8
	ReachableTime                        uint32
	// NL_INTERFACE_OFFLOAD_ROD TransmitOffload (12 bytes)
	TransmitOffload [12]byte
	// NL_INTERFACE_OFFLOAD_ROD ReceiveOffload (12 bytes)
	ReceiveOffload [12]byte
	// Windows Vista+ only:
	DisableDefaultRoutes uint8
	_3                   [3]byte // padding to 4-byte boundary
}

// windowsRouteManager implements RouteManager for Windows
type windowsRouteManager struct {
	ctx           context.Context
	options       RouteOptions
	luid          LUID
	ifIndex       uint32
	routes        []MIB_IPFORWARD_ROW2
	wfpManager    *wfpManager
	configuredIPs []SOCKADDR_INET
}

// NewRouteManager creates a new RouteManager for Windows
func NewRouteManager(ctx context.Context, options RouteOptions) (RouteManager, error) {
	errors.LogInfo(ctx, "NewRouteManager called for Windows, AutoRoute=", options.AutoRoute)

	if !options.AutoRoute {
		return &noopRouteManager{}, nil
	}

	// Use provided LUID or look up by name
	var luid LUID
	if options.InterfaceLUID != 0 {
		luid = LUID(options.InterfaceLUID)
		errors.LogDebug(ctx, "using provided interface LUID: ", options.InterfaceLUID)
	} else {
		errors.LogDebug(ctx, "looking up LUID for interface: ", options.InterfaceName)
		var err error
		luid, err = getInterfaceLUID(options.InterfaceName)
		if err != nil {
			return nil, fmt.Errorf("failed to get interface LUID: %w", err)
		}
	}

	// Get interface index from LUID
	var ifIndex uint32
	ret, _, _ := procConvertInterfaceLuidToIndex.Call(uintptr(unsafe.Pointer(&luid)), uintptr(unsafe.Pointer(&ifIndex)))
	if ret != 0 {
		errors.LogWarning(ctx, "ConvertInterfaceLuidToIndex failed: ", ret)
	}
	errors.LogDebug(ctx, "TUN interface LUID=", luid, " Index=", ifIndex)

	m := &windowsRouteManager{
		ctx:     ctx,
		options: options,
		luid:    luid,
		ifIndex: ifIndex,
	}

	// WFP is currently disabled due to struct layout issues with Windows API
	// Users should add their proxy server IP to routeExcludeAddress to prevent traffic loops
	// TODO: Fix WFP struct layouts and re-enable
	errors.LogInfo(ctx, "WFP is disabled - add proxy server IP to routeExcludeAddress to prevent loops")

	// Initialize WFP manager for process protection and DNS leak prevention (experimental)
	// errors.LogDebug(ctx, "initializing WFP manager, DisableDNSHijack=", options.DisableDNSHijack)
	// if !options.DisableDNSHijack {
	// 	wfp, err := newWFPManager(ctx, luid)
	// 	if err != nil {
	// 		errors.LogWarning(ctx, "failed to initialize WFP manager: ", err)
	// 	} else {
	// 		m.wfpManager = wfp
	// 		errors.LogInfo(ctx, "WFP manager initialized successfully")
	// 	}
	// }

	return m, nil
}

// SetRoutes configures routes for TUN interface
func (m *windowsRouteManager) SetRoutes() error {
	errors.LogDebug(m.ctx, "SetRoutes called, wfpManager=", m.wfpManager != nil)

	// Enable process protection FIRST - this prevents traffic loop
	// by excluding xray's own traffic from TUN routing
	if m.wfpManager != nil {
		errors.LogDebug(m.ctx, "enabling WFP process protection...")
		if err := m.wfpManager.EnableProcessProtection(); err != nil {
			errors.LogWarning(m.ctx, "failed to enable process protection: ", err)
		}
	} else {
		errors.LogWarning(m.ctx, "wfpManager is nil, process protection disabled!")
	}

	// Configure IP addresses
	if err := m.configureIPAddresses(); err != nil {
		return fmt.Errorf("failed to configure IP addresses: %w", err)
	}

	// Set interface metric to 0 (highest priority) for both IPv4 and IPv6
	// This is critical: Windows route preference = route metric + interface metric
	// Without this, TUN routes may not take priority over other interfaces
	if err := m.setInterfaceMetric(windows.AF_INET); err != nil {
		errors.LogWarning(m.ctx, "failed to set IPv4 interface metric: ", err)
	}
	if err := m.setInterfaceMetric(windows.AF_INET6); err != nil {
		errors.LogWarning(m.ctx, "failed to set IPv6 interface metric: ", err)
	}

	// Build route prefixes
	routePrefixes, err := BuildRouteRanges(m.options.RouteAddress, m.options.RouteExcludeAddress)
	if err != nil {
		return fmt.Errorf("failed to build route ranges: %w", err)
	}

	// Add routes
	errors.LogInfo(m.ctx, "Adding ", len(routePrefixes), " routes to TUN interface...")
	successCount := 0
	for i, prefix := range routePrefixes {
		route, err := m.createRoute(prefix)
		if err != nil {
			return fmt.Errorf("failed to create route for %s: %w", prefix, err)
		}

		ret, _, _ := procCreateIpForwardEntry2.Call(uintptr(unsafe.Pointer(&route)))
		if ret != 0 && ret != uintptr(windows.ERROR_OBJECT_ALREADY_EXISTS) {
			errors.LogWarning(m.ctx, "failed to add route ", prefix, ": error code ", ret)
			continue // Don't fail on individual route errors
		}

		// Log first few routes for debugging
		if i < 5 {
			errors.LogDebug(m.ctx, "Added route: ", prefix, " metric=", route.Metric, " ret=", ret)
		}

		successCount++
		m.routes = append(m.routes, route)
	}
	errors.LogInfo(m.ctx, "Successfully added ", successCount, "/", len(routePrefixes), " routes")

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
	// Go zero-initializes the struct (equivalent to SDK's InitializeIpForwardEntry inline function)
	var row MIB_IPFORWARD_ROW2

	row.InterfaceLuid = m.luid
	row.InterfaceIndex = m.ifIndex
	row.DestinationPrefix = prefixToAddressPrefix(prefix)

	// Use "On-link" (zero gateway) for point-to-point TUN interface
	// For TUN interfaces, the driver directly receives packets destined to the interface
	// Setting gateway to zero means "send directly to this interface"
	if prefix.Addr().Is4() {
		row.NextHop.Family = windows.AF_INET
		// Data is zero-initialized = 0.0.0.0 (On-link)
	} else {
		row.NextHop.Family = windows.AF_INET6
		// Data is zero-initialized = :: (On-link)
	}

	row.Metric = 0   // Route metric 0 (combined with interface metric 0 = total metric 0)
	row.Protocol = 3 // MIB_IPPROTO_NETMGMT
	row.Origin = 1   // NlroManual

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
	// Go zero-initializes the struct, which is the correct initial state
	var row MIB_UNICASTIPADDRESS_ROW

	row.InterfaceLuid = m.luid
	row.OnLinkPrefixLength = uint8(prefix.Bits())
	row.PrefixOrigin = 1 // IpPrefixOriginManual
	row.SuffixOrigin = 1 // IpSuffixOriginManual
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

// setInterfaceMetric sets a low metric on the TUN interface to ensure TUN routes take priority
// This is critical because Windows route preference = route metric + interface metric
func (m *windowsRouteManager) setInterfaceMetric(family uint16) error {
	var row MIB_IPINTERFACE_ROW

	// Initialize and set key fields for lookup
	row.Family = family
	row.InterfaceLuid = m.luid

	// Get current interface settings
	ret, _, _ := procGetIpInterfaceEntry.Call(uintptr(unsafe.Pointer(&row)))
	if ret != 0 {
		return fmt.Errorf("GetIpInterfaceEntry failed for family %d: error code %d", family, ret)
	}

	// Log current metric settings
	familyStr := "IPv4"
	if family == windows.AF_INET6 {
		familyStr = "IPv6"
	}
	errors.LogDebug(m.ctx, familyStr, " interface - current UseAutomaticMetric=", row.UseAutomaticMetric, " Metric=", row.Metric)

	// Disable automatic metric and set metric to 0 (highest priority)
	row.UseAutomaticMetric = 0 // FALSE
	row.Metric = 0             // Lowest possible metric = highest priority

	// Apply changes
	ret, _, _ = procSetIpInterfaceEntry.Call(uintptr(unsafe.Pointer(&row)))
	if ret != 0 {
		return fmt.Errorf("SetIpInterfaceEntry failed for family %d: error code %d", family, ret)
	}

	errors.LogInfo(m.ctx, familyStr, " interface metric set to 0 (highest priority)")
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
