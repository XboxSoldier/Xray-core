//go:build windows

package tun

import (
	"context"
	"fmt"
	"math"
	"os"
	"unsafe"

	"github.com/xtls/xray-core/common/errors"
	"golang.org/x/sys/windows"
)

// WFP (Windows Filtering Platform) constants
const (
	FWPM_SESSION_FLAG_DYNAMIC = 0x00000001
	RPC_C_AUTHN_DEFAULT       = 0xFFFFFFFF

	FWP_ACTION_BLOCK  = 0x00000001
	FWP_ACTION_PERMIT = 0x00001000

	FWP_MATCH_EQUAL = 0

	// FWP_DATA_TYPE values from Windows SDK
	FWP_EMPTY          = 0 // For auto-weight
	FWP_UINT8          = 1
	FWP_UINT16         = 2
	FWP_UINT32         = 3
	FWP_UINT64         = 4
	FWP_BYTE_BLOB_TYPE = 12
)

// GUIDs for WFP layers and conditions
var (
	FWPM_LAYER_ALE_AUTH_CONNECT_V4 = windows.GUID{
		Data1: 0xc38d57d1,
		Data2: 0x05a7,
		Data3: 0x4c33,
		Data4: [8]byte{0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82},
	}

	FWPM_LAYER_ALE_AUTH_CONNECT_V6 = windows.GUID{
		Data1: 0x4a72393b,
		Data2: 0x319f,
		Data3: 0x44bc,
		Data4: [8]byte{0x84, 0xc3, 0xba, 0x54, 0xdc, 0xb3, 0xb6, 0xb4},
	}

	FWPM_CONDITION_IP_REMOTE_PORT = windows.GUID{
		Data1: 0xc35a604d,
		Data2: 0xd22b,
		Data3: 0x4e1a,
		Data4: [8]byte{0x91, 0xb4, 0x68, 0xf6, 0x74, 0xee, 0x67, 0x4b},
	}

	FWPM_CONDITION_ALE_APP_ID = windows.GUID{
		Data1: 0xd78e1e87,
		Data2: 0x8644,
		Data3: 0x4ea5,
		Data4: [8]byte{0x94, 0x37, 0xd8, 0x09, 0xec, 0xef, 0xc9, 0x71},
	}

	FWPM_CONDITION_IP_LOCAL_INTERFACE = windows.GUID{
		Data1: 0x4cd62a49,
		Data2: 0x59c3,
		Data3: 0x4969,
		Data4: [8]byte{0xb7, 0xf3, 0xbd, 0xa5, 0xd3, 0x28, 0x90, 0xa4},
	}
)

// WFP structures
type FWPM_SESSION0 struct {
	SessionKey           windows.GUID
	DisplayData          FWPM_DISPLAY_DATA0
	Flags                uint32
	TxnWaitTimeoutInMSec uint32
	ProcessId            uint32
	Sid                  *windows.SID
	Username             *uint16
	KernelMode           uint8
	_                    [3]byte
}

type FWPM_DISPLAY_DATA0 struct {
	Name        *uint16
	Description *uint16
}

type FWPM_SUBLAYER0 struct {
	SubLayerKey  windows.GUID
	DisplayData  FWPM_DISPLAY_DATA0
	Flags        uint32
	_            [4]byte // padding for 8-byte alignment of ProviderKey
	ProviderKey  *windows.GUID
	ProviderData FWP_BYTE_BLOB
	Weight       uint16
	_2           [6]byte // padding to 8-byte boundary
}

type FWP_BYTE_BLOB struct {
	Size uint32
	_    [4]byte // padding for 8-byte alignment of Data
	Data *uint8
}

type FWPM_FILTER0 struct {
	FilterKey           windows.GUID
	DisplayData         FWPM_DISPLAY_DATA0
	Flags               uint32
	_                   [4]byte // padding for 8-byte alignment of ProviderKey
	ProviderKey         *windows.GUID
	ProviderData        FWP_BYTE_BLOB
	LayerKey            windows.GUID
	SubLayerKey         windows.GUID
	Weight              FWP_VALUE0
	NumFilterConditions uint32
	_2                  [4]byte // padding for 8-byte alignment of FilterCondition
	FilterCondition     *FWPM_FILTER_CONDITION0
	Action              FWPM_ACTION0
	Context             windows.GUID // union: rawContext (uint64) or providerContextKey (GUID)
	Reserved            *windows.GUID
	FilterId            uint64
	EffectiveWeight     FWP_VALUE0
}

type FWPM_FILTER_CONDITION0 struct {
	FieldKey       windows.GUID
	MatchType      uint32
	_              [4]byte // padding for 8-byte alignment of ConditionValue
	ConditionValue FWP_CONDITION_VALUE0
}

type FWP_CONDITION_VALUE0 struct {
	Type  uint32
	_     [4]byte
	Value uintptr
}

type FWP_VALUE0 struct {
	Type  uint32
	_     [4]byte
	Value uintptr
}

type FWPM_ACTION0 struct {
	Type uint32
	_    [4]byte
	GUID windows.GUID
}

var (
	modfwpuclnt = windows.NewLazySystemDLL("fwpuclnt.dll")
	modole32    = windows.NewLazySystemDLL("ole32.dll")

	procFwpmEngineOpen0            = modfwpuclnt.NewProc("FwpmEngineOpen0")
	procFwpmEngineClose0           = modfwpuclnt.NewProc("FwpmEngineClose0")
	procFwpmSubLayerAdd0           = modfwpuclnt.NewProc("FwpmSubLayerAdd0")
	procFwpmSubLayerDeleteByKey0   = modfwpuclnt.NewProc("FwpmSubLayerDeleteByKey0")
	procFwpmFilterAdd0             = modfwpuclnt.NewProc("FwpmFilterAdd0")
	procFwpmFilterDeleteById0      = modfwpuclnt.NewProc("FwpmFilterDeleteById0")
	procFwpmGetAppIdFromFileName0  = modfwpuclnt.NewProc("FwpmGetAppIdFromFileName0")
	procFwpmFreeMemory0            = modfwpuclnt.NewProc("FwpmFreeMemory0")
	procCoCreateGuid               = modole32.NewProc("CoCreateGuid")
)

// wfpManager manages Windows Filtering Platform for DNS leak prevention and process protection
type wfpManager struct {
	ctx              context.Context
	engine           uintptr
	subLayerKey      windows.GUID
	luid             LUID
	filterIDs        []uint64
	appID            *FWP_BYTE_BLOB
	dnsEnabled       bool
	processProtected bool
}

// newWFPManager creates a new WFP manager
func newWFPManager(ctx context.Context, luid LUID) (*wfpManager, error) {
	m := &wfpManager{
		ctx:  ctx,
		luid: luid,
	}

	// Open WFP engine with dynamic session (auto-cleanup on process exit)
	session := &FWPM_SESSION0{
		Flags: FWPM_SESSION_FLAG_DYNAMIC,
	}

	ret, _, err := procFwpmEngineOpen0.Call(
		0, // serverName (local)
		RPC_C_AUTHN_DEFAULT,
		0, // authIdentity
		uintptr(unsafe.Pointer(session)),
		uintptr(unsafe.Pointer(&m.engine)),
	)
	if ret != 0 {
		return nil, fmt.Errorf("FwpmEngineOpen0 failed: %v (code %d)", err, ret)
	}

	// Generate sublayer GUID
	ret, _, _ = procCoCreateGuid.Call(uintptr(unsafe.Pointer(&m.subLayerKey)))
	if ret != 0 {
		m.Close()
		return nil, fmt.Errorf("CoCreateGuid failed: code %d", ret)
	}

	// Add sublayer
	subLayer := FWPM_SUBLAYER0{
		SubLayerKey: m.subLayerKey,
		DisplayData: createDisplayData("Xray TUN", "Auto-route DNS protection"),
		Weight:      math.MaxUint16,
	}

	ret, _, err = procFwpmSubLayerAdd0.Call(
		m.engine,
		uintptr(unsafe.Pointer(&subLayer)),
		0, // sd (security descriptor)
	)
	if ret != 0 {
		m.Close()
		return nil, fmt.Errorf("FwpmSubLayerAdd0 failed: %v (code %d)", err, ret)
	}

	return m, nil
}

// EnableProcessProtection excludes traffic from current process from TUN routing
// This prevents the infinite loop where xray's outbound traffic goes back into TUN
func (m *wfpManager) EnableProcessProtection() error {
	if m.processProtected {
		return nil
	}

	// Get current executable path
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}

	// Get app ID for the executable
	exePathPtr, err := windows.UTF16PtrFromString(exePath)
	if err != nil {
		return fmt.Errorf("failed to convert path: %w", err)
	}

	var appID *FWP_BYTE_BLOB
	ret, _, _ := procFwpmGetAppIdFromFileName0.Call(
		uintptr(unsafe.Pointer(exePathPtr)),
		uintptr(unsafe.Pointer(&appID)),
	)
	if ret != 0 {
		return fmt.Errorf("FwpmGetAppIdFromFileName0 failed: code %d", ret)
	}
	m.appID = appID

	// Add filter to permit all traffic from this process (highest priority)
	// This allows xray's outbound connections to bypass TUN routing
	if err := m.addProcessPermitFilter(FWPM_LAYER_ALE_AUTH_CONNECT_V4); err != nil {
		return fmt.Errorf("failed to add IPv4 process permit filter: %w", err)
	}
	if err := m.addProcessPermitFilter(FWPM_LAYER_ALE_AUTH_CONNECT_V6); err != nil {
		return fmt.Errorf("failed to add IPv6 process permit filter: %w", err)
	}

	m.processProtected = true
	errors.LogInfo(m.ctx, "process protection enabled via WFP for ", exePath)

	return nil
}

// addProcessPermitFilter adds a filter to permit traffic from current process
func (m *wfpManager) addProcessPermitFilter(layerKey windows.GUID) error {
	condition := FWPM_FILTER_CONDITION0{
		FieldKey:  FWPM_CONDITION_ALE_APP_ID,
		MatchType: FWP_MATCH_EQUAL,
		ConditionValue: FWP_CONDITION_VALUE0{
			Type:  FWP_BYTE_BLOB_TYPE,
			Value: uintptr(unsafe.Pointer(m.appID)),
		},
	}

	filter := FWPM_FILTER0{
		DisplayData:         createDisplayData("Xray Process Permit", "Allow xray outbound traffic to bypass TUN"),
		LayerKey:            layerKey,
		SubLayerKey:         m.subLayerKey,
		Weight:              FWP_VALUE0{Type: FWP_EMPTY}, // Auto-weight
		NumFilterConditions: 1,
		FilterCondition:     &condition,
		Action:              FWPM_ACTION0{Type: FWP_ACTION_PERMIT},
	}

	var filterID uint64
	ret, _, err := procFwpmFilterAdd0.Call(
		m.engine,
		uintptr(unsafe.Pointer(&filter)),
		0, // sd
		uintptr(unsafe.Pointer(&filterID)),
	)
	if ret != 0 {
		return fmt.Errorf("FwpmFilterAdd0 failed: %v (code %d)", err, ret)
	}

	m.filterIDs = append(m.filterIDs, filterID)
	return nil
}

// EnableDNSProtection enables DNS leak prevention filters
func (m *wfpManager) EnableDNSProtection() error {
	if m.dnsEnabled {
		return nil
	}

	// First, allow DNS through TUN interface (higher priority)
	if err := m.addDNSAllowFilter(FWPM_LAYER_ALE_AUTH_CONNECT_V4); err != nil {
		return fmt.Errorf("failed to add IPv4 DNS allow filter: %w", err)
	}
	if err := m.addDNSAllowFilter(FWPM_LAYER_ALE_AUTH_CONNECT_V6); err != nil {
		return fmt.Errorf("failed to add IPv6 DNS allow filter: %w", err)
	}

	// Then, block DNS (port 53) on all other interfaces (lower priority)
	if err := m.addDNSBlockFilter(FWPM_LAYER_ALE_AUTH_CONNECT_V4); err != nil {
		return fmt.Errorf("failed to add IPv4 DNS block filter: %w", err)
	}
	if err := m.addDNSBlockFilter(FWPM_LAYER_ALE_AUTH_CONNECT_V6); err != nil {
		return fmt.Errorf("failed to add IPv6 DNS block filter: %w", err)
	}

	m.dnsEnabled = true
	errors.LogInfo(m.ctx, "DNS leak prevention enabled via WFP")

	return nil
}

// addDNSAllowFilter adds a filter to allow DNS traffic from our process
// Note: FWPM_CONDITION_IP_LOCAL_INTERFACE is not available on ALE layers,
// so we rely on process protection to allow xray's DNS queries through
func (m *wfpManager) addDNSAllowFilter(layerKey windows.GUID) error {
	// Since process protection already allows all traffic from xray,
	// we don't need a separate DNS allow filter.
	// The block filter will block DNS from other apps, and xray's DNS
	// will be permitted by the process protection filter.
	return nil
}

// addDNSBlockFilter adds a filter to block DNS traffic on a specific layer
func (m *wfpManager) addDNSBlockFilter(layerKey windows.GUID) error {
	// Condition: remote port == 53
	condition := FWPM_FILTER_CONDITION0{
		FieldKey:  FWPM_CONDITION_IP_REMOTE_PORT,
		MatchType: FWP_MATCH_EQUAL,
		ConditionValue: FWP_CONDITION_VALUE0{
			Type:  FWP_UINT16,
			Value: uintptr(53),
		},
	}

	filter := FWPM_FILTER0{
		DisplayData:         createDisplayData("Xray DNS Block", "Block DNS requests outside TUN"),
		LayerKey:            layerKey,
		SubLayerKey:         m.subLayerKey,
		Weight:              FWP_VALUE0{Type: FWP_EMPTY}, // Auto-weight
		NumFilterConditions: 1,
		FilterCondition:     &condition,
		Action:              FWPM_ACTION0{Type: FWP_ACTION_BLOCK},
	}

	var filterID uint64
	ret, _, err := procFwpmFilterAdd0.Call(
		m.engine,
		uintptr(unsafe.Pointer(&filter)),
		0, // sd
		uintptr(unsafe.Pointer(&filterID)),
	)
	if ret != 0 {
		return fmt.Errorf("FwpmFilterAdd0 failed: %v (code %d)", err, ret)
	}

	m.filterIDs = append(m.filterIDs, filterID)
	return nil
}

// DisableProtection disables all WFP filters
func (m *wfpManager) DisableProtection() error {
	var errs []error
	for _, filterID := range m.filterIDs {
		ret, _, err := procFwpmFilterDeleteById0.Call(m.engine, uintptr(filterID))
		if ret != 0 {
			errs = append(errs, fmt.Errorf("FwpmFilterDeleteById0 failed: %v (code %d)", err, ret))
		}
	}
	m.filterIDs = nil
	m.dnsEnabled = false
	m.processProtected = false

	if len(errs) > 0 {
		return fmt.Errorf("errors during filter cleanup: %v", errs)
	}

	errors.LogInfo(m.ctx, "WFP protection disabled")
	return nil
}

// DisableDNSProtection is kept for backward compatibility
func (m *wfpManager) DisableDNSProtection() error {
	return m.DisableProtection()
}

// Close cleans up WFP resources
func (m *wfpManager) Close() error {
	// Free app ID memory if allocated
	if m.appID != nil {
		procFwpmFreeMemory0.Call(uintptr(unsafe.Pointer(&m.appID)))
		m.appID = nil
	}

	if m.engine != 0 {
		// Filters and sublayer are cleaned up automatically due to dynamic session flag
		procFwpmEngineClose0.Call(m.engine)
		m.engine = 0
	}
	return nil
}

// createDisplayData creates a FWPM_DISPLAY_DATA0 structure
func createDisplayData(name, description string) FWPM_DISPLAY_DATA0 {
	namePtr, _ := windows.UTF16PtrFromString(name)
	descPtr, _ := windows.UTF16PtrFromString(description)
	return FWPM_DISPLAY_DATA0{
		Name:        namePtr,
		Description: descPtr,
	}
}
