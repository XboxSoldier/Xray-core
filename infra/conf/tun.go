package conf

import (
	"context"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/proxy/tun"
	"google.golang.org/protobuf/proto"
)

type TunConfig struct {
	Name      string `json:"name"`
	MTU       uint32 `json:"MTU"`
	UserLevel uint32 `json:"userLevel"`

	// Auto route configuration
	AutoRoute           bool     `json:"autoRoute"`
	RouteAddress        []string `json:"routeAddress"`
	RouteExcludeAddress []string `json:"routeExcludeAddress"`
	StrictRoute         bool     `json:"strictRoute"`
	TableIndex          int32    `json:"tableIndex"`

	// TUN interface addresses
	Inet4Address string `json:"inet4Address"`
	Inet6Address string `json:"inet6Address"`

	// Windows DNS leak prevention (enabled by default when autoRoute is true)
	DisableDNSHijack bool `json:"disableDNSHijack"`
}

func (v *TunConfig) Build() (proto.Message, error) {
	// Debug: log parsed config values
	errors.LogDebug(context.Background(), "TunConfig.Build() called: Name=", v.Name,
		", MTU=", v.MTU, ", AutoRoute=", v.AutoRoute,
		", RouteAddress=", v.RouteAddress, ", RouteExcludeAddress=", v.RouteExcludeAddress,
		", Inet4Address=", v.Inet4Address, ", Inet6Address=", v.Inet6Address)

	config := &tun.Config{
		Name:                v.Name,
		MTU:                 v.MTU,
		UserLevel:           v.UserLevel,
		AutoRoute:           v.AutoRoute,
		RouteAddress:        v.RouteAddress,
		RouteExcludeAddress: v.RouteExcludeAddress,
		StrictRoute:         v.StrictRoute,
		TableIndex:          v.TableIndex,
		Inet4Address:        v.Inet4Address,
		Inet6Address:        v.Inet6Address,
		DisableDnsHijack:    v.DisableDNSHijack,
	}

	if v.Name == "" {
		config.Name = "xray0"
	}

	if v.MTU == 0 {
		config.MTU = 1500
	}

	return config, nil
}
