//go:build android

package tun

import (
	"context"

	"github.com/xtls/xray-core/common/errors"
)

// NewRouteManager creates a new RouteManager for Android
// On Android, route configuration is managed by VpnService, not by xray-core directly
func NewRouteManager(ctx context.Context, options RouteOptions) (RouteManager, error) {
	if options.AutoRoute {
		errors.LogWarning(ctx, "auto_route is not supported on Android; "+
			"route configuration should be handled by VpnService in the Android app")
	}
	return &noopRouteManager{}, nil
}
