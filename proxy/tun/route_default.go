//go:build !linux && !windows && !android

package tun

import (
	"context"

	"github.com/xtls/xray-core/common/errors"
)

// NewRouteManager creates a new RouteManager for unsupported platforms
func NewRouteManager(ctx context.Context, options RouteOptions) (RouteManager, error) {
	if options.AutoRoute {
		errors.LogWarning(ctx, "auto_route is not supported on this platform")
	}
	return &noopRouteManager{}, nil
}
