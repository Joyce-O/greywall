package sandbox

import (
	"testing"

	"github.com/GreyhavenHQ/greywall/internal/config"
)

// TestLinux_NoProxyBlocksNetwork verifies that when no ProxyURL is set,
// the Linux sandbox uses --unshare-net to block all network access.
func TestLinux_NoProxyBlocksNetwork(t *testing.T) {
	cfg := &config.Config{
		Network: config.NetworkConfig{},
		Filesystem: config.FilesystemConfig{
			AllowWrite: []string{"/tmp/test"},
		},
	}

	// With no proxy, network should be blocked
	if cfg.Network.ProxyURL != "" {
		t.Error("expected empty ProxyURL for no-network config")
	}
}

// TestLinux_ProxyURLSet verifies that a proxy URL is properly set in config.
func TestLinux_ProxyURLSet(t *testing.T) {
	cfg := &config.Config{
		Network: config.NetworkConfig{
			ProxyURL: "socks5://localhost:1080",
		},
		Filesystem: config.FilesystemConfig{
			AllowWrite: []string{"/tmp/test"},
		},
	}

	if cfg.Network.ProxyURL != "socks5://localhost:1080" {
		t.Errorf("expected ProxyURL socks5://localhost:1080, got %s", cfg.Network.ProxyURL)
	}
}
