package sandbox

import (
	"fmt"
	"os"

	"gitea.app.monadical.io/monadical/greywall/internal/config"
	"gitea.app.monadical.io/monadical/greywall/internal/platform"
)

// Manager handles sandbox initialization and command wrapping.
type Manager struct {
	config        *config.Config
	proxyBridge   *ProxyBridge
	dnsBridge     *DnsBridge
	reverseBridge *ReverseBridge
	tun2socksPath string // path to extracted tun2socks binary on host
	exposedPorts  []int
	debug         bool
	monitor       bool
	initialized   bool
}

// NewManager creates a new sandbox manager.
func NewManager(cfg *config.Config, debug, monitor bool) *Manager {
	return &Manager{
		config:  cfg,
		debug:   debug,
		monitor: monitor,
	}
}

// SetExposedPorts sets the ports to expose for inbound connections.
func (m *Manager) SetExposedPorts(ports []int) {
	m.exposedPorts = ports
}

// Initialize sets up the sandbox infrastructure.
func (m *Manager) Initialize() error {
	if m.initialized {
		return nil
	}

	if !platform.IsSupported() {
		return fmt.Errorf("sandbox is not supported on platform: %s", platform.Detect())
	}

	// On Linux, set up proxy bridge and tun2socks if proxy is configured
	if platform.Detect() == platform.Linux {
		if m.config.Network.ProxyURL != "" {
			// Extract embedded tun2socks binary
			tun2socksPath, err := extractTun2Socks()
			if err != nil {
				m.logDebug("Failed to extract tun2socks: %v (will fall back to env-var proxying)", err)
			} else {
				m.tun2socksPath = tun2socksPath
			}

			// Create proxy bridge (socat: Unix socket -> external SOCKS5 proxy)
			bridge, err := NewProxyBridge(m.config.Network.ProxyURL, m.debug)
			if err != nil {
				if m.tun2socksPath != "" {
					os.Remove(m.tun2socksPath)
				}
				return fmt.Errorf("failed to initialize proxy bridge: %w", err)
			}
			m.proxyBridge = bridge

			// Create DNS bridge if a DNS server is configured
			if m.config.Network.DnsAddr != "" {
				dnsBridge, err := NewDnsBridge(m.config.Network.DnsAddr, m.debug)
				if err != nil {
					m.proxyBridge.Cleanup()
					if m.tun2socksPath != "" {
						os.Remove(m.tun2socksPath)
					}
					return fmt.Errorf("failed to initialize DNS bridge: %w", err)
				}
				m.dnsBridge = dnsBridge
			}
		}

		// Set up reverse bridge for exposed ports (inbound connections)
		// Only needed when network namespace is available - otherwise they share the network
		features := DetectLinuxFeatures()
		if len(m.exposedPorts) > 0 && features.CanUnshareNet {
			reverseBridge, err := NewReverseBridge(m.exposedPorts, m.debug)
			if err != nil {
				if m.proxyBridge != nil {
					m.proxyBridge.Cleanup()
				}
				if m.tun2socksPath != "" {
					os.Remove(m.tun2socksPath)
				}
				return fmt.Errorf("failed to initialize reverse bridge: %w", err)
			}
			m.reverseBridge = reverseBridge
		} else if len(m.exposedPorts) > 0 && m.debug {
			m.logDebug("Skipping reverse bridge (no network namespace, ports accessible directly)")
		}
	}

	m.initialized = true
	if m.config.Network.ProxyURL != "" {
		m.logDebug("Sandbox manager initialized (proxy: %s)", m.config.Network.ProxyURL)
	} else {
		m.logDebug("Sandbox manager initialized (no proxy, network blocked)")
	}
	return nil
}

// WrapCommand wraps a command with sandbox restrictions.
// Returns an error if the command is blocked by policy.
func (m *Manager) WrapCommand(command string) (string, error) {
	if !m.initialized {
		if err := m.Initialize(); err != nil {
			return "", err
		}
	}

	// Check if command is blocked by policy
	if err := CheckCommand(command, m.config); err != nil {
		return "", err
	}

	plat := platform.Detect()
	switch plat {
	case platform.MacOS:
		return WrapCommandMacOS(m.config, command, m.exposedPorts, m.debug)
	case platform.Linux:
		return WrapCommandLinux(m.config, command, m.proxyBridge, m.dnsBridge, m.reverseBridge, m.tun2socksPath, m.debug)
	default:
		return "", fmt.Errorf("unsupported platform: %s", plat)
	}
}

// Cleanup stops the proxies and cleans up resources.
func (m *Manager) Cleanup() {
	if m.reverseBridge != nil {
		m.reverseBridge.Cleanup()
	}
	if m.dnsBridge != nil {
		m.dnsBridge.Cleanup()
	}
	if m.proxyBridge != nil {
		m.proxyBridge.Cleanup()
	}
	if m.tun2socksPath != "" {
		os.Remove(m.tun2socksPath)
	}
	m.logDebug("Sandbox manager cleaned up")
}

func (m *Manager) logDebug(format string, args ...interface{}) {
	if m.debug {
		fmt.Fprintf(os.Stderr, "[greywall] "+format+"\n", args...)
	}
}
