// Package main implements the greywall CLI.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"syscall"

	"gitea.app.monadical.io/monadical/greywall/internal/config"
	"gitea.app.monadical.io/monadical/greywall/internal/platform"
	"gitea.app.monadical.io/monadical/greywall/internal/sandbox"
	"github.com/spf13/cobra"
)

// Build-time variables (set via -ldflags)
var (
	version   = "dev"
	buildTime = "unknown"
	gitCommit = "unknown"
)

var (
	debug         bool
	monitor       bool
	settingsPath  string
	proxyURL      string
	dnsAddr       string
	cmdString     string
	exposePorts   []string
	exitCode      int
	showVersion   bool
	linuxFeatures bool
)

func main() {
	// Check for internal --landlock-apply mode (used inside sandbox)
	// This must be checked before cobra to avoid flag conflicts
	if len(os.Args) >= 2 && os.Args[1] == "--landlock-apply" {
		runLandlockWrapper()
		return
	}

	rootCmd := &cobra.Command{
		Use:   "greywall [flags] -- [command...]",
		Short: "Run commands in a sandbox with network and filesystem restrictions",
		Long: `greywall is a command-line tool that runs commands in a sandboxed environment
with network and filesystem restrictions.

By default, all network access is blocked. Use --proxy to route traffic through
an external SOCKS5 proxy, or configure a proxy URL in your settings file at
~/.config/greywall/greywall.json (or ~/Library/Application Support/greywall/greywall.json on macOS).

On Linux, greywall uses tun2socks for truly transparent proxying: all TCP/UDP traffic
from any binary is captured at the kernel level via a TUN device and forwarded
through the external SOCKS5 proxy. No application awareness needed.

On macOS, greywall uses environment variables (best-effort) to direct traffic
to the proxy.

Examples:
  greywall -- curl https://example.com                          # Blocked (no proxy)
  greywall --proxy socks5://localhost:1080 -- curl https://example.com  # Via proxy
  greywall -- curl -s https://example.com                       # Use -- to separate flags
  greywall -c "echo hello && ls"                                # Run with shell expansion
  greywall --settings config.json npm install
  greywall -p 3000 -c "npm run dev"                             # Expose port 3000

Configuration file format:
{
  "network": {
    "proxyUrl": "socks5://localhost:1080"
  },
  "filesystem": {
    "denyRead": [],
    "allowWrite": ["."],
    "denyWrite": []
  },
  "command": {
    "deny": ["git push", "npm publish"]
  }
}`,
		RunE:          runCommand,
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.ArbitraryArgs,
	}

	rootCmd.Flags().BoolVarP(&debug, "debug", "d", false, "Enable debug logging")
	rootCmd.Flags().BoolVarP(&monitor, "monitor", "m", false, "Monitor and log sandbox violations")
	rootCmd.Flags().StringVarP(&settingsPath, "settings", "s", "", "Path to settings file (default: OS config directory)")
	rootCmd.Flags().StringVar(&proxyURL, "proxy", "", "External SOCKS5 proxy URL (e.g., socks5://localhost:1080)")
	rootCmd.Flags().StringVar(&dnsAddr, "dns", "", "DNS server address on host (e.g., localhost:3153)")
	rootCmd.Flags().StringVarP(&cmdString, "c", "c", "", "Run command string directly (like sh -c)")
	rootCmd.Flags().StringArrayVarP(&exposePorts, "port", "p", nil, "Expose port for inbound connections (can be used multiple times)")
	rootCmd.Flags().BoolVarP(&showVersion, "version", "v", false, "Show version information")
	rootCmd.Flags().BoolVar(&linuxFeatures, "linux-features", false, "Show available Linux security features and exit")

	rootCmd.Flags().SetInterspersed(true)

	rootCmd.AddCommand(newCompletionCmd(rootCmd))

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		exitCode = 1
	}
	os.Exit(exitCode)
}

func runCommand(cmd *cobra.Command, args []string) error {
	if showVersion {
		fmt.Printf("greywall - lightweight, container-free sandbox for running untrusted commands\n")
		fmt.Printf("  Version: %s\n", version)
		fmt.Printf("  Built:   %s\n", buildTime)
		fmt.Printf("  Commit:  %s\n", gitCommit)
		return nil
	}

	if linuxFeatures {
		sandbox.PrintLinuxFeatures()
		return nil
	}

	var command string
	switch {
	case cmdString != "":
		command = cmdString
	case len(args) > 0:
		command = sandbox.ShellQuote(args)
	default:
		return fmt.Errorf("no command specified. Use -c <command> or provide command arguments")
	}

	if debug {
		fmt.Fprintf(os.Stderr, "[greywall] Command: %s\n", command)
	}

	var ports []int
	for _, p := range exposePorts {
		port, err := strconv.Atoi(p)
		if err != nil || port < 1 || port > 65535 {
			return fmt.Errorf("invalid port: %s", p)
		}
		ports = append(ports, port)
	}

	if debug && len(ports) > 0 {
		fmt.Fprintf(os.Stderr, "[greywall] Exposing ports: %v\n", ports)
	}

	// Load config: settings file > default path > default config
	var cfg *config.Config
	var err error

	switch {
	case settingsPath != "":
		cfg, err = config.Load(settingsPath)
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}
	default:
		configPath := config.DefaultConfigPath()
		cfg, err = config.Load(configPath)
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}
		if cfg == nil {
			if debug {
				fmt.Fprintf(os.Stderr, "[greywall] No config found at %s, using default (block all network)\n", configPath)
			}
			cfg = config.Default()
		}
	}

	// CLI flags override config
	if proxyURL != "" {
		cfg.Network.ProxyURL = proxyURL
	}
	if dnsAddr != "" {
		cfg.Network.DnsAddr = dnsAddr
	}

	manager := sandbox.NewManager(cfg, debug, monitor)
	manager.SetExposedPorts(ports)
	defer manager.Cleanup()

	if err := manager.Initialize(); err != nil {
		return fmt.Errorf("failed to initialize sandbox: %w", err)
	}

	var logMonitor *sandbox.LogMonitor
	if monitor {
		logMonitor = sandbox.NewLogMonitor(sandbox.GetSessionSuffix())
		if logMonitor != nil {
			if err := logMonitor.Start(); err != nil {
				fmt.Fprintf(os.Stderr, "[greywall] Warning: failed to start log monitor: %v\n", err)
			} else {
				defer logMonitor.Stop()
			}
		}
	}

	sandboxedCommand, err := manager.WrapCommand(command)
	if err != nil {
		return fmt.Errorf("failed to wrap command: %w", err)
	}

	if debug {
		fmt.Fprintf(os.Stderr, "[greywall] Sandboxed command: %s\n", sandboxedCommand)
	}

	hardenedEnv := sandbox.GetHardenedEnv()
	if debug {
		if stripped := sandbox.GetStrippedEnvVars(os.Environ()); len(stripped) > 0 {
			fmt.Fprintf(os.Stderr, "[greywall] Stripped dangerous env vars: %v\n", stripped)
		}
	}

	execCmd := exec.Command("sh", "-c", sandboxedCommand) //nolint:gosec // sandboxedCommand is constructed from user input - intentional
	execCmd.Env = hardenedEnv
	execCmd.Stdin = os.Stdin
	execCmd.Stdout = os.Stdout
	execCmd.Stderr = os.Stderr

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start the command (non-blocking) so we can get the PID
	if err := execCmd.Start(); err != nil {
		return fmt.Errorf("failed to start command: %w", err)
	}

	// Start Linux monitors (eBPF tracing for filesystem violations)
	var linuxMonitors *sandbox.LinuxMonitors
	if monitor && execCmd.Process != nil {
		linuxMonitors, _ = sandbox.StartLinuxMonitor(execCmd.Process.Pid, sandbox.LinuxSandboxOptions{
			Monitor: true,
			Debug:   debug,
			UseEBPF: true,
		})
		if linuxMonitors != nil {
			defer linuxMonitors.Stop()
		}
	}

	go func() {
		sigCount := 0
		for sig := range sigChan {
			sigCount++
			if execCmd.Process == nil {
				continue
			}
			// First signal: graceful termination; second signal: force kill
			if sigCount >= 2 {
				_ = execCmd.Process.Kill()
			} else {
				_ = execCmd.Process.Signal(sig)
			}
		}
	}()

	// Wait for command to finish
	if err := execCmd.Wait(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			// Set exit code but don't os.Exit() here - let deferred cleanup run
			exitCode = exitErr.ExitCode()
			return nil
		}
		return fmt.Errorf("command failed: %w", err)
	}

	return nil
}

// newCompletionCmd creates the completion subcommand for shell completions.
func newCompletionCmd(rootCmd *cobra.Command) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "completion [bash|zsh|fish|powershell]",
		Short: "Generate shell completion scripts",
		Long: `Generate shell completion scripts for greywall.

Examples:
  # Bash (load in current session)
  source <(greywall completion bash)

  # Zsh (load in current session)
  source <(greywall completion zsh)

  # Fish (load in current session)
  greywall completion fish | source

  # PowerShell (load in current session)
  greywall completion powershell | Out-String | Invoke-Expression

To persist completions, redirect output to the appropriate completions
directory for your shell (e.g., /etc/bash_completion.d/ for bash,
${fpath[1]}/_greywall for zsh, ~/.config/fish/completions/greywall.fish for fish).
`,
		DisableFlagsInUseLine: true,
		ValidArgs:             []string{"bash", "zsh", "fish", "powershell"},
		Args:                  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			switch args[0] {
			case "bash":
				return rootCmd.GenBashCompletionV2(os.Stdout, true)
			case "zsh":
				return rootCmd.GenZshCompletion(os.Stdout)
			case "fish":
				return rootCmd.GenFishCompletion(os.Stdout, true)
			case "powershell":
				return rootCmd.GenPowerShellCompletionWithDesc(os.Stdout)
			default:
				return fmt.Errorf("unsupported shell: %s", args[0])
			}
		},
	}
	return cmd
}

// runLandlockWrapper runs in "wrapper mode" inside the sandbox.
// It applies Landlock restrictions and then execs the user command.
// Usage: greywall --landlock-apply [--debug] -- <command...>
// Config is passed via GREYWALL_CONFIG_JSON environment variable.
func runLandlockWrapper() {
	// Parse arguments: --landlock-apply [--debug] -- <command...>
	args := os.Args[2:] // Skip "greywall" and "--landlock-apply"

	var debugMode bool
	var cmdStart int

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--debug":
			debugMode = true
		case "--":
			cmdStart = i + 1
			goto parseCommand
		default:
			// Assume rest is the command
			cmdStart = i
			goto parseCommand
		}
	}

parseCommand:
	if cmdStart >= len(args) {
		fmt.Fprintf(os.Stderr, "[greywall:landlock-wrapper] Error: no command specified\n")
		os.Exit(1)
	}

	command := args[cmdStart:]

	if debugMode {
		fmt.Fprintf(os.Stderr, "[greywall:landlock-wrapper] Applying Landlock restrictions\n")
	}

	// Only apply Landlock on Linux
	if platform.Detect() == platform.Linux {
		// Load config from environment variable (passed by parent greywall process)
		var cfg *config.Config
		if configJSON := os.Getenv("GREYWALL_CONFIG_JSON"); configJSON != "" {
			cfg = &config.Config{}
			if err := json.Unmarshal([]byte(configJSON), cfg); err != nil {
				if debugMode {
					fmt.Fprintf(os.Stderr, "[greywall:landlock-wrapper] Warning: failed to parse config: %v\n", err)
				}
				cfg = nil
			}
		}
		if cfg == nil {
			cfg = config.Default()
		}

		// Get current working directory for relative path resolution
		cwd, _ := os.Getwd()

		// Apply Landlock restrictions
		err := sandbox.ApplyLandlockFromConfig(cfg, cwd, nil, debugMode)
		if err != nil {
			if debugMode {
				fmt.Fprintf(os.Stderr, "[greywall:landlock-wrapper] Warning: Landlock not applied: %v\n", err)
			}
			// Continue without Landlock - bwrap still provides isolation
		} else if debugMode {
			fmt.Fprintf(os.Stderr, "[greywall:landlock-wrapper] Landlock restrictions applied\n")
		}
	}

	// Find the executable
	execPath, err := exec.LookPath(command[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "[greywall:landlock-wrapper] Error: command not found: %s\n", command[0])
		os.Exit(127)
	}

	if debugMode {
		fmt.Fprintf(os.Stderr, "[greywall:landlock-wrapper] Exec: %s %v\n", execPath, command[1:])
	}

	// Sanitize environment (strips LD_PRELOAD, etc.)
	hardenedEnv := sandbox.FilterDangerousEnv(os.Environ())

	// Exec the command (replaces this process)
	err = syscall.Exec(execPath, command, hardenedEnv) //nolint:gosec
	if err != nil {
		fmt.Fprintf(os.Stderr, "[greywall:landlock-wrapper] Exec failed: %v\n", err)
		os.Exit(1)
	}
}
