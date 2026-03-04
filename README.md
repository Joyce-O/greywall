# Greywall

**The sandboxing layer of the GreyHaven platform.**

Greywall wraps commands in a sandbox that blocks network access by default and restricts filesystem operations. On Linux, it uses tun2socks for truly transparent proxying: all TCP/UDP traffic is captured at the kernel level via a TUN device and forwarded through an external SOCKS5 proxy. No application awareness needed.

```bash
# Block all network access (default — no proxy running = no connectivity)
greywall -- curl https://example.com

# Route traffic through an external SOCKS5 proxy
greywall --proxy socks5://localhost:1080 -- curl https://example.com

# Block dangerous commands
greywall -c "rm -rf /"  # → blocked by command deny rules
```

Greywall also works as a permission manager for CLI agents. See [agents.md](./docs/agents.md) for integration with Claude Code, Codex, Gemini CLI, OpenCode, and others.

## Install

**macOS / Linux:**

```bash
curl -fsSL https://gitea.app.monadical.io/monadical/greywall/raw/branch/main/install.sh | sh
```

<details>
<summary>Other installation methods</summary>

**Go install:**

```bash
go install gitea.app.monadical.io/monadical/greywall/cmd/greywall@latest
```

**Build from source:**

```bash
git clone https://gitea.app.monadical.io/monadical/greywall
cd greywall
make setup && make build
```

</details>

**Linux dependencies:**

- `bubblewrap` — container-free sandboxing (required)
- `socat` — network bridging (required)

Check dependency status with `greywall --version`.

## Usage

### Basic commands

```bash
# Run with all network blocked (default)
greywall -- curl https://example.com

# Run with shell expansion
greywall -c "echo hello && ls"

# Route through a SOCKS5 proxy
greywall --proxy socks5://localhost:1080 -- npm install

# Expose a port for inbound connections (e.g., dev servers)
greywall -p 3000 -c "npm run dev"

# Enable debug logging
greywall -d -- curl https://example.com

# Monitor sandbox violations
greywall -m -- npm install

# Show available Linux security features
greywall --linux-features

# Show version and dependency status
greywall --version
```

### Learning mode

Greywall can trace a command's filesystem access and generate a config template automatically:

```bash
# Run in learning mode — traces file access via strace
greywall --learning -- opencode

# List generated templates
greywall templates list

# Show a template's content
greywall templates show opencode

# Next run auto-loads the learned template
greywall -- opencode
```

### Configuration

Greywall reads from `~/.config/greywall/greywall.json` by default (or `~/Library/Application Support/greywall/greywall.json` on macOS).

```jsonc
{
  // Route traffic through an external SOCKS5 proxy
  "network": {
    "proxyUrl": "socks5://localhost:1080",
    "dnsAddr": "localhost:5353"
  },
  // Control filesystem access
  "filesystem": {
    "defaultDenyRead": true,
    "allowRead": ["~/.config/myapp"],
    "allowWrite": ["."],
    "denyWrite": ["~/.ssh/**"],
    "denyRead": ["~/.ssh/id_*", ".env"]
  },
  // Block dangerous commands
  "command": {
    "deny": ["git push", "npm publish"]
  }
}
```

Use `greywall --settings ./custom.json` to specify a different config file.

By default, traffic routes through the GreyProxy SOCKS5 proxy at `localhost:43052` with DNS via `localhost:43053`.

## Features

- **Transparent proxy** — All TCP/UDP traffic captured at the kernel level via tun2socks and routed through an external SOCKS5 proxy (Linux)
- **Network isolation** — All outbound blocked by default; traffic only flows when a proxy is available
- **Filesystem restrictions** — Deny-by-default read mode, controlled write paths, sensitive file protection
- **Learning mode** — Trace filesystem access with strace and auto-generate config templates
- **Command blocking** — Deny dangerous commands (`rm -rf /`, `git push`, `shutdown`, etc.)
- **SSH filtering** — Control which hosts and commands are allowed over SSH
- **Environment hardening** — Strips dangerous env vars (`LD_PRELOAD`, `DYLD_*`, etc.)
- **Violation monitoring** — Real-time logging of sandbox violations (`-m`)
- **Shell completions** — `greywall completion bash|zsh|fish|powershell`
- **Cross-platform** — Linux (bubblewrap + seccomp + Landlock + eBPF) and macOS (sandbox-exec)

Greywall can also be used as a [Go package](docs/library.md).

## Documentation

- [Documentation Index](docs/README.md)
- [Quickstart Guide](docs/quickstart.md)
- [Why Greywall](docs/why-greywall.md)
- [Configuration Reference](docs/configuration.md)
- [Security Model](docs/security-model.md)
- [Architecture](ARCHITECTURE.md)
- [Linux Security Features](docs/linux-security-features.md)
- [AI Agent Integration](docs/agents.md)
- [Library Usage (Go)](docs/library.md)
- [Troubleshooting](docs/troubleshooting.md)

## Attribution

Greywall is a fork of [Fence](https://github.com/Use-Tusk/fence), originally
created by [JY Tan](https://github.com/jy-tan) at [Tusk AI, Inc](https://github.com/Use-Tusk).
Copyright 2025 Tusk AI, Inc. Licensed under the Apache License 2.0.

Inspired by Anthropic's [sandbox-runtime](https://github.com/anthropic-experimental/sandbox-runtime).
