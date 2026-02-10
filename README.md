![Greywall Banner](assets/greywall-banner.png)

# Greywall

**The sandboxing layer of the GreyHaven platform.**

Greywall wraps commands in a sandbox that blocks network access by default and restricts filesystem operations. It is the core sandboxing component of the GreyHaven platform, providing defense-in-depth for running untrusted code.

```bash
# Block all network access (default)
greywall curl https://example.com  # → 403 Forbidden

# Allow specific domains
greywall -t code npm install  # → uses 'code' template with npm/pypi/etc allowed

# Block dangerous commands
greywall -c "rm -rf /"  # → blocked by command deny rules
```

Greywall also works as a permission manager for CLI agents. **Greywall works with popular coding agents like Claude Code, Codex, Gemini CLI, Cursor Agent, OpenCode, Factory (Droid) CLI, etc.** See [agents.md](./docs/agents.md) for more details.

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
go build -o greywall ./cmd/greywall
```

</details>

**Additional requirements for Linux:**

- `bubblewrap` (for sandboxing)
- `socat` (for network bridging)
- `bpftrace` (optional, for filesystem violation visibility when monitoring with `-m`)

## Usage

### Basic

```bash
# Run command with all network blocked (no domains allowed by default)
greywall curl https://example.com

# Run with shell expansion
greywall -c "echo hello && ls"

# Enable debug logging
greywall -d curl https://example.com

# Use a template
greywall -t code -- claude  # Runs Claude Code using `code` template config

# Monitor mode (shows violations)
greywall -m npm install

# Show all commands and options
greywall --help
```

### Configuration

Greywall reads from `~/.config/greywall/greywall.json` by default (or `~/Library/Application Support/greywall/greywall.json` on macOS).

```json
{
  "extends": "code",
  "network": { "allowedDomains": ["private.company.com"] },
  "filesystem": { "allowWrite": ["."] },
  "command": { "deny": ["git push", "npm publish"] }
}
```

Use `greywall --settings ./custom.json` to specify a different config.

### Import from Claude Code

```bash
greywall import --claude --save
```

## Features

- **Network isolation** - All outbound blocked by default; allowlist domains via config
- **Filesystem restrictions** - Control read/write access paths
- **Command blocking** - Deny dangerous commands like `rm -rf /`, `git push`
- **SSH Command Filtering** - Control which hosts and commands are allowed over SSH
- **Built-in templates** - Pre-configured rulesets for common workflows
- **Violation monitoring** - Real-time logging of blocked requests (`-m`)
- **Cross-platform** - macOS (sandbox-exec) + Linux (bubblewrap)

Greywall can be used as a Go package or CLI tool.

## Documentation

- [Index](/docs/README.md)
- [Quickstart Guide](docs/quickstart.md)
- [Configuration Reference](docs/configuration.md)
- [Security Model](docs/security-model.md)
- [Architecture](ARCHITECTURE.md)
- [Library Usage (Go)](docs/library.md)
- [Examples](examples/)

## Attribution

Greywall is based on [Fence](https://github.com/Use-Tusk/fence) by Use-Tusk.

Inspired by Anthropic's [sandbox-runtime](https://github.com/anthropic-experimental/sandbox-runtime).
