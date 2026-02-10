# Quickstart

## Installation

### From Source (recommended for now)

```bash
git clone https://gitea.app.monadical.io/monadical/greywall
cd greywall
go build -o greywall ./cmd/greywall
sudo mv greywall /usr/local/bin/
```

### Using Go Install

```bash
go install gitea.app.monadical.io/monadical/greywall/cmd/greywall@latest
```

### Linux Dependencies

On Linux, you also need:

```bash
# Ubuntu/Debian
sudo apt install bubblewrap socat

# Fedora
sudo dnf install bubblewrap socat

# Arch
sudo pacman -S bubblewrap socat
```

### Do I need sudo to run greywall?

No, for most Linux systems. Greywall works without root privileges because:

- Package-manager-installed `bubblewrap` is typically already setuid
- Greywall detects available capabilities and adapts automatically

If some features aren't available (like network namespaces in Docker/CI), greywall falls back gracefully - you'll still get filesystem isolation, command blocking, and proxy-based network filtering.

Run `greywall --linux-features` to see what's available in your environment.

## Verify Installation

```bash
greywall --version
```

## Your First Sandboxed Command

By default, greywall blocks all network access:

```bash
# This will fail - network is blocked
greywall curl https://example.com
```

You should see something like:

```text
curl: (56) CONNECT tunnel failed, response 403
```

## Allow Specific Domains

Create a config file at `~/.config/greywall/greywall.json` (or `~/Library/Application Support/greywall/greywall.json` on macOS):

```json
{
  "network": {
    "allowedDomains": ["example.com"]
  }
}
```

Now try again:

```bash
greywall curl https://example.com
```

This time it succeeds!

## Debug Mode

Use `-d` to see what's happening under the hood:

```bash
greywall -d curl https://example.com
```

This shows:

- The sandbox command being run
- Proxy activity (allowed/blocked requests)
- Filter rule matches

## Monitor Mode

Use `-m` to see only violations and blocked requests:

```bash
greywall -m npm install
```

This is useful for:

- Auditing what a command tries to access
- Debugging why something isn't working
- Understanding a package's network behavior

## Running Shell Commands

Use `-c` to run compound commands:

```bash
greywall -c "echo hello && ls -la"
```

## Expose Ports for Servers

If you're running a server that needs to accept connections:

```bash
greywall -p 3000 -c "npm run dev"
```

This allows external connections to port 3000 while keeping outbound network restricted.

## Next steps

- Read **[Why Greywall](why-greywall.md)** to understand when greywall is a good fit (and when it isn't).
- Learn the mental model in **[Concepts](concepts.md)**.
- Use **[Troubleshooting](troubleshooting.md)** if something is blocked unexpectedly.
- Start from copy/paste configs in **[`docs/templates/`](templates/README.md)**.
- Follow workflow-specific guides in **[Recipes](recipes/README.md)** (npm/pip/git/CI).
