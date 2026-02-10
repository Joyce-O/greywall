# Concepts

Greywall combines two ideas:

1. **An OS sandbox** to enforce "no direct network" and restrict filesystem operations.
2. **Local filtering proxies** (HTTP + SOCKS5) to selectively allow outbound traffic by domain.

## Network model

By default, greywall blocks all outbound network access.

When you allow domains, greywall:

- Starts local HTTP and SOCKS5 proxies
- Sets proxy environment variables (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`)
- Allows the sandboxed process to connect only to the local proxies
- Filters outbound connections by **destination domain**

### Localhost controls

- `allowLocalBinding`: lets a sandboxed process *listen* on local ports (e.g. dev servers).
- `allowLocalOutbound`: lets a sandboxed process connect to `localhost` services (e.g. Redis/Postgres on your machine).
- `-p/--port`: exposes inbound ports so things outside the sandbox can reach your server.

These are separate on purpose. A typical safe default for dev servers is:

- allow binding + expose just the needed port(s)
- disallow localhost outbound unless you explicitly need it

## Filesystem model

Greywall is designed around "read mostly, write narrowly":

- **Reads**: allowed by default (you can block specific paths via `denyRead`).
- **Writes**: denied by default (you must opt-in with `allowWrite`).
- **denyWrite**: overrides `allowWrite` (useful for protecting secrets and dangerous files).

Greywall also protects some dangerous targets regardless of config (e.g. shell startup files and git hooks). See `ARCHITECTURE.md` for the full list.

## Debug vs Monitor mode

- `-d/--debug`: verbose output (proxy activity, filter decisions, sandbox command details).
- `-m/--monitor`: show blocked requests/violations only (great for auditing and policy tuning).

Workflow tip:

1. Start restrictive.
2. Run with `-m` to see what gets blocked.
3. Add the minimum domains/paths required.

## Platform notes

- **macOS**: uses `sandbox-exec` with generated Seatbelt profiles.
- **Linux**: uses `bubblewrap` for namespaces + `socat` bridges to connect the isolated network namespace to host-side proxies.

If you want the under-the-hood view, see [Architecture](../ARCHITECTURE.md).
