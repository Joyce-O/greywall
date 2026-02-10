# Dev Server + Redis Demo

This demo shows how greywall controls network access: allowing specific external domains while blocking (or allowing) localhost connections.

## Prerequisites

You need Redis running on localhost:6379:

```bash
docker run -p 6379:6379 redis:alpine
```

## Install

```bash
npm install
```

## Demo 1: Localhost allowed, external blocked

This shows that requests to Redis (local service) works, but external requests are blocked.

```bash
greywall -p 3000 --settings greywall-external-blocked.json npm start
```

Test it:

```bash
# Works - localhost outbound to Redis allowed
curl http://localhost:3000/api/users

# Blocked - no domains whitelisted for external requests
curl http://localhost:3000/api/external
```

## Demo 2: External Allowed, Localhost Blocked

This shows the opposite: whitelisted external domains work, but Redis (localhost) is blocked.

```bash
greywall -p 3000 --settings greywall-external-only.json npm start
```

You will immediately notice that Redis connection is blocked on app startup:

```text
[app] Redis connection failed: connect EPERM 127.0.0.1:6379 - Local (0.0.0.0:0)
```

Test it:

```bash
# Works - httpbin.org is in the allowlist
curl http://localhost:3000/api/external

# Blocked - localhost outbound to Redis not allowed
curl http://localhost:3000/api/users
```

## Summary

| Config | Redis (localhost) | External (httpbin.org) |
|--------|-------------------|------------------------|
| `greywall-external-blocked.json` | ✓ Allowed | ✗ Blocked |
| `greywall-external-only.json` | ✗ Blocked | ✓ Allowed |

## Key Settings

| Setting | Purpose |
|---------|---------|
| `allowLocalBinding` | Server can listen on ports |
| `allowLocalOutbound` | App can connect to localhost services |
| `allowedDomains` | Whitelist of external domains |

## Note: Node.js Proxy Support

Node.js's native `http`/`https` modules don't respect proxy environment variables. This demo uses [`undici`](https://github.com/nodejs/undici) with `ProxyAgent` to route requests through greywall's proxy:

```javascript
import { ProxyAgent, fetch } from "undici";

const proxyUrl = process.env.HTTPS_PROXY;
const response = await fetch(url, {
  dispatcher: new ProxyAgent(proxyUrl),
});
```

Without this, external HTTP requests would fail with connection errors (the sandbox blocks them) rather than going through greywall's proxy.
