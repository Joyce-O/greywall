# Recipe: `git clone` / `git fetch`

Goal: allow fetching code from a limited set of hosts.

## HTTPS clone (GitHub example)

```json
{
  "network": {
    "allowedDomains": ["github.com", "api.github.com", "codeload.github.com"]
  },
  "filesystem": {
    "allowWrite": ["."]
  }
}
```

Run:

```bash
greywall --settings ./greywall.json git clone https://github.com/OWNER/REPO.git
```

## SSH clone

SSH traffic may go through SOCKS5 (`ALL_PROXY`) depending on your git/ssh configuration.

If it fails, use monitor/debug mode to see what was blocked:

```bash
greywall -m --settings ./greywall.json git clone git@github.com:OWNER/REPO.git
```
