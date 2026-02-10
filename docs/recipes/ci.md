# Recipe: CI jobs

Goal: make CI steps safer by default: minimal egress and controlled writes.

## Suggested baseline

```json
{
  "network": {
    "allowedDomains": []
  },
  "filesystem": {
    "allowWrite": [".", "/tmp"]
  }
}
```

Run:

```bash
greywall --settings ./greywall.json -c "make test"
```

## Add only what you need

Use monitor mode to discover what a job tries to reach:

```bash
greywall -m --settings ./greywall.json -c "make test"
```

Then allowlist only:

- your artifact/cache endpoints
- the minimum package registries required
- any internal services the job must access
