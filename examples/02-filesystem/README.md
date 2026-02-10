# Filesystem Sandbox Demo

This demo shows how greywall controls filesystem access with `allowWrite`, `denyWrite`, and `denyRead`.

## What it demonstrates

| Operation | Without Greywall | With Greywall |
|-----------|---------------|------------|
| Write to `./output/` | ✓ | ✓ (in allowWrite) |
| Write to `./` | ✓ | ✗ (not in allowWrite) |
| Write to `.env` | ✓ | ✗ (in denyWrite) |
| Write to `*.key` | ✓ | ✗ (in denyWrite) |
| Read `./demo.py` | ✓ | ✓ (allowed by default) |
| Read `/etc/shadow` | ✗ | ✗ (in denyRead) |
| Read `/etc/passwd` | ✓ | ✗ (in denyRead) |

## Run the demo

### Without greywall (all writes succeed)

```bash
python demo.py
```

### With greywall (unauthorized operations blocked)

```bash
greywall --settings greywall.json python demo.py
```

## Greywall config

```json
{
  "filesystem": {
    "allowWrite": ["./output"],
    "denyWrite": [".env", "*.key"],
    "denyRead": ["/etc/shadow", "/etc/passwd"]
  }
}
```

### How it works

1. **allowWrite** - Only paths listed here are writable. Everything else is read-only.

2. **denyWrite** - These paths are blocked even if they'd otherwise be allowed. Useful for protecting secrets.

3. **denyRead** - Block reads from sensitive system files.

## Key settings

| Setting | Default | Purpose |
|---------|---------|---------|
| `allowWrite` | `[]` (nothing) | Directories where writes are allowed |
| `denyWrite` | `[]` | Paths to block writes (overrides allowWrite) |
| `denyRead` | `[]` | Paths to block reads |

## Protected paths

Greywall also automatically protects certain paths regardless of config:

- Shell configs: `.bashrc`, `.zshrc`, `.profile`
- Git hooks: `.git/hooks/*`
- Git config: `.gitconfig`

See [ARCHITECTURE.md](../../ARCHITECTURE.md) for the full list.
