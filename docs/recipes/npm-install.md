# Recipe: `npm install`

Goal: allow npm to fetch packages, but block unexpected egress.

## Start restrictive

```json
{
  "network": {
    "allowedDomains": ["registry.npmjs.org", "*.npmjs.org"]
  },
  "filesystem": {
    "allowWrite": [".", "node_modules", "/tmp"]
  }
}
```

Run:

```bash
greywall --settings ./greywall.json npm install
```

## Iterate with monitor mode

If installs fail, run:

```bash
greywall -m --settings ./greywall.json npm install
```

Then add the minimum extra domains required for your workflow (private registries, GitHub tarballs, etc.).

Notes:

- If your dependencies fetch binaries during install, you may need to allow additional domains.
- Keep allowlists narrow; prefer specific hostnames over broad wildcards.
