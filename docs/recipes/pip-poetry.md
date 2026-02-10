# Recipe: `pip` / `poetry`

Goal: allow Python dependency fetching while keeping egress minimal.

## Start restrictive (PyPI)

```json
{
  "network": {
    "allowedDomains": ["pypi.org", "files.pythonhosted.org"]
  },
  "filesystem": {
    "allowWrite": [".", "/tmp"]
  }
}
```

Run:

```bash
greywall --settings ./greywall.json pip install -r requirements.txt
```

For Poetry:

```bash
greywall --settings ./greywall.json poetry install
```

## Iterate with monitor mode

```bash
greywall -m --settings ./greywall.json poetry install
```

If you use private indexes, add those domains explicitly.
