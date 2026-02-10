# Greywall Examples

Runnable examples demonstrating `greywall` capabilities.

If you're looking for copy/paste configs and "cookbook" workflows, also see:

- Config templates: [`docs/templates/`](../docs/templates/)
- Recipes for common workflows: [`docs/recipes/`](../docs/recipes/)

## Examples

| Example | What it demonstrates | How to run |
|--------|-----------------------|------------|
| **[01-dev-server](01-dev-server/README.md)** | Running a dev server in the sandbox, controlling external domains vs localhost outbound (Redis), and exposing an inbound port (`-p`) | `cd examples/01-dev-server && greywall -p 3000 --settings greywall-external-blocked.json npm start` |
| **[02-filesystem](02-filesystem/README.md)** | Filesystem controls: `allowWrite`, `denyWrite`, `denyRead` | `cd examples/02-filesystem && greywall --settings greywall.json python demo.py` |
