# Contributing

Beyond code, the most useful contribution most people can make is **hands-on testing against your own hardware** — running beta releases, sharing diagnostics dumps and debug logs from your install when something the integration doesn't cover, and iterating until it works. If you have a device family, a co-branded app, or a feature that isn't supported (video streaming, WaterStop bidirectional control, an unrecognised device family, a new co-branded app, …), see the [Help Wanted section in the README](README.md#help-wanted) for the areas that need community input and how to get involved.

## Development Setup

Everything runs in Docker. No local dependencies needed.

```bash
git clone https://github.com/bvis/aegis-hass.git
cd aegis-hass

# Configure git hooks (one-time; pre-push runs the full CI pipeline locally)
make setup

# Build dev container
make build-docker

# Compile protobuf files
make proto

# Run all checks
make check
```

## Commands

| Command | Description |
|---|---|
| `make setup` | One-time: configure git hooks (`core.hooksPath = .githooks`) |
| `make check` | Run all checks (lint, format, typecheck, tests, dead code) |
| `make test` | Run unit tests with coverage |
| `make test-e2e` | Run E2E tests (requires AJAX_EMAIL + AJAX_PASSWORD) |
| `make lint` | Run linter |
| `make format` | Format code |
| `make typecheck` | Run type checker |
| `make proto` | Compile protobuf files (add `PROTOS="path/rel/to/proto_src.proto"` for just one) |
| `make cli` | Interactive connection test |

## Regenerating protobuf stubs

Two rules, both enforced by `tests/unit/test_proto_gencode_version.py`:

**Always compile through `make proto`, never an ad-hoc `python -m grpc_tools.protoc`.** Every generated stub embeds the version of the compiler that produced it, and protobuf refuses to load a stub built by a version newer than the runtime installed next to it. A stray compiler therefore ships code that raises `VersionError` on import for every user — which is exactly what happened in the 1.15.1 betas (#354). `make proto` verifies the installed `grpcio-tools` matches the exact pin in `pyproject.toml` before writing anything, and refuses to run if it doesn't (rebuild the dev image: `make build-docker`).

**Regenerate only what you changed:** `make proto PROTOS="systems/ajax/.../hub_device.proto"`. A full `make proto` rewrites ~2600 files and buries the real change; a partial one keeps the diff reviewable. Bumping the `grpcio-tools` pin is the exception — that requires a full recompile so the whole tree stays on one version, plus raising the `protobuf`/`grpcio` floors in **both** `manifest.json` and `pyproject.toml` to whatever the new compiler stamps in.

## Commit Conventions

We use [Conventional Commits](https://www.conventionalcommits.org/):

- `feat(scope):` New feature
- `fix(scope):` Bug fix
- `docs:` Documentation
- `chore:` Maintenance
- `refactor:` Code refactoring
- `test:` Tests

## Credentials and secrets

Do not commit FCM credentials (`fcm_project_id`, `fcm_app_id`, `fcm_api_key`, `fcm_sender_id`), Ajax session tokens, OAuth client secrets, or any other credential — in source, tests, fixtures, issues, PR descriptions, or commit messages. Each user supplies their own values through the integration's config flow (Settings → Devices & Services → Aegis for Ajax → Configure) or through the Repair card. See the README's [Where the values live](README.md#where-the-values-live) section for how a user extracts them from their own Ajax mobile app.

Patterns to watch for in `git diff` before staging:

- `AIza[A-Za-z0-9_-]{35}` (Google API key)
- `1:[0-9]+:android:[0-9a-f]+` (Firebase App ID)
- `.env`, `credentials.json`, `*.pem`, `*.p12` files
- Long alphanumeric strings paired with words like `token`, `secret`, or `bearer`

GitHub's secret scanning runs on every push. Alerts on credentials in current code should be fixed by reverting the commit and re-staging without the value.

## Adding a New Device Type

1. Find the device's `ObjectType` variant in the proto files
2. Add the mapping to `_DEVICE_TYPE_SENSORS` in `binary_sensor.py`
3. If it has switch/relay capabilities, add to `SWITCH_DEVICE_TYPES` in `switch.py`
4. Write tests for the new mappings
5. Update `README.md` device table

## E2E Testing

```bash
AJAX_EMAIL=your@email.com AJAX_PASSWORD=yourpass make test-e2e
```

Destructive tests (arm/disarm) are skipped by default. To run them:

```bash
AJAX_EMAIL=... AJAX_PASSWORD=... pytest tests/e2e/ -v -m "e2e"
```
