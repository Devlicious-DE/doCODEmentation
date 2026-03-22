# doCODEmentation

doCODEmentation is an open-source Python CLI that builds a **living inventory** of Docker Compose–based homelabs and self-hosted stacks.

**Goal:** Documentation should match the real state of your infrastructure with minimal friction—one scan, Git-friendly outputs.

## Why it exists

Manual docs drift. This tool reads your Compose files and emits structured, diffable artifacts you can track in version control.

Principles:

- **Config as source of truth** — not hand-maintained diagrams only
- **Not tied to one reverse proxy** — Traefik labels are optional; fallbacks use ports and other fields
- **Human + machine readable** — YAML, JSON, and Markdown
- **Low friction** — `scan` (and optional `watch`) as the main workflow

## Requirements

- Python **3.11+**

## Installation

```bash
pip install -r requirements.txt
```

Run the CLI either as:

```bash
python docomentation.py --help
```

or via the included wrapper (executable after `chmod +x dcm`):

```bash
./dcm --help
```

## Quick start

Scan a directory of Compose files and write outputs under `./docs`:

```bash
./dcm scan --dir ./path/to/compose --output ./docs
```

Example with the optional `test-data` tree (if present locally):

```bash
./dcm scan --dir ./test-data --output ./docs
```

Outputs:

- `docs/inventory.yaml` — primary, diff-friendly
- `docs/inventory.json` — integrations / APIs
- `docs/inventory.md` — human-readable report

## CLI commands

| Command | Purpose |
|--------|---------|
| `scan` | Scan Compose files and regenerate inventory |
| `watch` | Watch for Compose file changes and rescan |
| `diff` | Compare current vs previous inventory snapshot |
| `add` | Add/update a row in `manual_overrides.yaml` |
| `summary` | Print a terminal summary table (Rich) |
| `audit` | Baseline hardening checks + optional secret hints |

Examples:

```bash
# Scan and optionally commit inventory to git
./dcm scan --dir /volume1/docker --output ./docs --git-commit

./dcm watch --dir /volume1/docker --output ./docs

./dcm diff --output ./docs

./dcm add --name MyService --url https://example.com --note "External" --output ./docs

./dcm summary --output ./docs

./dcm audit --output ./docs
./dcm audit --output ./docs --ignore traefik --ignore homepage

./dcm --version
```

## Identifiers and service metadata

- **Primary service identifier:** `container_name` when set, otherwise the Compose service name (field `name` in inventory).
- **`compose_service_name`:** original key under `services:` in the Compose file.
- **`service_type`:** heuristic classification from the image name: `web`, `database`, `cache`, `proxy`, `monitoring`, `automation`, `media`, `other`.
- **`image_tag`:** literal tag from the image string; if the reference contains `${...}`, it is reported as **`unresolved`** (no substitution is performed).

## Security model

doCODEmentation is built to **avoid leaking secrets**.

**Read:**

- Compose files named `docker-compose.yml`, `docker-compose.yaml`, `compose.yml`, `compose.yaml`
- `manual_overrides.yaml` in the output directory

**Never read (skipped / refused):**

- `.env` and any path ending in `.env`
- `secrets.yaml` / `secrets.yml`
- Any filename containing `secret`

**Behavior:**

- Environment variables: **keys only** in inventory—**never values**
- **`${VAR}` is never resolved** anywhere (tags stay `unresolved` when templated)
- Traefik-style **label values** for obviously sensitive label keys are **redacted** in output
- **Potential hardcoded secrets:** the scanner can flag suspicious `environment` entries (by key name + value heuristics) and report **service + key + warning only**—never the value

Best practice: keep secrets in `.env` (not scanned), Docker/Builtin secrets, or your secret manager—not inline in committed Compose.

## `manual_overrides.yaml`

Placed next to outputs (e.g. `docs/manual_overrides.yaml`). Use it for:

- Manual services not present in scanned Compose
- Policy exceptions (e.g. intentionally privileged reverse proxy)
- Optional score floor for documented exceptions

Example:

```yaml
services:
  - name: traefik
    security_exception: true
    security_exception_reason: "Intentional elevated privileges for Docker socket / proxy orchestration"
    security_score_floor: 75
    note: "Review manually; do not treat like a random misconfiguration."
```

Match **`name`** to the inventory service id (`container_name` or Compose service name).

## Security scoring & audit

- Score is **0–100** heuristic from `no-new-privileges`, `cap_drop`, `read_only`, and `user` (`root` / `non_root` / `unset`).
- **`database`** and **`cache`** types are **not** penalized for missing `cap_drop` (different baseline).
- **`audit`** prints baseline findings and, when present, a **Potential Hardcoded Secrets** table (keys only).
- Services with `security.exception: true` from overrides are skipped in the baseline audit table.

Scores are **signals**, not compliance certification.

## Development & tests

```bash
pip install -r requirements.txt
pytest test_scanner.py
```

CI (GitHub Actions) runs the same test file on push and pull requests.

## Contributing

Issues and PRs welcome. Please avoid changes that would log or persist secret values. See `.github/ISSUE_TEMPLATE/`.

## License

MIT — see [LICENSE](LICENSE).
