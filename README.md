# semgrep-sift 🔍

A standalone tool to export your Semgrep Cloud findings by date range. Includes a modern web UI and a rich terminal CLI.

## Features

- 🌐 **Web UI** — Enter your token, pick a date range, and download findings as JSON or CSV
- 💻 **CLI** — Headless or interactive terminal mode with beautiful tables and progress spinners
- 🐳 **Docker** — One-command deployment on port 8085

## Quick Start

### Web UI (Docker)

```bash
docker compose up --build
```

Open http://localhost:8085

### CLI

```bash
# Interactive mode
python src/cli.py

# Headless mode
python src/cli.py --token <TOKEN> --start-date 2025-01-01 --end-date 2025-03-01 --format csv -o findings

# Show help
python src/cli.py --help
```

## CLI Options

| Flag | Description |
|------|-------------|
| `--token` | Semgrep API token |
| `--start-date` | Start date (YYYY-MM-DD) |
| `--end-date` | End date (YYYY-MM-DD) |
| `--format` | `json` or `csv` (default: `json`) |
| `--output`, `-o` | Output file path |
| `--no-interactive` | Fail if required args are missing |
| `--preview` | Show first 10 findings as a table |
| `--help` | Show help message and exit |

## Troubleshooting

### "Invalid Semgrep API token" or 401 errors

semgrep-sift requires a **Semgrep AppSec Platform API token**, not the token from `semgrep login`.
Generate the correct token at: `https://semgrep.dev/orgs/-/settings/tokens`

### 500 / 502 errors when fetching findings

If you see a message like:

> *Semgrep's findings API returned a 500 server error*

This means Semgrep's own REST API is experiencing an internal error for your deployment. This is outside of semgrep-sift's control.
**What to do:**
- Wait a few minutes and try again
- Contact Semgrep support at `support@semgrep.com` and mention the `/api/v1/deployments/{slug}/findings` endpoint

## License

MIT
