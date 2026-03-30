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

## License

MIT
