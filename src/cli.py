import datetime
import sys
from pathlib import Path
from typing import Optional

import httpx
import typer
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table

from src.shared.export import findings_to_csv, findings_to_json
from src.shared.models import Finding
from src.shared.semgrep_cloud import SemgrepCloudClient

app = typer.Typer(help="semgrep-sift: Export your Semgrep Cloud findings")
console = Console()


def _banner() -> None:
    console.print(
        Panel.fit(
            "[bold green]semgrep-sift[/bold green]\nExport your Semgrep Cloud findings\nRun with [cyan]--help[/cyan] for options",
            border_style="indigo",
        )
    )


@app.command()
def main(
    token: Optional[str] = typer.Option(None, "--token", help="Semgrep API token"),
    start_date: Optional[datetime.date] = typer.Option(None, "--start-date", help="Start date (YYYY-MM-DD)"),
    end_date: Optional[datetime.date] = typer.Option(None, "--end-date", help="End date (YYYY-MM-DD)"),
    format: str = typer.Option("json", "--format", help="Output format: json or csv"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output file path (default: stdout)"),
    no_interactive: bool = typer.Option(False, "--no-interactive", help="Fail if required args are missing"),
    preview: bool = typer.Option(False, "--preview", help="Show preview table of first 10 findings"),
) -> None:
    if not sys.argv[1:]:
        _banner()

    if not token:
        if no_interactive:
            console.print("[red]Error:[/red] --token is required in non-interactive mode", style="bold red")
            raise typer.Exit(code=2)
        token = Prompt.ask("Enter your Semgrep API token", password=True)

    if not token:
        console.print("[red]Error:[/red] Token is required", style="bold red")
        raise typer.Exit(code=2)

    client = SemgrepCloudClient(token)

    with console.status("[bold indigo]Fetching deployments...") as status:
        sync_client = httpx.Client(timeout=60.0)
        try:
            deployments = client.get_deployments(sync_client)
        except httpx.HTTPStatusError as exc:
            sync_client.close()
            if exc.response.status_code == 401:
                console.print("[red]Error:[/red] Invalid Semgrep API token", style="bold red")
            else:
                console.print(f"[red]Error:[/red] Semgrep API returned {exc.response.status_code}", style="bold red")
            raise typer.Exit(code=1)
        except Exception as exc:
            sync_client.close()
            console.print(f"[red]Error:[/red] Could not reach Semgrep Cloud: {exc}", style="bold red")
            raise typer.Exit(code=1)

    if not deployments:
        sync_client.close()
        console.print("[yellow]Warning:[/yellow] No deployments found for this token", style="bold yellow")
        raise typer.Exit(code=0)

    deployment_id = str(deployments[0]["id"])
    status.update(f"[bold indigo]Fetching findings for deployment {deployment_id}...")

    try:
        raw_findings = client.fetch_findings(
            sync_client,
            deployment_id=deployment_id,
            start_date=start_date,
            end_date=end_date,
        )
    except Exception as exc:
        sync_client.close()
        console.print(f"[red]Error:[/red] Failed to fetch findings: {exc}", style="bold red")
        raise typer.Exit(code=1)
    finally:
        sync_client.close()

    findings = [Finding(**f) for f in raw_findings]

    if format == "csv":
        content = findings_to_csv(findings)
        ext = "csv"
    else:
        content = findings_to_json(findings)
        ext = "json"

    if output:
        output_path = output if str(output).endswith(f".{ext}") else Path(f"{output}.{ext}")
        output_path.write_text(content)
        console.print(f"[green]\u2714[/green] Saved {len(findings)} findings to [cyan]{output_path}[/cyan]")
    else:
        console.print(content)

    if preview and findings:
        table = Table(title=f"First {min(10, len(findings))} findings")
        table.add_column("Rule", style="cyan")
        table.add_column("Severity", style="magenta")
        table.add_column("Path", style="green")
        table.add_column("Repo", style="yellow")
        for f in findings[:10]:
            table.add_row(f.rule_name, f.severity, f.path, f.repository)
        console.print(table)

    if findings:
        sev_counts = {}
        for f in findings:
            sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
        summary = Table.grid()
        summary.add_column(style="bold")
        summary.add_column()
        for sev, cnt in sorted(sev_counts.items()):
            summary.add_row(f"{sev}:", str(cnt))
        console.print(Panel(summary, title="Summary", border_style="green"))


if __name__ == "__main__":
    app()
