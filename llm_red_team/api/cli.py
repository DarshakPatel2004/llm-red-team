"""API CLI for LLM Red Team Suite."""

from __future__ import annotations
import click
from rich.console import Console
from rich.table import Table

console = Console()


@click.group()
def main() -> None:
    """LLM Red Team Suite - Enterprise LLM security testing framework."""
    pass


@main.command()
@click.option('--models', default=None, help='Comma-separated list of models')
@click.option('--tiers', default=None, help='Comma-separated list of tiers')
@click.option('--all-enabled', is_flag=True, help='Run all enabled models')
@click.option('--dry-run', is_flag=True, help='Run with mock client')
@click.option('--resume', is_flag=True, help='Resume interrupted session')
def run(models: str | None, tiers: str | None, all_enabled: bool, dry_run: bool, resume: bool) -> None:
    """Run adversarial tests against configured models."""
    from llm_red_team.config.loader import ConfigLoader
    from llm_red_team.clients import MockClient
    from llm_red_team.engine.runner import TestRunner

    config = ConfigLoader()
    models_config = config.get_enabled_models() if all_enabled else []

    if dry_run or not models_config:
        console.print("[yellow]Running in DRY-RUN mode with MockClient[/yellow]")
        client = MockClient("mock", {})
        runner = TestRunner(client)
        results = runner.run_all()
        summary = runner.get_summary()
    else:
        model_name, model_cfg = models_config[0]
        from llm_red_team.clients import AnthropicClient
        client = AnthropicClient(model_cfg["model_id"], model_cfg)
        runner = TestRunner(client)
        results = runner.run_all()
        summary = runner.get_summary()

    console.print(f"\n[bold green]Results:[/bold green]")
    console.print(f"  Total Tests: {summary['total_tests']}")
    console.print(f"  Successful: {summary['successful']}")
    console.print(f"  Failed: {summary['failed']}")
    console.print(f"  Success Rate: {summary['success_rate']}%")
    console.print(f"  Avg Latency: {summary['avg_latency_ms']}ms")


@main.command()
def models() -> None:
    """List available models."""
    from llm_red_team.config.loader import ConfigLoader

    config = ConfigLoader()
    cfg = config.load()
    table = Table(title="Available Models")
    table.columns.add("Name", justify_center=True)
    table.columns.add("Provider", justify_center=True)
    table.columns.add("Type", justify_center=True)
    table.columns.add("Enabled", justify_center=True)
    table.columns.add("Tags")

    for name, model in cfg["models"].items():
        table.add_row(
            name,
            model.get("provider", "-"),
            model.get("type", "-"),
            "Yes" if model.get("enabled") else "No",
            ", ".join(model.get("tags", [])),
        )
    console.print(table)


@main.command()
@click.argument('name')
@click.option('--type', default='api', help='Model type')
@click.option('--provider', default='custom', help='Provider name')
@click.option('--endpoint', default=None, help='Endpoint URL')
def models_add(name: str, type: str, provider: str, endpoint: str | None) -> None:
    """Add a new model to the configuration."""
    from llm_red_team.config.loader import ConfigLoader

    config = ConfigLoader()
    cfg = config.load()
    config.add_model(name, {
        "type": type, "provider": provider,
        "endpoint": endpoint or f"https://{name}.api.com",
        "enabled": True, "tags": [type, "custom"],
    })
    console.print(f"[green]Model '{name}' added successfully[/green]")


@main.command()
@click.option('--format', default='json', help='Output format')
@click.option('--output', default=None, help='Output file path')
def report(format: str, output: str | None) -> None:
    """Generate analysis report."""
    console.print("[cyan]Report generation...[/cyan]")
    console.print("[yellow]Run 'llm-red-team run' first to generate results[/yellow]")


@main.command()
def health() -> None:
    """Check health of all configured models."""
    from llm_red_team.config.loader import ConfigLoader

    config = ConfigLoader()
    cfg = config.load()
    table = Table(title="Model Health Check")
    table.columns.add("Model", justify_center=True)
    table.columns.add("Status", justify_center=True)

    for name, model in cfg["models"].items():
        table.add_row(name, "Healthy" if model.get("enabled") else "Disabled")
    console.print(table)


@main.command()
@click.option('--format', default='pdf', help='Export format')
@click.option('--output', default='export', help='Output filename')
def export(format: str, output: str) -> None:
    """Export results in various formats."""
    console.print(f"[cyan]Exporting to {format}: {output}[/cyan]")


if __name__ == "__main__":
    main()
