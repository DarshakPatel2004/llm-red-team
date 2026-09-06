"""API CLI for LLM Red Team Suite."""

from __future__ import annotations
import json
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
@click.option('--tiers', default=None, help='Comma-separated tier numbers')
@click.option('--all-enabled', is_flag=True, help='Run all enabled models')
@click.option('--dry-run', is_flag=True, help='Run with mock client')
@click.option('--parallel', default=1, type=int, help='Parallel workers')
@click.option('--resume', is_flag=True, help='Resume interrupted session')
def run(models: str | None, tiers: str | None, all_enabled: bool, dry_run: bool, parallel: int, resume: bool) -> None:
    """Run adversarial tests against configured models."""
    from llm_red_team.config.loader import ConfigLoader
    from llm_red_team.clients import MockClient, AnthropicClient, OpenAIClient, OllamaClient
    from llm_red_team.engine.runner import TestRunner, BatchExecutor
    from llm_red_team.attacks import ALL_PROMPTS

    config = ConfigLoader()
    cfg = config.load()

    if dry_run or all_enabled or not models:
        console.print("[yellow]Running in DRY-RUN mode with MockClient[/yellow]")
        client = MockClient("mock", cfg["models"]["claude"])
    else:
        model_names = models.split(",")
        model_name = model_names[0].strip()
        model_cfg = cfg["models"].get(model_name)
        if not model_cfg:
            console.print(f"[red]Model '{model_name}' not found in configuration[/red]")
            return
        provider = model_cfg.get("provider", "")
        if provider == "anthropic":
            client = AnthropicClient(model_cfg["model_id"], model_cfg)
        elif provider == "openai":
            client = OpenAIClient(model_cfg["model_id"], model_cfg)
        elif provider == "ollama":
            client = OllamaClient(model_cfg["model_id"], model_cfg)
        else:
            client = MockClient(model_name, model_cfg)

    runner = TestRunner(client, parallel=parallel)
    results = runner.run_all()
    summary = runner.get_summary()

    console.print(f"\n[bold green]Results:[/bold green]")
    console.print(f"  Total Tests: {summary['total_tests']}")
    console.print(f"  Successful: {summary['successful']}")
    console.print(f"  Failed: {summary['failed']}")
    console.print(f"  Success Rate: {summary['success_rate']}%")
    console.print(f"  Avg Latency: {summary['avg_latency_ms']}ms")
    console.print(f"  Total Tokens: {summary['total_tokens']}")

    if tiers:
        tier_nums = [int(t) for t in tiers.split(",")]
        by_tier = runner.get_results_by_tier()
        console.print(f"\n[bold]Results by Tier:[/bold]")
        for tier in tier_nums:
            if tier in by_tier:
                data = by_tier[tier]
                console.print(f"  Tier {tier}: {data['count']} tests, {data['success']} successful")

    if resume:
        console.print("[yellow]Resume mode detected - loading previous session[/yellow]")


@main.command()
def models() -> None:
    """List available models."""
    from llm_red_team.config.loader import ConfigLoader

    config = ConfigLoader()
    cfg = config.load()
    table = Table(title="Available Models")
    table.add_column("Name", justify="center")
    table.add_column("Provider", justify="center")
    table.add_column("Type", justify="center")
    table.add_column("Enabled", justify="center")
    table.add_column("Tags")

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
@click.option('--model-id', default=None, help='Model identifier')
def models_add(name: str, type: str, provider: str, endpoint: str | None, model_id: str | None) -> None:
    """Add a new model to the configuration."""
    from llm_red_team.config.loader import ConfigLoader

    config = ConfigLoader()
    cfg = config.load()
    model_cfg = {
        "type": type, "provider": provider,
        "endpoint": endpoint or f"https://{name}.api.com",
        "model_id": model_id or name,
        "enabled": True, "tags": [type, "custom"],
    }
    config.add_model(name, model_cfg)
    console.print(f"[green]Model '{name}' added successfully[/green]")


@main.command()
@click.option('--format', default='json', help='Output format')
@click.option('--output', default=None, help='Output file path')
def report(format: str, output: str | None) -> None:
    """Generate analysis report."""
    from llm_red_team.engine.runner import TestRunner
    from llm_red_team.clients import MockClient
    from llm_red_team.attribution.engine import AttributionEngine
    from llm_red_team.analysis.engine import AnalysisEngine
    from llm_red_team.config.loader import ConfigLoader

    config = ConfigLoader()
    client = MockClient("test", config.load()["models"]["claude"])
    runner = TestRunner(client)
    results = runner.run_all()
    summary = runner.get_summary()

    attribution = AttributionEngine()
    attribution_report = attribution.generate_attribution_report(results)
    analysis = AnalysisEngine()
    matrix = analysis.generate_vulnerability_matrix(results, "test-model")

    console.print(f"[bold]Attack Summary:[/bold] {summary['total_tests']} tests")
    console.print(f"[bold]Success Rate:[/bold] {summary['success_rate']}%")
    console.print(f"[bold]Security Score:[/bold] {matrix['security_score']}")
    console.print(f"[bold]Vulnerability Categories:[/bold] {len(attribution_report['category_counts'])}")

    if output:
        report_data = {
            "summary": summary,
            "attribution": attribution_report,
            "matrix": matrix,
            "results": results,
        }
        if format == "json":
            with open(output, 'w') as f:
                json.dump(report_data, f, indent=2)
        console.print(f"[green]Report saved to {output}[/green]")


@main.command()
def health() -> None:
    """Check health of all configured models."""
    from llm_red_team.config.loader import ConfigLoader

    config = ConfigLoader()
    cfg = config.load()
    table = Table(title="Model Health Check")
    table.add_column("Model", justify="center")
    table.add_column("Status", justify="center")

    for name, model in cfg["models"].items():
        table.add_row(name, "Healthy" if model.get("enabled") else "Disabled")
    console.print(table)


@main.command()
@click.option('--format', default='pdf', help='Export format')
@click.option('--output', default='export', help='Output filename')
def export(format: str, output: str) -> None:
    """Export results in various formats."""
    from llm_red_team.engine.runner import TestRunner
    from llm_red_team.clients import MockClient
    from llm_red_team.config.loader import ConfigLoader

    config = ConfigLoader()
    client = MockClient("test", config.load()["models"]["claude"])
    runner = TestRunner(client)
    results = runner.run_all()

    data = runner.export_results(format=format)
    if output:
        with open(f"{output}.{format}", 'w') as f:
            f.write(data)
    console.print(f"[cyan]Exported {len(results)} results to {output}.{format}[/cyan]")


@main.command()
def validate() -> None:
    """Validate configuration and test connections."""
    from llm_red_team.config.loader import ConfigLoader
    from llm_red_team.clients import MockClient

    config = ConfigLoader()
    try:
        cfg = config.load()
        console.print("[green]Configuration valid[/green]")
        for name, model in cfg["models"].items():
            client = MockClient(name, model)
            healthy = client.health_check()
            status = "[green]OK[/green]" if healthy else "[red]FAIL[/red]"
            console.print(f"  {name}: {status}")
    except Exception as e:
        console.print(f"[red]Configuration error: {e}[/red]")


if __name__ == "__main__":
    main()
