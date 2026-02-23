"""CLI entry point and orchestration for cdnperf."""

from __future__ import annotations

import asyncio
import os
import sys

import click

from cdnperf import __version__
from cdnperf.config import DEFAULT_DELAY_MS, DEFAULT_MAX_HOPS, DEFAULT_SAMPLES, DEFAULT_TIMEOUT, DEFAULT_WARMUP
from cdnperf.models import FullResult, MeasurementConfig


@click.command()
@click.option("-p", "--providers", default="", help="Comma-separated providers [default: all]")
@click.option("-n", "--samples", default=DEFAULT_SAMPLES, help="Samples per provider", show_default=True)
@click.option("-w", "--warmup", default=DEFAULT_WARMUP, help="Warmup requests (discarded)", show_default=True)
@click.option("--no-warmup", is_flag=True, help="Disable warmup")
@click.option("-d", "--delay", default=DEFAULT_DELAY_MS, help="Inter-sample delay in ms", show_default=True)
@click.option("-t", "--timeout", default=DEFAULT_TIMEOUT, help="Request timeout in seconds", show_default=True)
@click.option("--dns-server", default=None, help="Custom DNS server (e.g., 8.8.8.8)")
@click.option("-4", "--ipv4-only", is_flag=True, help="Force IPv4")
@click.option("-6", "--ipv6-only", is_flag=True, help="Force IPv6")
@click.option("--trace/--no-trace", default=True, help="Enable/disable network path tracing", show_default=True)
@click.option("--max-hops", default=DEFAULT_MAX_HOPS, help="Max hops for traceroute", show_default=True)
@click.option("--json", "json_output", is_flag=True, help="Output JSON to stdout")
@click.option("--csv", "csv_output", is_flag=True, help="Output CSV to stdout")
@click.option("-o", "--output", default=None, help="Write results to file")
@click.option("-q", "--quiet", is_flag=True, help="Suppress progress, show only results")
@click.option("-v", "--verbose", is_flag=True, help="Show per-sample details")
@click.option("--no-geo", is_flag=True, help="Skip geolocation lookup")
@click.option("--compare", is_flag=True, help="Show only summary comparison table")
@click.version_option(version=__version__)
def main(
    providers: str,
    samples: int,
    warmup: int,
    no_warmup: bool,
    delay: int,
    timeout: float,
    dns_server: str | None,
    ipv4_only: bool,
    ipv6_only: bool,
    trace: bool,
    max_hops: int,
    json_output: bool,
    csv_output: bool,
    output: str | None,
    quiet: bool,
    verbose: bool,
    no_geo: bool,
    compare: bool,
) -> None:
    """cdnperf — CDN PoP Latency Measurement Tool.

    Measures latency to CDN Points of Presence with per-phase timing
    breakdown (DNS, TCP, TLS, TTFB) and network path tracing with ASN info.
    """
    # Check for proxy warnings
    if not quiet and not json_output and not csv_output:
        for var in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
            if os.environ.get(var):
                from cdnperf.display import render_warning
                render_warning(f"Proxy detected ({var}={os.environ[var]}) — results may not reflect direct CDN routing")
                break

    config = MeasurementConfig(
        providers=[p.strip().lower() for p in providers.split(",") if p.strip()] if providers else [],
        samples=samples,
        warmup=0 if no_warmup else warmup,
        delay_ms=delay,
        timeout=timeout,
        dns_server=dns_server,
        ipv4_only=ipv4_only,
        ipv6_only=ipv6_only,
        trace_enabled=trace,
        max_hops=max_hops,
        verbose=verbose,
        quiet=quiet,
        no_geo=no_geo,
        compare_only=compare,
        json_output=json_output,
        csv_output=csv_output,
        output_file=output,
    )

    try:
        result = asyncio.run(_run(config))
    except KeyboardInterrupt:
        if not quiet and not json_output and not csv_output:
            from cdnperf.display import console
            console.print("\n[yellow]Interrupted.[/yellow]")
        sys.exit(130)

    # Output
    _handle_output(result, config)


async def _run(config: MeasurementConfig) -> FullResult:
    """Main async orchestration."""
    from cdnperf.display import ProgressTracker, console, render_warning
    from cdnperf.engine import measure_all
    from cdnperf.location import get_geolocation
    from cdnperf.providers import get_provider_map, list_providers
    from cdnperf.stats import aggregate_provider_stats
    from cdnperf.trace import trace_all

    # Validate providers
    available = list_providers()
    if config.providers:
        unknown = [p for p in config.providers if p not in available]
        if unknown:
            from cdnperf.display import render_error
            render_error(f"Unknown providers: {', '.join(unknown)}. Available: {', '.join(available)}")
            sys.exit(1)
        slugs = config.providers
    else:
        slugs = available

    # Start geolocation in background
    geo_task = None
    if not config.no_geo:
        geo_task = asyncio.create_task(get_geolocation())

    # Set up progress tracking (only track actual samples, not warmup)
    progress = None
    if not config.quiet and not config.json_output and not config.csv_output:
        progress = ProgressTracker(slugs, config.samples)

    # Progress callback
    def on_progress(provider_slug: str, sample_index: int, total: int, sample_result):
        if progress:
            if sample_result is not None:
                # Sample completed
                completed = sample_index + 1
                if sample_result.error:
                    status = "error" if completed >= total else "sampling"
                elif completed >= total:
                    status = "done"
                else:
                    status = "sampling"
                progress.update(provider_slug, completed, status)
            else:
                # Sample starting
                progress.update(provider_slug, sample_index, "sampling")

    # Run measurements
    if progress:
        console.print(f"[bold]Measuring {len(slugs)} CDN providers, {config.samples} samples each...[/bold]\n")
        progress.start()

    try:
        provider_results = await measure_all(config, progress_callback=on_progress)
    finally:
        if progress:
            progress.finish()

    # Compute statistics
    for pr in provider_results:
        aggregate_provider_stats(pr)

    # Traceroute (concurrent for all providers)
    if config.trace_enabled:
        if not config.quiet and not config.json_output and not config.csv_output:
            console.print(f"\n[bold]Tracing network paths...[/bold]")

        targets = {}
        for pr in provider_results:
            if pr.resolved_ip:
                targets[pr.provider_slug] = pr.resolved_ip

        if targets:
            paths = await trace_all(targets, max_hops=config.max_hops)
            for pr in provider_results:
                if pr.provider_slug in paths:
                    pr.network_path = paths[pr.provider_slug]

    # Collect geolocation
    geo = None
    if geo_task:
        try:
            geo = await geo_task
        except Exception:
            geo = None

    return FullResult(
        geo=geo,
        providers=provider_results,
        config=config,
    )


def _handle_output(result: FullResult, config: MeasurementConfig) -> None:
    """Handle output rendering and export."""
    from cdnperf.display import console, render_comparison, render_full
    from cdnperf.export import export_csv, export_json, write_to_file

    # JSON output
    if config.json_output:
        json_str = export_json(result)
        if config.output_file:
            write_to_file(json_str, config.output_file)
            if not config.quiet:
                console.print(f"[dim]Results written to {config.output_file}[/dim]")
        else:
            click.echo(json_str)
        return

    # CSV output
    if config.csv_output:
        csv_str = export_csv(result)
        if config.output_file:
            write_to_file(csv_str, config.output_file)
            if not config.quiet:
                console.print(f"[dim]Results written to {config.output_file}[/dim]")
        else:
            click.echo(csv_str)
        return

    # Rich terminal output
    if config.compare_only:
        reachable = [p for p in result.providers if p.is_reachable]
        render_comparison(reachable)
    else:
        render_full(result, verbose=config.verbose)

    # Also write to file if -o specified (non-json/csv mode writes JSON)
    if config.output_file:
        json_str = export_json(result)
        write_to_file(json_str, config.output_file)
        console.print(f"\n[dim]Results written to {config.output_file}[/dim]")


if __name__ == "__main__":
    main()
