"""APSec Tester command-line interface.

This module is the ONLY place allowed to terminate the process. Every other
layer raises typed exceptions (APSecError subclasses); the CLI catches them,
prints a clean message and maps them to a documented exit code.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import List, Optional

import typer

from apsec import __app_name__, __version__
from apsec.core import console as c
from apsec.core.config import ExitCode, parse_severity
from apsec.core.errors import APSecError, SpecLoadError, SpecValidationError
from apsec.core.logger import configure as configure_logging
from apsec.core.scope import OutOfScopeError, load_scope
from apsec.parsers.openapi import load_openapi
from apsec.parsers.postman import load_postman
from apsec.flow import FlowEngine, load_flow
from apsec.recon import Asset, ReconEngine
from apsec.reporters import render_console, write_html, write_json, write_markdown
from apsec.reporters.bounty_reporter import load_result_dict, write_bounty
from apsec.scanner import ScanEngine, ScanResult, Severity
from apsec.scanner.live import LiveScanEngine
from apsec.scanner.live.rules import load_rules
from apsec.scanner.injection import InjectionEngine
from apsec.chaos import ChaosEngine
from apsec.ai import narrative, prioritize
from apsec.crawl import crawl as crawl_site

app = typer.Typer(
    name=__app_name__,
    help="APSec Tester — security-first API security scanner.",
    add_completion=False,
    no_args_is_help=True,
)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"{__app_name__} {__version__}")
        raise typer.Exit()


def _resolve_gate(fail_on: str) -> Severity:
    """Parse the --fail-on gate, exiting cleanly on a bad value."""
    try:
        return parse_severity(fail_on)
    except KeyError:
        c.error(
            f"Unknown --fail-on value: {fail_on!r}. "
            "Use one of: info, low, medium, high, critical."
        )
        raise typer.Exit(code=ExitCode.USAGE_ERROR)


def _emit_reports(
    result: ScanResult,
    *,
    quiet: bool,
    json_out: Optional[Path],
    md_out: Optional[Path],
    html_out: Optional[Path],
) -> None:
    """Render the console report and write any requested file formats."""
    if not quiet:
        render_console(result)

    writers = (
        (json_out, write_json, "JSON"),
        (md_out, write_markdown, "Markdown"),
        (html_out, write_html, "HTML"),
    )
    for path, writer, label in writers:
        if path is None:
            continue
        try:
            written = writer(result, path)
            c.ok(f"{label} report written to {written}")
        except APSecError as exc:
            c.error(str(exc))
            raise typer.Exit(code=ExitCode.RUNTIME_ERROR)


def _gate_exit(result: ScanResult, gate: Severity) -> None:
    """Exit non-zero when findings meet/exceed the gate."""
    if result.findings and result.highest_severity >= gate:
        raise typer.Exit(code=ExitCode.FINDINGS_OVER_GATE)
    raise typer.Exit(code=ExitCode.OK)


@app.callback()
def main(
    version: Optional[bool] = typer.Option(
        None,
        "--version",
        "-V",
        help="Show version and exit.",
        callback=_version_callback,
        is_eager=True,
    ),
) -> None:
    """APSec Tester root command."""


@app.command()
def scan(
    spec: Path = typer.Argument(
        ...,
        exists=False,
        help="Path to an OpenAPI 3.x document (.json/.yaml/.yml).",
    ),
    fail_on: str = typer.Option(
        "high", "--fail-on", "-f",
        help="Minimum severity that makes the scan exit non-zero.",
    ),
    json_out: Optional[Path] = typer.Option(None, "--json", "-j", help="Write a JSON report."),
    md_out: Optional[Path] = typer.Option(None, "--md", "-m", help="Write a Markdown report."),
    html_out: Optional[Path] = typer.Option(None, "--html", help="Write an HTML report."),
    no_deep: bool = typer.Option(
        False, "--no-deep", help="Skip openapi-spec-validator deep validation."
    ),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress the console report."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable debug logging."),
) -> None:
    """Statically scan an OpenAPI contract for security issues."""
    configure_logging(verbose=verbose)
    gate = _resolve_gate(fail_on)

    try:
        doc = load_openapi(spec, deep=not no_deep)
    except (SpecLoadError, SpecValidationError) as exc:
        c.error(str(exc))
        raise typer.Exit(code=ExitCode.SPEC_ERROR)
    except APSecError as exc:
        c.error(str(exc))
        raise typer.Exit(code=ExitCode.RUNTIME_ERROR)

    try:
        result = ScanEngine().scan(doc)
    except APSecError as exc:
        c.error(str(exc))
        raise typer.Exit(code=ExitCode.RUNTIME_ERROR)

    _emit_reports(result, quiet=quiet, json_out=json_out, md_out=md_out, html_out=html_out)
    _gate_exit(result, gate)


@app.command()
def probe(
    url: Optional[str] = typer.Argument(
        None, help="Base URL of the running API to probe (e.g. https://api.example.com)."
    ),
    postman: Optional[Path] = typer.Option(
        None, "--postman", "-p",
        help="Postman collection to derive the base URL from (used if URL omitted).",
    ),
    scope_file: Optional[Path] = typer.Option(
        None, "--scope", "-s",
        help="Scope YAML; the target is refused unless it is in scope.",
    ),
    mode: str = typer.Option("full", "--mode", help="Scan depth: quick | full."),
    rules: Optional[Path] = typer.Option(
        None, "--rules", "-r", help="YAML file of custom rules to evaluate."
    ),
    fail_on: str = typer.Option(
        "high", "--fail-on", "-f",
        help="Minimum severity that makes the probe exit non-zero.",
    ),
    json_out: Optional[Path] = typer.Option(None, "--json", "-j", help="Write a JSON report."),
    md_out: Optional[Path] = typer.Option(None, "--md", "-m", help="Write a Markdown report."),
    html_out: Optional[Path] = typer.Option(None, "--html", help="Write an HTML report."),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress the console report."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable debug logging."),
) -> None:
    """Actively probe a running API for live security issues."""
    configure_logging(verbose=verbose)
    gate = _resolve_gate(fail_on)

    if mode not in ("quick", "full"):
        c.error(f"Unknown --mode {mode!r}. Use 'quick' or 'full'.")
        raise typer.Exit(code=ExitCode.USAGE_ERROR)

    target = url
    if target is None and postman is not None:
        try:
            collection = load_postman(postman)
        except APSecError as exc:
            c.error(str(exc))
            raise typer.Exit(code=ExitCode.SPEC_ERROR)
        target = collection.base_url
        if target is None:
            c.error("Could not derive a base URL from the Postman collection.")
            raise typer.Exit(code=ExitCode.USAGE_ERROR)
        c.info(f"Derived target from Postman collection: {target}")

    if not target:
        c.error("Provide a URL argument or --postman collection to probe.")
        raise typer.Exit(code=ExitCode.USAGE_ERROR)

    # Safety gate: refuse anything outside an authorized scope.
    if scope_file is not None:
        try:
            scope = load_scope(scope_file)
            scope.assert_in_scope(target)
        except OutOfScopeError as exc:
            c.error(str(exc))
            raise typer.Exit(code=ExitCode.USAGE_ERROR)
        except APSecError as exc:
            c.error(str(exc))
            raise typer.Exit(code=ExitCode.SPEC_ERROR)
        c.ok(f"Target is in scope: {target}")

    custom_rules = []
    if rules is not None:
        try:
            custom_rules = load_rules(rules)
        except APSecError as exc:
            c.error(str(exc))
            raise typer.Exit(code=ExitCode.SPEC_ERROR)

    try:
        result = LiveScanEngine(mode=mode, custom_rules=custom_rules).scan(target)
    except APSecError as exc:
        c.error(str(exc))
        raise typer.Exit(code=ExitCode.RUNTIME_ERROR)

    _emit_reports(result, quiet=quiet, json_out=json_out, md_out=md_out, html_out=html_out)
    _gate_exit(result, gate)


def _render_recon(assets: list[Asset]) -> None:
    """Print a compact recon table."""
    c.banner("APSec Tester — Recon")
    print()
    alive = [a for a in assets if a.alive]
    c.info(f"Discovered {len(assets)} in-scope host(s), {len(alive)} alive")
    print()
    for a in assets:
        mark = c.paint("●", c.G) if a.alive else c.paint("○", c.Gr)
        head = f"{mark} {a.host}"
        if a.alive:
            meta = f"[{a.scheme} {a.status}]"
            extra = f" {a.title}" if a.title else ""
            srv = f" ({a.server})" if a.server else ""
            print(f"{head}  {c.paint(meta, c.C)}{srv}{extra}")
        else:
            print(f"{head}  {c.paint('unresponsive', c.Gr)}")
        c.dim(f"    {', '.join(a.addresses)}")


@app.command()
def recon(
    scope_file: Path = typer.Argument(
        ..., help="Scope YAML (include/exclude). Recon runs ONLY inside this scope."
    ),
    wordlist: Optional[Path] = typer.Option(
        None, "--wordlist", "-w", help="Optional subdomain wordlist (one word per line)."
    ),
    concurrency: int = typer.Option(20, "--concurrency", "-c", help="Max parallel hosts."),
    json_out: Optional[Path] = typer.Option(None, "--json", "-j", help="Write assets as JSON."),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress the console table."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable debug logging."),
) -> None:
    """Discover in-scope assets (passive CT logs + optional wordlist)."""
    configure_logging(verbose=verbose)

    try:
        scope = load_scope(scope_file)
    except APSecError as exc:
        c.error(str(exc))
        raise typer.Exit(code=ExitCode.SPEC_ERROR)

    words: list[str] = []
    if wordlist is not None:
        try:
            words = [w.strip() for w in wordlist.read_text(encoding="utf-8").splitlines() if w.strip()]
        except OSError as exc:
            c.error(f"Could not read wordlist {wordlist}: {exc}")
            raise typer.Exit(code=ExitCode.SPEC_ERROR)

    try:
        engine = ReconEngine(scope, wordlist=words, concurrency=concurrency)
        assets = asyncio.run(engine.run())
    except APSecError as exc:
        c.error(str(exc))
        raise typer.Exit(code=ExitCode.RUNTIME_ERROR)

    if not quiet:
        _render_recon(assets)

    if json_out is not None:
        try:
            Path(json_out).parent.mkdir(parents=True, exist_ok=True)
            Path(json_out).write_text(
                json.dumps([a.to_dict() for a in assets], indent=2), encoding="utf-8"
            )
            c.ok(f"Recon JSON written to {json_out}")
        except OSError as exc:
            c.error(f"Could not write {json_out}: {exc}")
            raise typer.Exit(code=ExitCode.RUNTIME_ERROR)

    raise typer.Exit(code=ExitCode.OK)


@app.command()
def flow(
    flow_file: Path = typer.Argument(
        ..., help="Abuse-case flow YAML (identities + steps) to detect BOLA/IDOR."
    ),
    base_url: Optional[str] = typer.Option(
        None, "--base-url", "-u", help="Base URL (overrides base_url in the flow file)."
    ),
    scope_file: Optional[Path] = typer.Option(
        None, "--scope", "-s", help="Scope YAML; the base URL is refused unless in scope."
    ),
    fail_on: str = typer.Option(
        "high", "--fail-on", "-f", help="Minimum severity that makes the run exit non-zero."
    ),
    json_out: Optional[Path] = typer.Option(None, "--json", "-j", help="Write a JSON report."),
    md_out: Optional[Path] = typer.Option(None, "--md", "-m", help="Write a Markdown report."),
    html_out: Optional[Path] = typer.Option(None, "--html", help="Write an HTML report."),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress the console report."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable debug logging."),
) -> None:
    """Run authorization abuse cases (BOLA/IDOR, broken auth) from a flow file."""
    configure_logging(verbose=verbose)
    gate = _resolve_gate(fail_on)

    try:
        flow_def = load_flow(flow_file)
    except APSecError as exc:
        c.error(str(exc))
        raise typer.Exit(code=ExitCode.SPEC_ERROR)

    scope = None
    if scope_file is not None:
        try:
            scope = load_scope(scope_file)
        except APSecError as exc:
            c.error(str(exc))
            raise typer.Exit(code=ExitCode.SPEC_ERROR)

    try:
        engine = FlowEngine(flow_def, base_url=base_url, scope=scope)
        result = asyncio.run(engine.run())
    except OutOfScopeError as exc:
        c.error(str(exc))
        raise typer.Exit(code=ExitCode.USAGE_ERROR)
    except APSecError as exc:
        c.error(str(exc))
        raise typer.Exit(code=ExitCode.RUNTIME_ERROR)

    _emit_reports(result, quiet=quiet, json_out=json_out, md_out=md_out, html_out=html_out)
    _gate_exit(result, gate)


@app.command()
def fuzz(
    urls: Optional[List[str]] = typer.Argument(
        None, help="Parameterized URLs to fuzz, e.g. 'https://x/api?id=1'."
    ),
    url_file: Optional[Path] = typer.Option(
        None, "--url-file", "-U", help="File with one URL per line."
    ),
    scope_file: Optional[Path] = typer.Option(
        None, "--scope", "-s", help="Scope YAML; out-of-scope URLs are skipped."
    ),
    fail_on: str = typer.Option(
        "high", "--fail-on", "-f", help="Minimum severity that makes the run exit non-zero."
    ),
    json_out: Optional[Path] = typer.Option(None, "--json", "-j", help="Write a JSON report."),
    md_out: Optional[Path] = typer.Option(None, "--md", "-m", help="Write a Markdown report."),
    html_out: Optional[Path] = typer.Option(None, "--html", help="Write an HTML report."),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress the console report."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable debug logging."),
) -> None:
    """Fuzz URL parameters for SQL injection and reflected XSS."""
    configure_logging(verbose=verbose)
    gate = _resolve_gate(fail_on)

    targets: list[str] = list(urls or [])
    if url_file is not None:
        try:
            targets += [ln.strip() for ln in url_file.read_text(encoding="utf-8").splitlines() if ln.strip()]
        except OSError as exc:
            c.error(f"Could not read URL file {url_file}: {exc}")
            raise typer.Exit(code=ExitCode.SPEC_ERROR)
    if not targets:
        c.error("Provide at least one URL argument or a --url-file.")
        raise typer.Exit(code=ExitCode.USAGE_ERROR)

    scope = None
    if scope_file is not None:
        try:
            scope = load_scope(scope_file)
        except APSecError as exc:
            c.error(str(exc))
            raise typer.Exit(code=ExitCode.SPEC_ERROR)

    try:
        result = asyncio.run(InjectionEngine(scope=scope).scan(targets))
    except APSecError as exc:
        c.error(str(exc))
        raise typer.Exit(code=ExitCode.RUNTIME_ERROR)

    _emit_reports(result, quiet=quiet, json_out=json_out, md_out=md_out, html_out=html_out)
    _gate_exit(result, gate)


@app.command()
def chaos(
    url: str = typer.Argument(..., help="Target URL to fault-test for info leakage."),
    scope_file: Optional[Path] = typer.Option(
        None, "--scope", "-s", help="Scope YAML; the target is refused unless in scope."
    ),
    fail_on: str = typer.Option(
        "medium", "--fail-on", "-f", help="Minimum severity that makes the run exit non-zero."
    ),
    json_out: Optional[Path] = typer.Option(None, "--json", "-j", help="Write a JSON report."),
    md_out: Optional[Path] = typer.Option(None, "--md", "-m", help="Write a Markdown report."),
    html_out: Optional[Path] = typer.Option(None, "--html", help="Write an HTML report."),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress the console report."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable debug logging."),
) -> None:
    """Induce faults and detect stack-trace / internal-path disclosure."""
    configure_logging(verbose=verbose)
    gate = _resolve_gate(fail_on)

    scope = None
    if scope_file is not None:
        try:
            scope = load_scope(scope_file)
        except APSecError as exc:
            c.error(str(exc))
            raise typer.Exit(code=ExitCode.SPEC_ERROR)

    try:
        result = asyncio.run(ChaosEngine(scope=scope).scan(url))
    except OutOfScopeError as exc:
        c.error(str(exc))
        raise typer.Exit(code=ExitCode.USAGE_ERROR)
    except APSecError as exc:
        c.error(str(exc))
        raise typer.Exit(code=ExitCode.RUNTIME_ERROR)

    _emit_reports(result, quiet=quiet, json_out=json_out, md_out=md_out, html_out=html_out)
    _gate_exit(result, gate)


@app.command()
def report(
    json_report: Path = typer.Argument(
        ..., help="A JSON report saved by scan/probe/flow/fuzz/chaos (--json)."
    ),
    md_out: Path = typer.Option(
        Path("bounty-report.md"), "--md", "-m", help="Where to write the bounty-ready Markdown."
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable debug logging."),
) -> None:
    """Convert a JSON report into a bounty-ready (HackerOne-style) Markdown."""
    configure_logging(verbose=verbose)
    try:
        data = load_result_dict(json_report)
        written = write_bounty(data, md_out)
    except APSecError as exc:
        c.error(str(exc))
        raise typer.Exit(code=ExitCode.SPEC_ERROR)
    c.ok(f"Bounty-ready report written to {written}")
    raise typer.Exit(code=ExitCode.OK)


@app.command()
def triage(
    json_report: Path = typer.Argument(
        ..., help="A JSON report saved by any engine (--json)."
    ),
    top: int = typer.Option(10, "--top", "-n", help="How many ranked findings to show."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable debug logging."),
) -> None:
    """Prioritize findings by exploitability / bounty value (offline)."""
    configure_logging(verbose=verbose)
    try:
        data = load_result_dict(json_report)
    except APSecError as exc:
        c.error(str(exc))
        raise typer.Exit(code=ExitCode.SPEC_ERROR)

    c.banner("APSec Tester — Triage")
    print()
    c.info(narrative(data))
    print()
    for i, r in enumerate(prioritize(data)[:top], 1):
        print(f"{i:>2}. {c.paint(f'{r.score:>6}', c.C)}  "
              f"{c.paint(r.severity, c.Y)}  {c.paint(r.check_id, c.Gr)}  {r.title}")
        c.dim(f"      {r.location}  —  {r.rationale}")
    raise typer.Exit(code=ExitCode.OK)


@app.command()
def crawl(
    url: str = typer.Argument(..., help="Base URL to crawl with a headless browser."),
    scope_file: Optional[Path] = typer.Option(
        None, "--scope", "-s", help="Scope YAML; only in-scope links are followed."
    ),
    max_pages: int = typer.Option(25, "--max-pages", help="Maximum pages to visit."),
    json_out: Optional[Path] = typer.Option(None, "--json", "-j", help="Write discovered URLs as JSON."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable debug logging."),
) -> None:
    """Discover routes with a headless browser (requires the 'browser' extra)."""
    configure_logging(verbose=verbose)

    scope = None
    if scope_file is not None:
        try:
            scope = load_scope(scope_file)
        except APSecError as exc:
            c.error(str(exc))
            raise typer.Exit(code=ExitCode.SPEC_ERROR)

    try:
        urls = asyncio.run(crawl_site(url, scope=scope, max_pages=max_pages))
    except OutOfScopeError as exc:
        c.error(str(exc))
        raise typer.Exit(code=ExitCode.USAGE_ERROR)
    except APSecError as exc:
        c.error(str(exc))
        raise typer.Exit(code=ExitCode.RUNTIME_ERROR)

    c.ok(f"Discovered {len(urls)} in-scope URL(s)")
    for u in urls:
        print(f"  {u}")
    if json_out is not None:
        try:
            Path(json_out).write_text(json.dumps(urls, indent=2), encoding="utf-8")
            c.ok(f"URLs written to {json_out}")
        except OSError as exc:
            c.error(f"Could not write {json_out}: {exc}")
            raise typer.Exit(code=ExitCode.RUNTIME_ERROR)
    raise typer.Exit(code=ExitCode.OK)


@app.command()
def version() -> None:
    """Print the APSec Tester version."""
    typer.echo(f"{__app_name__} {__version__}")


if __name__ == "__main__":  # pragma: no cover
    app()
