from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import shutil
import time

import typer
from git import InvalidGitRepositoryError, Repo
from rich.console import Console
from rich.table import Table
from ruamel.yaml import YAML
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from generators import write_inventory_json, write_inventory_markdown, write_inventory_yaml
from scanner import build_inventory

__version__ = "0.1.0"
app = typer.Typer(help="doCODEmentation - Homelab infrastructure documentation CLI")
console = Console()
yaml = YAML(typ="safe")


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"doCODEmentation {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False,
        "--version",
        help="Show CLI version and exit.",
        is_eager=True,
        callback=_version_callback,
    ),
) -> None:
    _ = version


def _load_yaml_file(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        with path.open("r", encoding="utf-8") as f:
            return yaml.load(f) or default
    except Exception:
        return default


def _save_yaml_file(path: Path, content: Any) -> None:
    writer = YAML()
    writer.default_flow_style = False
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        writer.dump(content, f)


def _manual_overrides_path(output_dir: Path) -> Path:
    return output_dir / "manual_overrides.yaml"


def _run_scan(base_dir: Path, output_dir: Path) -> tuple[dict[str, Any], list[str]]:
    output_dir.mkdir(parents=True, exist_ok=True)
    manual = _load_yaml_file(_manual_overrides_path(output_dir), {"services": []})
    result = build_inventory(base_dir=base_dir, manual_overrides=manual, scanner_version=__version__)
    return result.inventory, result.warnings


def _write_outputs(inventory: dict[str, Any], output_dir: Path) -> None:
    inv_path = output_dir / "inventory.yaml"
    prev_path = output_dir / "inventory.previous.yaml"
    if inv_path.exists():
        shutil.copy2(inv_path, prev_path)
    write_inventory_yaml(inventory, output_dir)
    write_inventory_json(inventory, output_dir)
    write_inventory_markdown(inventory, output_dir)


def _git_commit_if_requested(output_dir: Path) -> None:
    try:
        repo = Repo(Path.cwd(), search_parent_directories=True)
    except InvalidGitRepositoryError:
        console.print("[yellow]Git repo not found. Skipping commit.[/yellow]")
        return

    files = [
        output_dir / "inventory.yaml",
        output_dir / "inventory.json",
        output_dir / "inventory.md",
        output_dir / "manual_overrides.yaml",
        output_dir / "inventory.previous.yaml",
    ]
    tracked = [str(p) for p in files if p.exists()]
    if not tracked:
        return

    repo.index.add(tracked)
    message = f"docomentation: scan {datetime.now(timezone.utc).isoformat()}"
    repo.index.commit(message)
    console.print(f"[green]Committed:[/green] {message}")


@app.command()
def scan(
    dir: Path = typer.Option(..., "--dir", exists=True, file_okay=False, readable=True),
    output: Path = typer.Option(Path("./docs"), "--output"),
    git_commit: bool = typer.Option(False, "--git-commit"),
) -> None:
    inventory, warnings = _run_scan(dir, output)
    _write_outputs(inventory, output)
    if git_commit:
        _git_commit_if_requested(output)

    console.print(f"[green]Scan completed.[/green] Services: {len(inventory.get('services', []))}")
    console.print(f"Outputs: {output / 'inventory.yaml'}, {output / 'inventory.json'}, {output / 'inventory.md'}")
    if warnings:
        console.print(f"[yellow]Warnings ({len(warnings)}):[/yellow]")
        for w in warnings:
            console.print(f" - {w}")


class _ComposeChangeHandler(FileSystemEventHandler):
    def __init__(self, base_dir: Path, output_dir: Path, debounce_seconds: float = 1.5) -> None:
        super().__init__()
        self.base_dir = base_dir
        self.output_dir = output_dir
        self.debounce_seconds = debounce_seconds
        self._last = 0.0

    def on_any_event(self, event) -> None:  # type: ignore[override]
        if event.is_directory:
            return
        if not any(
            str(event.src_path).endswith(name)
            for name in ("compose.yml", "compose.yaml", "docker-compose.yml", "docker-compose.yaml")
        ):
            return
        now = time.time()
        if now - self._last < self.debounce_seconds:
            return
        self._last = now
        console.print("[cyan]Change detected, rescanning...[/cyan]")
        inventory, warnings = _run_scan(self.base_dir, self.output_dir)
        _write_outputs(inventory, self.output_dir)
        console.print(f"[green]Rescan completed.[/green] Services: {len(inventory.get('services', []))}")
        if warnings:
            console.print(f"[yellow]Warnings ({len(warnings)})[/yellow]")


@app.command()
def watch(
    dir: Path = typer.Option(..., "--dir", exists=True, file_okay=False, readable=True),
    output: Path = typer.Option(Path("./docs"), "--output"),
) -> None:
    console.print("[cyan]Initial scan...[/cyan]")
    inventory, warnings = _run_scan(dir, output)
    _write_outputs(inventory, output)
    if warnings:
        console.print(f"[yellow]Warnings ({len(warnings)})[/yellow]")

    handler = _ComposeChangeHandler(base_dir=dir, output_dir=output)
    observer = Observer()
    observer.schedule(handler, str(dir), recursive=True)
    observer.start()
    console.print("[green]Watching for changes. Press Ctrl+C to stop.[/green]")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()


@app.command()
def diff(output: Path = typer.Option(Path("./docs"), "--output")) -> None:
    current = _load_yaml_file(output / "inventory.yaml", {"services": []})
    previous = _load_yaml_file(output / "inventory.previous.yaml", {"services": []})

    curr_services = {s["name"]: s for s in current.get("services", []) if isinstance(s, dict) and s.get("name")}
    prev_services = {s["name"]: s for s in previous.get("services", []) if isinstance(s, dict) and s.get("name")}

    added = sorted(set(curr_services) - set(prev_services))
    removed = sorted(set(prev_services) - set(curr_services))
    changed = sorted(
        name for name in (set(curr_services) & set(prev_services)) if curr_services[name] != prev_services[name]
    )

    table = Table(title="Inventory Diff")
    table.add_column("Type")
    table.add_column("Service(s)")
    table.add_row("Added", ", ".join(added) or "-")
    table.add_row("Removed", ", ".join(removed) or "-")
    table.add_row("Changed", ", ".join(changed) or "-")
    console.print(table)


@app.command()
def add(
    name: str = typer.Option(..., "--name"),
    url: str = typer.Option(..., "--url"),
    note: str = typer.Option("", "--note"),
    output: Path = typer.Option(Path("./docs"), "--output"),
) -> None:
    path = _manual_overrides_path(output)
    data = _load_yaml_file(path, {"services": []})
    services = data.get("services", [])
    if not isinstance(services, list):
        services = []

    existing = next((s for s in services if isinstance(s, dict) and s.get("name") == name), None)
    if existing:
        existing["url"] = url
        if note:
            existing["note"] = note
    else:
        services.append(
            {
                "name": name,
                "url": url,
                "note": note,
                "source": "manual",
            }
        )
    data["services"] = services
    _save_yaml_file(path, data)
    console.print(f"[green]Manual entry saved:[/green] {name}")


@app.command()
def summary(output: Path = typer.Option(Path("./docs"), "--output")) -> None:
    inventory = _load_yaml_file(output / "inventory.yaml", {"services": []})
    services = inventory.get("services", [])
    table = Table(title="Infrastructure Summary")
    table.add_column("Name")
    table.add_column("Image")
    table.add_column("URL")
    table.add_column("Networks")
    table.add_column("Security")
    for s in services:
        table.add_row(
            str(s.get("name", "-")),
            str(s.get("image", "-")),
            ", ".join(s.get("urls", [])) or "-",
            ", ".join(s.get("networks", [])) or "-",
            str(s.get("security", {}).get("score", 0)),
        )
    console.print(table)


@app.command()
def audit(
    output: Path = typer.Option(Path("./docs"), "--output"),
    ignore: list[str] = typer.Option(
        [],
        "--ignore",
        help="Service names to ignore in audit. Repeatable.",
    ),
) -> None:
    inventory = _load_yaml_file(output / "inventory.yaml", {"services": []})
    services = inventory.get("services", [])
    ignored = set(ignore)
    findings: list[tuple[str, str]] = []
    for s in services:
        sec = s.get("security", {})
        name = str(s.get("name", "unknown"))
        if name in ignored:
            continue
        if sec.get("exception", False):
            continue
        if sec.get("user_mode") in {"root", "unset"}:
            findings.append((name, f"user_mode={sec.get('user_mode')}"))
        if not sec.get("no_new_privileges", False):
            findings.append((name, "no_new_privileges=false"))
        if s.get("service_type") not in {"database", "cache"} and sec.get("cap_drop") != "all":
            findings.append((name, f"cap_drop={sec.get('cap_drop')}"))
        if not sec.get("read_only", False):
            findings.append((name, "read_only=false"))

    if findings:
        table = Table(title="Security Audit Findings")
        table.add_column("Service")
        table.add_column("Issue")
        for svc, issue in findings:
            table.add_row(svc, issue)
        console.print(table)
    else:
        console.print("[green]No baseline hardening findings.[/green]")

    hardcoded = inventory.get("security_summary", {}).get("hardcoded_secret_warnings", [])
    if hardcoded:
        secrets_table = Table(title="Potential Hardcoded Secrets")
        secrets_table.add_column("Service")
        secrets_table.add_column("Key")
        secrets_table.add_column("Issue")
        for item in hardcoded:
            svc = str(item.get("service", "unknown"))
            key = str(item.get("key", ""))
            issue = str(item.get("issue", "potential hardcoded secret"))
            secrets_table.add_row(svc, key, f"⚠ {issue}")
        console.print(secrets_table)

    if findings or hardcoded:
        raise typer.Exit(code=1)
    raise typer.Exit(code=0)


def _main_with_alias() -> None:
    app()


if __name__ == "__main__":
    _main_with_alias()
