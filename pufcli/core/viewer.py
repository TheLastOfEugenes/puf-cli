from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table

console = Console()


def ensure_results_file(path: str | Path) -> Path:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"results file not found: {p}")
    return p


def load_ffuf_results(path: str | Path) -> dict[str, Any]:
    p = ensure_results_file(path)
    with p.open("r", encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, dict):
        raise ValueError("ffuf results file is not a JSON object")

    data.setdefault("results", [])
    return data

def style_status(status: object) -> str:
    try:
        code = int(status)
    except (TypeError, ValueError):
        return "white"

    if 200 <= code < 300:
        return "green"
    if 300 <= code < 400:
        return "yellow"
    if 400 <= code < 500:
        return "bright_red"
    if 500 <= code < 600:
        return "magenta"
    return "white"

def print_ffuf_results(path: str | Path, kind: str, page: int = 1, page_size: int = 250) -> None:
    data = load_ffuf_results(path)
    results = data.get("results", [])

    total = len(results)
    start = (page - 1) * page_size
    end = start + page_size

    if start >= total and total > 0:
        raise ValueError(f"page {page} is out of range (total results: {total})")

    page_rows = results[start:end]

    table = Table(title=f"[bold]{kind} results[/bold]: {Path(path).name}", header_style="bold blue")
    table.add_column("#", style="dim", no_wrap=True)
    table.add_column("Status", no_wrap=True)
    table.add_column("Words", no_wrap=True)
    table.add_column("Length", no_wrap=True)

    if kind == "subs":
        table.add_column("Host")
    else:
        table.add_column("URL")

    table.add_column("FUZZ")

    for i, row in enumerate(page_rows, start + 1):
        input_data = row.get("input", {}) if isinstance(row, dict) else {}
        fuzz = input_data.get("FUZZ", "") if isinstance(input_data, dict) else ""
        status = str(row.get("status", "")) if isinstance(row, dict) else ""
        words = str(row.get("words", "")) if isinstance(row, dict) else ""
        length = str(row.get("length", "")) if isinstance(row, dict) else ""
        value = row.get("host", "") if kind == "subs" else row.get("url", "")

        status_style = style_status(row.get("status", ""))

        table.add_row(
            str(i),
            f"[{status_style}]{status}[/{status_style}]",
            f"[dim]{words}[/dim]",
            f"[dim]{length}[/dim]",
            f"[cyan]{value}[/cyan]",
            str(fuzz),
        )

    console.print(table)

    shown_from = 0 if total == 0 else start + 1
    shown_to = min(end, total)
    console.print(
        f"[dim]Showing {shown_from}-{shown_to} of {total} results "
        f"(page {page}, page-size {page_size})[/dim]"
    )


def load_nmap_xml(path: str | Path) -> ET.Element:
    p = ensure_results_file(path)
    tree = ET.parse(p)
    return tree.getroot()

def style_port_state(state: str) -> str:
    state = (state or "").lower()
    if state == "open":
        return "green"
    if state == "filtered":
        return "yellow"
    if state == "closed":
        return "red"
    return "white"

def print_nmap_results(path: str | Path, page: int = 1, page_size: int = 250) -> None:
    root = load_nmap_xml(path)

    all_rows = []
    for host in root.findall("host"):
        addr = host.find("address")
        host_addr = addr.get("addr", "") if addr is not None else ""

        ports = host.find("ports")
        if ports is None:
            continue

        for port in ports.findall("port"):
            state_el = port.find("state")
            service_el = port.find("service")

            state = state_el.get("state", "") if state_el is not None else ""
            service = service_el.get("name", "") if service_el is not None else ""

            all_rows.append((
                f"[cyan]{host_addr}[/cyan]",
                port.get("portid", ""),
                port.get("protocol", ""),
                f"[{style_port_state(state)}]{state}[/{style_port_state(state)}]",
                service,
            ))

    total = len(all_rows)
    start = (page - 1) * page_size
    end = start + page_size

    if start >= total and total > 0:
        raise ValueError(f"page {page} is out of range (total rows: {total})")

    page_rows = all_rows[start:end]

    table = Table(title=f"[bold]nmap results[/bold]: {Path(path).name}", header_style="bold blue")
    table.add_column("Host")
    table.add_column("Port", no_wrap=True)
    table.add_column("Proto", no_wrap=True)
    table.add_column("State", no_wrap=True)
    table.add_column("Service")

    for row in page_rows:
        table.add_row(*row)

    console.print(table)

    shown_from = 0 if total == 0 else start + 1
    shown_to = min(end, total)
    console.print(
        f"[dim]Showing {shown_from}-{shown_to} of {total} rows "
        f"(page {page}, page-size {page_size})[/dim]"
    )