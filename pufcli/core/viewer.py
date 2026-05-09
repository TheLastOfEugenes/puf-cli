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


def print_ffuf_results(path: str | Path, kind: str) -> None:
    data = load_ffuf_results(path)
    results = data.get("results", [])

    table = Table(title=f"{kind} results: {Path(path).name}")
    table.add_column("#", style="dim", no_wrap=True)
    table.add_column("Status", no_wrap=True)
    table.add_column("Words", no_wrap=True)
    table.add_column("Length", no_wrap=True)

    if kind == "subs":
        table.add_column("Host")
    else:
        table.add_column("URL")

    table.add_column("FUZZ")

    for i, row in enumerate(results, 1):
        input_data = row.get("input", {}) if isinstance(row, dict) else {}
        fuzz = input_data.get("FUZZ", "") if isinstance(input_data, dict) else ""
        status = str(row.get("status", "")) if isinstance(row, dict) else ""
        words = str(row.get("words", "")) if isinstance(row, dict) else ""
        length = str(row.get("length", "")) if isinstance(row, dict) else ""
        value = row.get("host", "") if kind == "subs" else row.get("url", "")

        table.add_row(
            str(i),
            status,
            words,
            length,
            str(value),
            str(fuzz),
        )

    console.print(table)
    console.print(f"[dim]Total results:[/dim] {len(results)}")


def load_nmap_xml(path: str | Path) -> ET.Element:
    p = ensure_results_file(path)
    tree = ET.parse(p)
    return tree.getroot()


def print_nmap_results(path: str | Path) -> None:
    root = load_nmap_xml(path)

    table = Table(title=f"nmap results: {Path(path).name}")
    table.add_column("Host")
    table.add_column("Port", no_wrap=True)
    table.add_column("Proto", no_wrap=True)
    table.add_column("State", no_wrap=True)
    table.add_column("Service")

    rows = 0

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

            table.add_row(
                host_addr,
                port.get("portid", ""),
                port.get("protocol", ""),
                state,
                service,
            )
            rows += 1

    console.print(table)
    console.print(f"[dim]Total ports shown:[/dim] {rows}")