from __future__ import annotations

import shlex
import subprocess
from pathlib import Path
from urllib.parse import urlparse


def get_hostname(target: str) -> str:
    parsed = urlparse(target if "://" in target else f"http://{target}")
    return parsed.hostname or target


def ensure_scan_dir(scan_dir: str | Path) -> Path:
    path = Path(scan_dir)
    path.mkdir(parents=True, exist_ok=True)
    return path


def get_outfile(scan_dir: str | Path, kind: str) -> Path:
    scan_dir = ensure_scan_dir(scan_dir)
    if kind == "nmap":
        return scan_dir / "nmap.xml"
    if kind == "files":
        return scan_dir / "files.json"
    if kind == "dirs":
        return scan_dir / "dirs.json"
    if kind == "subs":
        return scan_dir / "subs.json"
    raise ValueError(f"Unknown scan kind: {kind}")


def build_nmap_command(target: str, config, scan_dir: str | Path) -> tuple[list[str], Path]:
    outfile = get_outfile(scan_dir, "nmap")
    template = config.get_command("nmap")

    if not template:
        raise ValueError("nmap command not set in puf.conf")

    cmd = template.format(
        target=target,
        outfile=str(outfile),
    )
    return shlex.split(cmd), outfile


def build_ffuf_command(target: str, kind: str, config, scan_dir: str | Path) -> tuple[list[str], Path]:
    if kind not in {"files", "dirs", "subs"}:
        raise ValueError(f"Invalid ffuf kind: {kind}")

    outfile = get_outfile(scan_dir, kind)
    hostname = get_hostname(target)

    if kind == "subs":
        template = config.get_command("fuzz_subs")
        wordlist = config.get_wordlist("subs")
    else:
        template = config.get_command("fuzz")
        wordlist = config.get_wordlist(kind)

    if not template:
        raise ValueError(f"{'fuzz_subs' if kind == 'subs' else 'fuzz'} command not set in puf.conf")

    if not wordlist:
        raise ValueError(f"{kind} wordlist not set in puf.conf")

    cmd = template.format(
        target=target,
        hostname=hostname,
        wordlist=wordlist,
        outfile=str(outfile),
        type=kind,
    )
    return shlex.split(cmd), outfile


def _popen_kwargs(verbosity: str) -> dict:
    if verbosity not in {"normal", "silent"}:
        raise ValueError(f"Invalid verbosity: {verbosity}")

    if verbosity == "silent":
        return {
            "stdin": subprocess.DEVNULL,
            "stdout": subprocess.DEVNULL,
            "stderr": subprocess.DEVNULL,
            "text": True,
        }

    return {
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.STDOUT,
        "text": True,
        "bufsize": 1,
    }


def run_nmap(
    target: str,
    config,
    scan_dir: str | Path,
    verbosity: str = "normal",
) -> tuple[subprocess.Popen, Path, list[str]]:
    cmd, outfile = build_nmap_command(target, config, scan_dir)
    proc = subprocess.Popen(cmd, **_popen_kwargs(verbosity))
    return proc, outfile, cmd


def run_ffuf(
    target: str,
    kind: str,
    config,
    scan_dir: str | Path,
    verbosity: str = "normal",
) -> tuple[subprocess.Popen, Path, list[str]]:
    cmd, outfile = build_ffuf_command(target, kind, config, scan_dir)
    proc = subprocess.Popen(cmd, **_popen_kwargs(verbosity))
    return proc, outfile, cmd


def is_running(proc: subprocess.Popen) -> bool:
    return proc.poll() is None