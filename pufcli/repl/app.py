from __future__ import annotations

import argparse
from pathlib import Path

import cmd2

from pufcli.core.config import PufConfig
from pufcli.core.scanner import run_ffuf, run_nmap

from urllib.parse import urlparse


class PufApp(cmd2.Cmd):
    intro = "PUF CLI starter. Type help or ? to list commands."
    prompt = "puf-cli > "

    def __init__(self, config_path: str = "puf.conf") -> None:
        super().__init__(allow_cli_args=False)
        self.config = PufConfig(config_path)
        self.base_scan_dir = Path("scans")
        self.poutput("PUF CLI ready")

    run_parser = cmd2.Cmd2ArgumentParser()
    run_parser.add_argument("kind", choices=["nmap", "files", "dirs", "subs"])
    run_parser.add_argument("target")

    @cmd2.with_argparser(run_parser)
    def do_run(self, args: argparse.Namespace) -> None:
        target = self._normalize_target(args.target)
        scan_dir = self.base_scan_dir / self._target_folder(target)
        scan_dir.mkdir(parents=True, exist_ok=True)

        try:
            if args.kind == "nmap":
                nmap_target = self._nmap_target(target)
                proc, outfile, cmd = run_nmap(nmap_target, self.config, scan_dir)
                self.poutput("[+] started nmap scan")
                self.poutput(f"CMD: {' '.join(cmd)}")
                self.poutput(f"OUTFILE: {outfile}")
                proc.wait()

            else:
                proc, outfile, cmd = run_ffuf(target, args.kind, self.config, scan_dir)
                self.poutput(f"[+] started {args.kind} scan")
                self.poutput(f"CMD: {' '.join(cmd)}")
                self.poutput(f"OUTFILE: {outfile}")
                proc.wait()

            if proc.returncode == 0:
                self.poutput(f"[+] completed: {args.kind}")
            else:
                self.perror(f"[!] scan failed with code {proc.returncode}")

        except Exception as exc:
            self.perror(f"[!] {exc}")

    def do_reload(self, _: str) -> None:
        self.config.reload()
        self.poutput("[+] config reloaded")

    def do_exit(self, _: str) -> bool:
        return True

    def do_quit(self, _: str) -> bool:
        return True

    @staticmethod
    def _normalize_target(target: str) -> str:
        target = target.strip()
        if "://" not in target:
            target = "http://" + target
        return target

    @staticmethod
    def _target_folder(target: str) -> str:
        parsed = urlparse(target)
        host = parsed.netloc or parsed.path
        path = parsed.path.strip("/")

        folder = host
        if path:
            folder += "_" + path.replace("/", "_")

        return folder.replace(":", "_")

    @staticmethod
    def _nmap_target(target: str) -> str:
        parsed = urlparse(target if "://" in target else f"http://{target}")
        return parsed.hostname or target

def main() -> None:
    root = Path(__file__).resolve().parents[2]
    app = PufApp(str(root / "puf.conf"))
    app.cmdloop()


if __name__ == "__main__":
    main()