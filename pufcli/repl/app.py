from __future__ import annotations

import argparse
from pathlib import Path
from urllib.parse import urlparse

import cmd2

from pufcli.core.config import PufConfig
from pufcli.core.scanner import run_ffuf, run_nmap
from pufcli.core.viewer import print_ffuf_results, print_nmap_results


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

    show_parser = cmd2.Cmd2ArgumentParser()
    show_parser.add_argument("kind", choices=["nmap", "files", "dirs", "subs"])
    show_parser.add_argument("target")
    show_parser.add_argument("--page", type=int, default=1)
    show_parser.add_argument("--page-size", type=int, default=250)

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

                if proc.stdout:
                    for line in proc.stdout:
                        line = line.rstrip()
                        if line:
                            self.poutput(line)

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

    @cmd2.with_argparser(show_parser)
    def do_show(self, args: argparse.Namespace) -> None:
        target = self._normalize_target(args.target)

        try:
            if args.page < 1:
                raise ValueError("page must be at least 1")
            if args.page_size < 1:
                raise ValueError("page-size must be at least 1")

            result_file = self._get_result_file(target, args.kind)

            if args.kind == "nmap":
                print_nmap_results(result_file, page=args.page, page_size=args.page_size)
            else:
                print_ffuf_results(
                    result_file,
                    args.kind,
                    page=args.page,
                    page_size=args.page_size,
                )

        except FileNotFoundError as exc:
            self.perror(f"[!] {exc}")
        except Exception as exc:
            self.perror(f"[!] failed to show results: {exc}")

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

    def _get_scan_dir(self, target: str) -> Path:
        scan_dir = self.base_scan_dir / self._target_folder(target)
        if not scan_dir.exists():
            raise FileNotFoundError("target has not been scanned yet")
        return scan_dir

    def _get_result_file(self, target: str, kind: str) -> Path:
        scan_dir = self._get_scan_dir(target)

        if kind == "nmap":
            result_file = scan_dir / "nmap.xml"
        else:
            result_file = scan_dir / f"{kind}.json"

        if not result_file.exists():
            if kind == "nmap":
                raise FileNotFoundError("target has not been scanned with nmap yet")
            raise FileNotFoundError(f"target has not been scanned for {kind} yet")

        return result_file


def main() -> None:
    root = Path(__file__).resolve().parents[2]
    app = PufApp(str(root / "puf.conf"))
    app.cmdloop()


if __name__ == "__main__":
    main()