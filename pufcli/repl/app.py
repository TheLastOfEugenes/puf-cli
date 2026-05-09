from __future__ import annotations

import argparse
import time
from pathlib import Path
from urllib.parse import urlparse

import cmd2
from rich.text import Text

from pufcli.core.config import PufConfig
from pufcli.core.scanner import is_running, run_ffuf, run_nmap
from pufcli.core.viewer import print_ffuf_results, print_nmap_results

import shutil

class PufApp(cmd2.Cmd):
    intro = "PUF CLI starter. Type help or ? to list commands."
    prompt = "puf-cli > "

    def __init__(self, config_path: str = "puf.conf") -> None:
        super().__init__(allow_cli_args=False)
        self.config = PufConfig(config_path)
        self.base_scan_dir = Path("scans")
        self.prompt = "puf-cli > "
        self.continuation_prompt = "... "
        self.poutput("PUF CLI ready")

    def preloop(self) -> None:
        self.prompt = "puf-cli > "

    def postcmd(self, stop: bool, line: str) -> bool:
        self.prompt = "puf-cli > "
        return stop

    run_parser = cmd2.Cmd2ArgumentParser()
    run_parser.add_argument(
        "kind",
        choices=["nmap", "files", "dirs", "subs", "path", "web", "service"],
    )
    run_parser.add_argument("target")

    show_parser = cmd2.Cmd2ArgumentParser()
    show_parser.add_argument("kind", choices=["nmap", "files", "dirs", "subs"])
    show_parser.add_argument("target")
    show_parser.add_argument("--page", type=int, default=1)
    show_parser.add_argument("--page-size", type=int, default=250)

    list_parser = cmd2.Cmd2ArgumentParser()
    list_parser.add_argument("target", nargs="?")

    remove_parser = cmd2.Cmd2ArgumentParser()
    remove_parser.add_argument("target")
    remove_parser.add_argument(
        "result",
        nargs="?",
        choices=["nmap", "files", "dirs", "subs"],
    )

    @cmd2.with_argparser(run_parser)
    def do_run(self, args: argparse.Namespace) -> None:
        target = self._normalize_target(args.target)
        scan_dir = self.base_scan_dir / self._target_folder(target)
        scan_dir.mkdir(parents=True, exist_ok=True)

        try:
            if self._is_bundle_kind(args.kind):
                self._run_bundle(args.kind, target, scan_dir)
            else:
                self._run_single(args.kind, target, scan_dir)
        except KeyboardInterrupt:
            self.perror("[!] interrupted")
        except Exception as exc:
            self.perror(f"[!] {exc}")
        finally:
            self.prompt = "puf-cli > "

    def _run_single(self, kind: str, target: str, scan_dir: Path) -> None:
        if kind == "nmap":
            nmap_target = self._nmap_target(target)
            proc, outfile, cmd = run_nmap(
                nmap_target,
                self.config,
                scan_dir,
                verbosity="normal",
            )
        else:
            proc, outfile, cmd = run_ffuf(
                target,
                kind,
                self.config,
                scan_dir,
                verbosity="normal",
            )

        self.poutput(f"[+] started {kind} scan")
        self.poutput(f"CMD: {' '.join(cmd)}")
        self.poutput(f"OUTFILE: {outfile}")

        if proc.stdout:
            for line in iter(proc.stdout.readline, ""):
                if line == "" and proc.poll() is not None:
                    break
                line = line.rstrip()
                if line:
                    self.poutput(line)

        proc.wait()

        if proc.returncode == 0:
            self.poutput(f"[+] completed: {kind}")
        else:
            self.perror(f"[!] scan failed with code {proc.returncode}")

    def _run_bundle(self, bundle_kind: str, target: str, scan_dir: Path) -> None:
        kinds = self._expand_run_kind(bundle_kind)
        self.poutput(f"[+] starting {bundle_kind} bundle for {target}")
        self.poutput(f"[+] bundle plan: {', '.join(kinds)}")

        jobs: list[dict] = []
        failures: list[str] = []

        visible_kind = kinds[-1] if kinds and kinds[-1] == "nmap" else None

        for kind in kinds:
            try:
                if kind == "nmap":
                    proc, outfile, cmd = run_nmap(
                        self._nmap_target(target),
                        self.config,
                        scan_dir,
                        verbosity="normal" if kind == visible_kind else "silent",
                    )
                else:
                    proc, outfile, cmd = run_ffuf(
                        target,
                        kind,
                        self.config,
                        scan_dir,
                        verbosity="silent",
                    )

                jobs.append(
                    {
                        "kind": kind,
                        "proc": proc,
                        "outfile": outfile,
                        "cmd": cmd,
                        "reported": False,
                    }
                )
                self.poutput(f"[+] launched {kind}")

            except Exception as exc:
                failures.append(kind)
                self.perror(f"[!] failed to launch {kind}: {exc}")

        visible_job = None
        for job in jobs:
            if job["kind"] == visible_kind:
                visible_job = job
                break

        if visible_job and visible_job["proc"].stdout:
            proc = visible_job["proc"]

            while True:
                line = proc.stdout.readline()
                if line:
                    line = line.rstrip()
                    if line:
                        self.poutput(line)

                self._report_finished_jobs(jobs, failures)

                if line == "" and proc.poll() is not None:
                    break

            proc.wait()
            self._report_finished_jobs(jobs, failures)
        else:
            while any(is_running(job["proc"]) for job in jobs):
                self._report_finished_jobs(jobs, failures)
                time.sleep(0.2)

        for job in jobs:
            if not job["reported"]:
                rc = job["proc"].wait()
                if rc == 0:
                    self.poutput(f"[+] completed: {job['kind']}")
                else:
                    failures.append(job["kind"])
                    self.perror(f"[!] failed: {job['kind']} (code {rc})")
                job["reported"] = True

        if failures:
            failed = ", ".join(dict.fromkeys(failures))
            self.perror(f"[!] bundle {bundle_kind} completed with failures: {failed}")
        else:
            self.poutput(f"[+] bundle {bundle_kind} completed")

    def _report_finished_jobs(self, jobs: list[dict], failures: list[str]) -> None:
        for job in jobs:
            if job["reported"]:
                continue

            rc = job["proc"].poll()
            if rc is None:
                continue

            if rc == 0:
                self.poutput(f"[+] completed: {job['kind']}")
            else:
                failures.append(job["kind"])
                self.perror(f"[!] failed: {job['kind']} (code {rc})")

            job["reported"] = True

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

    @cmd2.with_argparser(list_parser)
    def do_list(self, args: argparse.Namespace) -> None:
        try:
            if args.target is None:
                targets = self._iter_target_dirs()
                if not targets:
                    self.poutput(Text("No scanned targets found", style="yellow"))
                    return

                self.poutput(Text("Available targets", style="bold blue"))
                for target in targets:
                    line = Text()
                    line.append("- ", style="cyan")
                    line.append(target.name)
                    self.poutput(line)
                return

            target = self._normalize_target(args.target)
            files = self._list_result_files(target)

            if not files:
                self.poutput(Text("No result files found for target", style="yellow"))
                return

            header = Text()
            header.append("Available results for ", style="bold blue")
            header.append(self._target_folder(target), style="cyan")
            self.poutput(header)

            for file in files:
                raw_name = file.name
                display_name = self._result_display_name(raw_name)
                style = self._result_style(raw_name)

                line = Text()
                line.append("- ", style=style)
                line.append(display_name, style=style)
                self.poutput(line)

        except FileNotFoundError as exc:
            self.perror(f"[!] {exc}")
        except Exception as exc:
            self.perror(f"[!] failed to list items: {exc}")

    @cmd2.with_argparser(remove_parser)
    def do_remove(self, args: argparse.Namespace) -> None:
        target = self._normalize_target(args.target)

        try:
            scan_dir = self._get_scan_dir(target)

            if args.result is None:
                label = self._target_folder(target)
                if not self._confirm(f"Remove target '{label}'?"):
                    self.poutput("[+] cancelled")
                    return

                shutil.rmtree(scan_dir)
                self.poutput(f"[+] removed target: {label}")
                return

            result_file = self._get_result_file(target, args.result)

            if not self._confirm(
                f"Remove result '{args.result}' for target '{self._target_folder(target)}'?"
            ):
                self.poutput("[+] cancelled")
                return

            result_file.unlink()
            self.poutput(f"[+] removed result: {args.result} for {self._target_folder(target)}")

        except FileNotFoundError as exc:
            self.perror(f"[!] {exc}")
        except Exception as exc:
            self.perror(f"[!] failed to remove: {exc}")

    def do_reload(self, _: str) -> None:
        self.config.reload()
        self.poutput("[+] config reloaded")

    def do_exit(self, _: str) -> bool:
        return True

    def do_quit(self, _: str) -> bool:
        return True

    def _confirm(self, prompt: str) -> bool:
        while True:
            answer = input(f"{prompt} [y/N]: ").strip().lower()
            if answer in {"", "n", "no"}:
                return False
            if answer in {"y", "yes"}:
                return True
            self.poutput("Please answer with y or N.")

    def _iter_target_dirs(self) -> list[Path]:
        if not self.base_scan_dir.exists():
            return []
        return sorted(
            [p for p in self.base_scan_dir.iterdir() if p.is_dir()],
            key=lambda p: p.name.lower(),
        )

    def _list_result_files(self, target: str) -> list[Path]:
        scan_dir = self._get_scan_dir(target)
        return sorted(
            [p for p in scan_dir.iterdir() if p.is_file()],
            key=lambda p: p.name.lower(),
        )

    @staticmethod
    def _expand_run_kind(kind: str) -> list[str]:
        bundles = {
            "path": ["files", "dirs"],
            "web": ["files", "dirs", "subs"],
            "service": ["files", "dirs", "subs", "nmap"],
        }
        return bundles.get(kind, [kind])

    @staticmethod
    def _is_bundle_kind(kind: str) -> bool:
        return kind in {"path", "web", "service"}

    @staticmethod
    def _result_display_name(filename: str) -> str:
        mapping = {
            "nmap.xml": "nmap",
            "files.json": "files",
            "dirs.json": "dirs",
            "subs.json": "subs",
            "files_f.json": "filtered files",
            "dirs_f.json": "filtered dirs",
            "subs_f.json": "filtered subs",
            "files_filtered.json": "filtered files",
            "dirs_filtered.json": "filtered dirs",
            "subs_filtered.json": "filtered subs",
            "files_cf.json": "custom filtered files",
            "dirs_cf.json": "custom filtered dirs",
            "subs_cf.json": "custom filtered subs",
            "files_custom_filtered.json": "custom filtered files",
            "dirs_custom_filtered.json": "custom filtered dirs",
            "subs_custom_filtered.json": "custom filtered subs",
        }

        if filename in mapping:
            return mapping[filename]

        if filename.endswith(".json"):
            return filename[:-5]
        if filename.endswith(".xml"):
            return filename[:-4]
        return filename

    @staticmethod
    def _result_style(filename: str) -> str:
        if filename == "nmap.xml":
            return "green"
        if filename in {"files.json", "dirs.json", "subs.json"}:
            return "cyan"
        if filename.endswith("_f.json") or filename.endswith("_filtered.json"):
            return "yellow"
        if filename.endswith("_cf.json") or filename.endswith("_custom_filtered.json"):
            return "magenta"
        if filename.endswith(".json"):
            return "white"
        if filename.endswith(".xml"):
            return "green"
        return "dim"

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