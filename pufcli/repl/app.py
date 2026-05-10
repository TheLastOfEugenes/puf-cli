from __future__ import annotations

import argparse
import shutil
import time
from pathlib import Path
from urllib.parse import urlparse

import cmd2
from rich.text import Text

from pufcli.core.config import PufConfig
from pufcli.core.scanner import is_running, run_ffuf, run_nmap
from pufcli.core.viewer import print_ffuf_results, print_nmap_results


class PufApp(cmd2.Cmd):
    APP_NAME = "puf-cli"
    INTRO_TEXT = "PUF CLI starter. Type help or ? to list commands."
    BASE_SCAN_DIR = "scans"

    PROMPT_LABEL = "puf-cli"
    PROMPT_SUFFIX = " > "
    CONTINUATION_PROMPT = "... "
    PROMPT_COLOR = "bright_magenta"
    PROMPT_SUFFIX_COLOR = "gold"

    ANSI_RESET = "\033[0m"
    ANSI_COLORS = {
        "bright_magenta": "\033[95m",
        "bright_yellow": "\033[93m",
        "gold": "\033[33m",
        "cyan": "\033[96m",
    }

    COLORS = {
        "info": "bold blue",
        "warning": "yellow",
        "error": "red",
        "muted": "dim",
        "target": "bright_cyan",
        "result_ffuf": "white",
        "result_filtered": "bright_magenta",
        "result_custom": "dark_orange",
        "result_nmap": "green",
    }

    LITERALS = {
        "list": "list",
    }

    RESULT_KINDS = ("nmap", "files", "dirs", "subs")
    BUNDLE_KINDS = ("path", "web", "service")
    RUN_KINDS = RESULT_KINDS + BUNDLE_KINDS

    BUNDLES = {
        "path": ["files", "dirs"],
        "web": ["files", "dirs", "subs"],
        "service": ["files", "dirs", "subs", "nmap"],
    }

    RESULT_FILES = {
        "nmap": "nmap.xml",
        "files": "files.json",
        "dirs": "dirs.json",
        "subs": "subs.json",
    }

    RESULT_DISPLAY_NAMES = {
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

    intro = INTRO_TEXT

    run_parser = cmd2.Cmd2ArgumentParser()
    run_parser.add_argument("target")
    run_parser.add_argument("kind", choices=list(RUN_KINDS))

    show_parser = cmd2.Cmd2ArgumentParser()
    show_parser.add_argument("target")
    show_parser.add_argument("kind", nargs="?")
    show_parser.add_argument("--page", type=int, default=1)
    show_parser.add_argument("--page-size", type=int, default=250)

    list_parser = cmd2.Cmd2ArgumentParser()
    list_parser.add_argument("target", nargs="?")

    remove_parser = cmd2.Cmd2ArgumentParser()
    remove_parser.add_argument("arg1")
    remove_parser.add_argument("arg2", nargs="?")

    def __init__(self, config_path: str = "puf.conf") -> None:
        super().__init__(allow_cli_args=False)
        self.config = PufConfig(config_path)
        self.base_scan_dir = Path(self.BASE_SCAN_DIR)
        self.continuation_prompt = self.CONTINUATION_PROMPT
        self._refresh_prompt()
        self.poutput(f"{self.APP_NAME} ready")

    def preloop(self) -> None:
        self._refresh_prompt()

    def postcmd(self, stop: bool, line: str) -> bool:
        self._refresh_prompt()
        return stop

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
            self._refresh_prompt()

    @cmd2.with_argparser(show_parser)
    def do_show(self, args: argparse.Namespace) -> None:
        try:
            if args.page < 1:
                raise ValueError("page must be at least 1")
            if args.page_size < 1:
                raise ValueError("page-size must be at least 1")

            if args.target == self.LITERALS["list"] and args.kind is None:
                self._show_targets()
                return

            if args.kind == self.LITERALS["list"]:
                target = self._normalize_target(args.target)
                self._show_results_list(target)
                return

            if args.kind is None or args.kind not in self.RESULT_KINDS:
                raise ValueError(self._show_usage())

            target = self._normalize_target(args.target)
            kind = args.kind
            result_file = self._get_result_file(target, kind)

            if kind == "nmap":
                print_nmap_results(result_file, page=args.page, page_size=args.page_size)
            else:
                print_ffuf_results(
                    result_file,
                    kind,
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
                self._show_targets()
                return

            target = self._normalize_target(args.target)
            self._show_results_list(target)

        except FileNotFoundError as exc:
            self.perror(f"[!] {exc}")
        except Exception as exc:
            self.perror(f"[!] failed to list items: {exc}")

    @cmd2.with_argparser(remove_parser)
    def do_remove(self, args: argparse.Namespace) -> None:
        try:
            if args.arg1 == self.LITERALS["list"] and args.arg2 is None:
                self._show_targets()
                return

            if args.arg2 == self.LITERALS["list"]:
                target = self._normalize_target(args.arg1)
                self._show_results_list(target)
                return

            target = self._normalize_target(args.arg1)
            scan_dir = self._get_scan_dir(target)

            if args.arg2 is None:
                label = self._target_folder(target)
                if not self._confirm(f"Remove target '{label}'?"):
                    self.poutput("[+] cancelled")
                    return

                shutil.rmtree(scan_dir)
                self.poutput(f"[+] removed target: {label}")
                return

            result = args.arg2
            if result not in self.RESULT_KINDS:
                raise ValueError(self._remove_usage())

            result_file = self._get_result_file(target, result)

            if not self._confirm(
                f"Remove file '{result_file.name}' for target '{self._target_folder(target)}'?"
            ):
                self.poutput("[+] cancelled")
                return

            result_file.unlink()
            self.poutput(f"[+] removed result: {result} for {self._target_folder(target)}")

            if not any(scan_dir.iterdir()):
                scan_dir.rmdir()
                self.poutput(f"[+] removed empty target folder: {self._target_folder(target)}")

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

    def _ansi(self, color_name: str) -> str:
        return self.ANSI_COLORS.get(color_name, "")

    def _style(self, key: str) -> str:
        return self.COLORS[key]

    def _build_prompt(self) -> str:
        return (
            f"{self._ansi(self.PROMPT_COLOR)}{self.PROMPT_LABEL}"
            f"{self.ANSI_RESET}"
            f"{self._ansi(self.PROMPT_SUFFIX_COLOR)}{self.PROMPT_SUFFIX}"
            f"{self.ANSI_RESET}"
        )

    def _refresh_prompt(self) -> None:
        self.prompt = self._build_prompt()

    def _show_usage(self) -> str:
        return "usage: show list | show <target> list | show <target> <kind>"
    
    def _remove_usage(self) -> str:
        kinds = "|".join(self.RESULT_KINDS)
        return f"usage: remove list | remove <target> list | remove <target> [{kinds}]"

    def _confirm(self, prompt: str) -> bool:
        while True:
            answer = input(f"{prompt} [y/N]: ").strip().lower()
            if answer in {"", "n", "no"}:
                return False
            if answer in {"y", "yes"}:
                return True
            self.poutput("Please answer with y or N.")

    def _run_single(self, kind: str, target: str, scan_dir: Path) -> None:
        if kind == "nmap":
            proc, outfile, cmd = run_nmap(
                self._nmap_target(target),
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

        visible_job = next((job for job in jobs if job["kind"] == visible_kind), None)

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
            if job["reported"]:
                continue

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

    def _show_targets(self) -> None:
        targets = self._iter_target_dirs()
        if not targets:
            self.poutput(Text("No scanned targets found", style=self._style("warning")))
            return

        self.poutput(Text("Available targets", style=self._style("info")))
        for target in targets:
            line = Text()
            line.append("- ", style=self._style("target"))
            line.append(target.name, style=self._style("target"))
            self.poutput(line)

    def _show_results_list(self, target: str) -> None:
        files = self._list_result_files(target)

        if not files:
            self.poutput(Text("No result files found for target", style=self._style("warning")))
            return

        header = Text()
        header.append("Available results for ", style=self._style("info"))
        header.append(self._target_folder(target), style=self._style("target"))
        self.poutput(header)

        for file in files:
            raw_name = file.name
            display_name = self._result_display_name(raw_name)
            style = self._result_style(raw_name)

            line = Text()
            line.append("- ", style=style)
            line.append(display_name, style=style)
            self.poutput(line)

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

    @classmethod
    def _expand_run_kind(cls, kind: str) -> list[str]:
        return list(cls.BUNDLES.get(kind, [kind]))

    @classmethod
    def _is_bundle_kind(cls, kind: str) -> bool:
        return kind in cls.BUNDLE_KINDS

    @classmethod
    def _result_display_name(cls, filename: str) -> str:
        if filename in cls.RESULT_DISPLAY_NAMES:
            return cls.RESULT_DISPLAY_NAMES[filename]
        if filename.endswith(".json"):
            return filename[:-5]
        if filename.endswith(".xml"):
            return filename[:-4]
        return filename

    def _result_style(self, filename: str) -> str:
        if filename == self.RESULT_FILES["nmap"]:
            return self._style("result_nmap")
        if filename.endswith("_cf.json") or filename.endswith("_custom_filtered.json"):
            return self._style("result_custom")
        if filename.endswith("_f.json") or filename.endswith("_filtered.json"):
            return self._style("result_filtered")
        if filename.endswith(".json"):
            return self._style("result_ffuf")
        return self._style("muted")

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

        if kind not in self.RESULT_FILES:
            raise ValueError(f"Unknown result kind: {kind}")

        result_file = scan_dir / self.RESULT_FILES[kind]

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