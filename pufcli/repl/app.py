from __future__ import annotations

import argparse
import shlex
import shutil
import subprocess
import time
from pathlib import Path
from urllib.parse import urlparse

import cmd2
from rich.text import Text

from pufcli.core.config import PufConfig
from pufcli.core.filter import FILTERABLE_KINDS, preferred_result_file, run_filter
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
        "result_custom_scan": "white",
    }

    LITERALS = {
        "list": "list",
        "last": "last",
        "all": "all",
    }

    RESULT_KINDS = ("nmap", "files", "dirs", "subs")
    BUNDLE_KINDS = ("path", "web", "service")
    BUILTIN_SCAN_NAMES = RESULT_KINDS + BUNDLE_KINDS
    RUNNABLE_SCAN_NAMES = BUILTIN_SCAN_NAMES

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

    BUILTIN_PROFILE_KEYS = {
        "nmap": "nmap",
        "files": "fuzz",
        "dirs": "fuzz",
        "subs": "fuzz_subs",
    }

    FILTER_RESULT_ALIASES = {
        "files_f": "files_f.json",
        "dirs_f": "dirs_f.json",
        "subs_f": "subs_f.json",
        "files_cf": "files_cf.json",
        "dirs_cf": "dirs_cf.json",
        "subs_cf": "subs_cf.json",
    }

    FILTERABLE_KINDS = FILTERABLE_KINDS

    intro = INTRO_TEXT

    run_parser = cmd2.Cmd2ArgumentParser()
    run_parser.add_argument("target")
    run_parser.add_argument("scan")
    run_parser.add_argument(
        "--background",
        action="store_true",
        help="run the scan in background",
    )

    show_parser = cmd2.Cmd2ArgumentParser()
    show_parser.add_argument("target")
    show_parser.add_argument("kind", nargs="*")
    show_parser.add_argument("--page", type=int, default=1)
    show_parser.add_argument("--page-size", type=int, default=250)

    list_parser = cmd2.Cmd2ArgumentParser()
    list_parser.add_argument("target", nargs="?")

    remove_parser = cmd2.Cmd2ArgumentParser()
    remove_parser.add_argument("target")
    remove_parser.add_argument("kind", nargs="?")

    scan_parser = cmd2.Cmd2ArgumentParser()
    scan_subparsers = scan_parser.add_subparsers(dest="action", required=True)

    scan_subparsers.add_parser("list")

    scan_show_parser = scan_subparsers.add_parser("show")
    scan_show_parser.add_argument("name")

    scan_set_parser = scan_subparsers.add_parser("set")
    scan_set_parser.add_argument("name")
    scan_set_parser.add_argument("command")

    scan_add_parser = scan_subparsers.add_parser("add")
    scan_add_parser.add_argument("name")
    scan_add_parser.add_argument("command")

    scan_remove_parser = scan_subparsers.add_parser("remove")
    scan_remove_parser.add_argument("name")

    filter_parser = cmd2.Cmd2ArgumentParser()
    filter_parser.add_argument("target")
    filter_parser.add_argument("kind", nargs="?")
    filter_parser.add_argument("--status")
    filter_parser.add_argument("--min-words", type=int)
    filter_parser.add_argument("--max-words", type=int)
    filter_parser.add_argument("--min-lines", type=int)
    filter_parser.add_argument("--max-lines", type=int)
    filter_parser.add_argument("--min-length", type=int)
    filter_parser.add_argument("--max-length", type=int)
    filter_parser.add_argument("--match")
    filter_parser.add_argument("--exclude")
    filter_parser.add_argument("--regex")

    scan_autofilter_parser = scan_subparsers.add_parser("autofilter")
    scan_autofilter_parser.add_argument(
        "mode",
        choices=("show", "enable", "disable"),
    )

    def __init__(self, config_path: str = "puf.conf") -> None:
        super().__init__(allow_cli_args=False)
        self.config = PufConfig(config_path)
        self.base_scan_dir = Path(self.BASE_SCAN_DIR)
        self.continuation_prompt = self.CONTINUATION_PROMPT

        self.builtin_scan_profiles = self._load_builtin_scan_profiles()
        self.custom_scan_profiles: dict[str, str] = {}

        self.jobs: dict[int, dict] = {}
        self.next_job_id = 1

        self.last_target: str | None = None
        self.last_scan: str | None = None
        self.last_result_kind: str | None = None
        self.row_refs: dict[str, dict] = {}

        self._refresh_prompt()
        self.poutput(f"{self.APP_NAME} ready")

        self.auto_filter_enabled = True

    def preloop(self) -> None:
        self._refresh_prompt()

    def postcmd(self, stop: bool, line: str) -> bool:
        self._refresh_prompt()
        return stop

    @cmd2.with_argparser(run_parser)
    def do_run(self, args: argparse.Namespace) -> None:
        target = (
            self._resolve_row_target(args.target)
            if args.target.startswith("r")
            else self._normalize_target(args.target)
        )
        scan = self._resolve_last_scan(args.scan)

        scan_dir = self.base_scan_dir / self._target_folder(target)
        scan_dir.mkdir(parents=True, exist_ok=True)

        try:
            if scan == self.LITERALS["all"]:
                self.last_target = target
                for kind in self.RESULT_KINDS:
                    self.last_scan = kind
                    self._run_builtin_scan(kind, target, scan_dir, background=args.background)
                return

            self._remember_run(target, scan)

            if scan in self.BUNDLE_KINDS:
                self._run_bundle(scan, target, scan_dir, background=args.background)
                return

            if scan in self.RESULT_KINDS:
                self._run_builtin_scan(scan, target, scan_dir, background=args.background)
                return

            if scan in self.custom_scan_profiles:
                self._run_custom_scan(scan, target, scan_dir, background=args.background)
                return

            raise ValueError(f"unknown scan: {scan}")

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

            kind_tokens = args.kind or []

            if args.target == self.LITERALS["list"] and not kind_tokens:
                self._show_targets()
                return

            if len(kind_tokens) == 1 and kind_tokens[0] == self.LITERALS["list"]:
                target = self._resolve_existing_target(args.target)
                self._show_results_list(target)
                return

            if not kind_tokens:
                raise ValueError(self._show_usage())

            target = self._resolve_existing_target(args.target)
            kind = self._resolve_show_kind_tokens(kind_tokens)

            if kind == self.LITERALS["all"]:
                ordered = ["nmap", "files", "dirs", "subs"]
                for result_kind in ordered:
                    try:
                        actual_kind, result_file = self._preferred_show_kind_for_all(target, result_kind)
                    except FileNotFoundError:
                        continue
                    self._remember_result_action(target, actual_kind)
                    self._show_single_result_file(result_file, actual_kind, args.page, args.page_size)
                return

            if not self._is_showable_result_name(kind):
                raise ValueError(self._show_usage())

            self._remember_result_action(target, kind)
            self._show_single_result(target, kind, args.page, args.page_size)

        except FileNotFoundError as exc:
            self.perror(f"[!] {exc}")
        except Exception as exc:
            self._print_error(f"[!] failed to show results:\n{exc}")

    @cmd2.with_argparser(list_parser)
    def do_list(self, args: argparse.Namespace) -> None:
        try:
            if args.target is None:
                self._show_targets()
                return

            target = self._resolve_existing_target(args.target)
            self._show_results_list(target)

        except FileNotFoundError as exc:
            self.perror(f"[!] {exc}")
        except Exception as exc:
            self.perror(f"[!] failed to list items: {exc}")

    @cmd2.with_argparser(remove_parser)
    def do_remove(self, args: argparse.Namespace) -> None:
        try:
            if args.target == self.LITERALS["list"] and args.kind is None:
                self._show_targets()
                return

            if args.kind == self.LITERALS["list"]:
                target = self._resolve_existing_target(args.target)
                self._show_results_list(target)
                return

            target = self._resolve_existing_target(args.target)
            scan_dir = self._get_scan_dir(target)

            if args.kind is None:
                label = self._target_folder(target)
                if not self._confirm(f"Remove target '{label}'?"):
                    self.poutput("[+] cancelled")
                    return

                shutil.rmtree(scan_dir)
                self.poutput(f"[+] removed target: {label}")
                return

            kind = self._resolve_last_result_kind(args.kind)

            if kind == self.LITERALS["all"]:
                if not self._confirm(f"Remove all results for target '{self._target_folder(target)}'?"):
                    self.poutput("[+] cancelled")
                    return

                removed_any = False
                for result_kind in self.RESULT_KINDS:
                    result_file = scan_dir / self.RESULT_FILES[result_kind]
                    if result_file.exists():
                        result_file.unlink()
                        self.poutput(f"[+] removed result: {result_kind} for {self._target_folder(target)}")
                        self._remember_result_action(target, result_kind)
                        removed_any = True

                if not removed_any:
                    self.poutput("[+] no result files found to remove")

                if scan_dir.exists() and not any(scan_dir.iterdir()):
                    scan_dir.rmdir()
                    self.poutput(f"[+] removed empty target folder: {self._target_folder(target)}")
                return

            if kind not in self.RESULT_KINDS:
                raise ValueError(self._remove_usage())

            result_file = self._get_result_file(target, kind)

            if not self._confirm(
                f"Remove file '{result_file.name}' for target '{self._target_folder(target)}'?"
            ):
                self.poutput("[+] cancelled")
                return

            result_file.unlink()
            self._remember_result_action(target, kind)
            self.poutput(f"[+] removed result: {kind} for {self._target_folder(target)}")

            if not any(scan_dir.iterdir()):
                scan_dir.rmdir()
                self.poutput(f"[+] removed empty target folder: {self._target_folder(target)}")

        except FileNotFoundError as exc:
            self.perror(f"[!] {exc}")
        except Exception as exc:
            self._print_error(f"failed to remove:\n{exc}")

    @cmd2.with_argparser(scan_parser)
    def do_scan(self, args: argparse.Namespace) -> None:
        try:
            if args.action == "list":
                self._scan_list()
                return
            if args.action == "show":
                self._scan_show(args.name)
                return
            if args.action == "set":
                self._scan_set(args.name, args.command)
                return
            if args.action == "add":
                self._scan_add(args.name, args.command)
                return
            if args.action == "remove":
                self._scan_remove(args.name)
                return
            if args.action == "autofilter":
                self._scan_autofilter(args.mode)
                return

            raise ValueError("unknown scan action")

        except Exception as exc:
            self.perror(f"[!] scan command failed: {exc}")

    @cmd2.with_argparser(filter_parser)
    def do_filter(self, args: argparse.Namespace) -> None:
        try:
            if args.target == self.LITERALS["list"] and args.kind is None:
                self._show_targets()
                return

            if args.kind == self.LITERALS["list"]:
                target = self._resolve_existing_target(args.target)
                self._show_results_list(target)
                return

            if args.kind is None:
                raise ValueError(self._filter_usage())

            target = self._resolve_existing_target(args.target)
            kind = self._resolve_last_result_kind(args.kind)

            if kind not in self.FILTERABLE_KINDS:
                raise ValueError("filter only supports files, dirs, or subs")

            source_file = self._get_result_file(target, kind)
            scan_dir = self._get_scan_dir(target)

            overrides = {
                "status": args.status,
                "min_words": args.min_words,
                "max_words": args.max_words,
                "min_lines": args.min_lines,
                "max_lines": args.max_lines,
                "min_length": args.min_length,
                "max_length": args.max_length,
                "match": args.match,
                "exclude": args.exclude,
                "regex": args.regex,
            }

            output_file = run_filter(
                config=self.config,
                scan_dir=scan_dir,
                kind=kind,
                source_file=source_file,
                mode="custom_filtered",
                overrides=overrides,
            )
            self._remember_result_action(target, kind)
            self.poutput(f"[+] custom filter saved to: {output_file}")

        except FileNotFoundError as exc:
            self.perror(f"[!] {exc}")
        except Exception as exc:
            self._print_error(f"filter failed:\n{exc}")

    def do_jobs(self, _: str) -> None:
        self._prune_finished_jobs()

        if not self.jobs:
            self.poutput("No background jobs")
            return

        for job_id, job in sorted(self.jobs.items()):
            status = self._job_status(job)
            self.poutput(f"[{job_id}] {job['scan']} {job['target']} -> {job['outfile']} [{status}]")

    def do_reload(self, _: str) -> None:
        self.config.reload()
        self.builtin_scan_profiles = self._load_builtin_scan_profiles()
        self.poutput("[+] config reloaded")

    def do_exit(self, _: str) -> bool:
        return True

    def do_quit(self, _: str) -> bool:
        return True
    
    def _is_showable_result_name(self, name: str) -> bool:
        return (
            name in self.RESULT_KINDS
            or name in self.custom_scan_profiles
            or name in self.FILTER_RESULT_ALIASES
        )

    @staticmethod
    def _format_duration(seconds: float) -> str:
        total = max(0, int(round(seconds)))
        mins, secs = divmod(total, 60)
        hours, mins = divmod(mins, 60)

        if hours:
            return f"{hours}h {mins}m {secs}s"
        if mins:
            return f"{mins}m {secs}s"
        return f"{secs}s"
    
    def _scan_autofilter(self, mode: str) -> None:
        if mode == "show":
            state = "enabled" if self.auto_filter_enabled else "disabled"
            self.poutput(f"[+] auto-filter is {state}")
            return

        if mode == "enable":
            self.auto_filter_enabled = True
            self.poutput("[+] auto-filter enabled")
            return

        if mode == "disable":
            self.auto_filter_enabled = False
            self.poutput("[+] auto-filter disabled")
            return

        raise ValueError(f"unknown autofilter mode: {mode}")

    def _resolve_show_kind_tokens(self, tokens: list[str]) -> str:
        if not tokens:
            raise ValueError(self._show_usage())

        if len(tokens) == 1:
            return self._resolve_last_result_kind(tokens[0])

        normalized = " ".join(tokens).strip().lower()
        parts = normalized.split()

        if "last" in parts and len(parts) == 1:
            return self._resolve_last_result_kind("last")

        if "all" in parts and len(parts) == 1:
            return "all"

        if "nmap" in parts:
            return "nmap"

        base_kind = next((k for k in ("files", "dirs", "subs") if k in parts), None)
        if base_kind:
            has_filtered = "filtered" in parts
            has_custom = "custom" in parts

            if has_filtered and has_custom:
                return f"{base_kind}_cf"
            if has_filtered:
                return f"{base_kind}_f"
            return base_kind

        candidate = normalized.replace(" ", "_")
        return self._resolve_last_result_kind(candidate)

    def _resolve_existing_target(self, target: str) -> str:
        if target == self.LITERALS["last"]:
            if not self.last_target:
                raise ValueError("no previous target available")
            return self.last_target
        return self._resolve_known_target(target)

    def _resolve_known_target(self, value: str) -> str:
        raw = value.strip()
        candidates = self._target_candidates(raw)

        for candidate in candidates:
            scan_dir = self.base_scan_dir / self._target_folder(candidate)
            if scan_dir.exists():
                return candidate

        normalized = self._normalize_target(raw)
        scan_dir = self.base_scan_dir / self._target_folder(normalized)
        if scan_dir.exists():
            return normalized

        raise FileNotFoundError(f"target has not been scanned yet: {value}")

    def _should_auto_filter(self, kind: str) -> bool:
        return self.auto_filter_enabled and kind in self.FILTERABLE_KINDS

    def _run_auto_filter(self, target: str, kind: str, source_file: Path) -> None:
        if not self._should_auto_filter(kind):
            return

        try:
            scan_dir = self._get_scan_dir(target)
            filtered_file = run_filter(
                config=self.config,
                scan_dir=scan_dir,
                kind=kind,
                source_file=source_file,
                mode="filtered",
            )
            self.poutput(f"[+] auto-filtered -> {filtered_file}")
        except Exception as exc:
            self.perror(f"[!] auto-filter failed for {kind}: {exc}")

    def _target_candidates(self, value: str) -> list[str]:
        raw = value.strip()
        candidates: list[str] = []

        if raw.startswith("http://") or raw.startswith("https://"):
            candidates.append(raw)
        else:
            candidates.append(raw)
            candidates.append(f"http://{raw}")
            candidates.append(f"https://{raw}")

        seen = set()
        ordered = []
        for item in candidates:
            if item not in seen:
                seen.add(item)
                ordered.append(item)
        return ordered

    def _store_row_refs(self, rows: list[dict]) -> None:
        self.row_refs = {}
        for row in rows:
            uid = row.get("uid")
            if uid:
                self.row_refs[uid] = row

    def _preferred_show_kind_for_all(self, target: str, kind: str) -> tuple[str, Path]:
        scan_dir = self._get_scan_dir(target)
        base_file = self._get_result_file(target, kind)
        return kind, preferred_result_file(scan_dir, kind, base_file)

    def _show_single_result_file(self, path: Path, kind: str, page: int, page_size: int) -> None:
        if kind == "nmap":
            print_nmap_results(path, page=page, page_size=page_size)
        else:
            rows = print_ffuf_results(path, kind, page=page, page_size=page_size)
            self._store_row_refs(rows)

    def _resolve_row_target(self, value: str) -> str:
        if not (value.startswith("r") and value[1:].isdigit()):
            return self._normalize_target(value)

        row = self.row_refs.get(value)
        if not row:
            raise ValueError(f"unknown row id: {value}")

        target = row.get("target_value") or row.get("url") or row.get("host") or row.get("value")
        if not target:
            raise ValueError(f"row id {value} has no usable target")

        return self._normalize_target(target)

    def _iter_showable_result_names(self, target: str) -> list[str]:
        names = []

        scan_dir = self._get_scan_dir(target)

        for kind in self.RESULT_KINDS:
            result_file = scan_dir / self.RESULT_FILES[kind]
            if result_file.exists():
                names.append(kind)

        for name in sorted(self.custom_scan_profiles):
            result_file = scan_dir / f"{name}.out"
            if result_file.exists():
                names.append(name)

        return names

    def _show_single_result(self, target: str, kind: str, page: int, page_size: int) -> None:
        if kind in self.RESULT_KINDS:
            result_file = self._get_result_file(target, kind)

            if kind == "nmap":
                print_nmap_results(result_file, page=page, page_size=page_size)
            else:
                rows = print_ffuf_results(result_file, kind, page=page, page_size=page_size)
                self._store_row_refs(rows)
            return

        if kind in self.FILTER_RESULT_ALIASES:
            scan_dir = self._get_scan_dir(target)
            result_file = scan_dir / self.FILTER_RESULT_ALIASES[kind]

            if not result_file.exists():
                raise FileNotFoundError(f"target has no result for {kind}")

            base_kind = kind.split("_", 1)[0]
            rows = print_ffuf_results(result_file, base_kind, page=page, page_size=page_size)
            self._store_row_refs(rows)
            return

        self._show_custom_result(target, kind)

    def _show_custom_result(self, target: str, name: str) -> None:
        scan_dir = self._get_scan_dir(target)
        result_file = scan_dir / f"{name}.out"

        if not result_file.exists():
            raise FileNotFoundError(f"target has no result for custom scan '{name}'")

        self.poutput(Text(f"Custom result: {name}", style=self._style("info")))

        try:
            content = result_file.read_text(encoding="utf-8", errors="replace")
        except Exception as exc:
            raise ValueError(f"failed to read custom result '{name}': {exc}") from exc

        if not content.strip():
            self.poutput(Text("[empty file]", style=self._style("muted")))
            return

        for line in content.splitlines():
            self.poutput(line)

    def _resolve_last_scan(self, scan: str) -> str:
        if scan != self.LITERALS["last"]:
            return scan

        if not self.last_scan:
            raise ValueError("no previous scan available")

        return self.last_scan

    def _resolve_last_result_kind(self, kind: str) -> str:
        if kind != self.LITERALS["last"]:
            return kind

        if not self.last_result_kind:
            raise ValueError("no previous result kind available")

        return self.last_result_kind

    def _remember_run(self, target: str, scan: str) -> None:
        self.last_target = target
        self.last_scan = scan

    def _remember_result_action(self, target: str, kind: str) -> None:
        self.last_target = target
        self.last_result_kind = kind

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

    def _print_error(self, message: str) -> None:
        lines = str(message).splitlines() or [str(message)]
        if not lines:
            return
        self.perror(f"[!] {lines[0]}")
        for line in lines[1:]:
            self.perror(f"    {line}")

    def _show_usage(self) -> str:
        return "\n".join([
            "usage:",
            "  show list",
            "  show <target|last> list",
            "  show <target|last> <kind|last|all>",
            "  show <target|last> [custom] filtered <files|dirs|subs>",
        ])

    def _remove_usage(self) -> str:
        kinds = "|".join(self.RESULT_KINDS)
        return "\n".join([
            "usage:",
            "  remove list",
            "  remove <target|last> list",
            f"  remove <target|last> [{kinds}|last|all]",
        ])

    def _filter_usage(self) -> str:
        return "\n".join([
            "usage:",
            "  filter list",
            "  filter <target|last> list",
            "  filter <target|last> <files|dirs|subs|last> \\",
            "    [--status CSV] [--min-words N] [--max-words N] \\",
            "    [--min-lines N] [--max-lines N] [--min-length N] [--max-length N] \\",
            "    [--match TEXT] [--exclude TEXT] [--regex REGEX]",
        ])

    def _confirm(self, prompt: str) -> bool:
        while True:
            answer = input(f"{prompt} [y/N]: ").strip().lower()
            if answer in {"", "n", "no"}:
                return False
            if answer in {"y", "yes"}:
                return True
            self.poutput("Please answer with y or N.")

    def _load_builtin_scan_profiles(self) -> dict[str, str]:
        profiles: dict[str, str] = {}

        for scan_name, config_key in self.BUILTIN_PROFILE_KEYS.items():
            command = self.config.get_command(config_key)
            if command:
                profiles[scan_name] = command

        return profiles

    def _all_scan_profiles(self) -> dict[str, str]:
        profiles = dict(self.builtin_scan_profiles)
        profiles.update(self.custom_scan_profiles)
        return profiles

    def _scan_list(self) -> None:
        profiles = self._all_scan_profiles()

        if not profiles:
            self.poutput("No scan profiles available")
            return

        self.poutput(Text("Available scan profiles", style=self._style("info")))

        for name in sorted(profiles):
            origin = "built-in" if name in self.builtin_scan_profiles else "custom"
            line = Text()
            line.append("- ", style=self._style("target"))
            line.append(name, style=self._style("target"))
            line.append(f" ({origin})", style=self._style("muted"))
            self.poutput(line)

    def _scan_show(self, name: str) -> None:
        profiles = self._all_scan_profiles()
        if name not in profiles:
            raise ValueError(f"unknown scan profile: {name}")
        self.poutput(f"{name}: {profiles[name]}")

    def _scan_set(self, name: str, command: str) -> None:
        if name in self.custom_scan_profiles:
            self.custom_scan_profiles[name] = command
            self.poutput(f"[+] updated custom scan profile: {name}")
            return

        if name in self.builtin_scan_profiles:
            self.builtin_scan_profiles[name] = command
            self.poutput(f"[+] updated built-in scan profile: {name}")
            return

        raise ValueError(f"unknown scan profile: {name}")

    def _scan_add(self, name: str, command: str) -> None:
        if name in self.BUILTIN_SCAN_NAMES or name in self.custom_scan_profiles:
            raise ValueError(f"scan profile already exists: {name}")

        self.custom_scan_profiles[name] = command
        self.poutput(f"[+] added custom scan profile: {name}")

    def _scan_remove(self, name: str) -> None:
        if name in self.builtin_scan_profiles:
            raise ValueError("cannot remove built-in scan profiles")

        if name not in self.custom_scan_profiles:
            raise ValueError(f"unknown custom scan profile: {name}")

        if not self._confirm(f"Remove custom scan profile '{name}'?"):
            self.poutput("[+] cancelled")
            return

        del self.custom_scan_profiles[name]
        self.poutput(f"[+] removed custom scan profile: {name}")

    def _run_builtin_scan(
        self,
        kind: str,
        target: str,
        scan_dir: Path,
        background: bool = False,
    ) -> None:
        template = self.builtin_scan_profiles.get(kind)
        if not template:
            raise ValueError(f"no command configured for scan: {kind}")

        started_at = time.monotonic()

        if kind == "nmap":
            proc, outfile, cmd = run_nmap(
                self._nmap_target(target),
                self.config,
                scan_dir,
                verbosity="silent" if background else "normal",
                template_override=template,
            )
        else:
            proc, outfile, cmd = run_ffuf(
                target,
                kind,
                self.config,
                scan_dir,
                verbosity="silent" if background else "normal",
                template_override=template,
            )

        self.poutput(f"[+] started {kind} scan")
        self.poutput(f"CMD: {' '.join(cmd)}")
        self.poutput(f"OUTFILE: {outfile}")

        if background:
            self._register_job(kind, target, proc, outfile, cmd, started_at=started_at)
            return

        success = self._stream_foreground_process(kind, proc, started_at=started_at)

        if success and kind in self.FILTERABLE_KINDS:
            try:
                filtered_file = run_filter(
                    config=self.config,
                    scan_dir=scan_dir,
                    kind=kind,
                    source_file=outfile,
                    mode="filtered",
                )
                self.poutput(f"[+] auto-filtered -> {filtered_file}")
            except Exception as exc:
                self.perror(f"[!] auto-filter failed for {kind}: {exc}")

    def _run_custom_scan(
        self,
        name: str,
        target: str,
        scan_dir: Path,
        background: bool = False,
    ) -> None:
        command_template = self.custom_scan_profiles.get(name)
        if not command_template:
            raise ValueError(f"unknown custom scan profile: {name}")

        outfile = scan_dir / f"{name}.out"
        cmd = shlex.split(
            command_template.format(
                target=target,
                hostname=self._nmap_target(target),
                outfile=str(outfile),
            )
        )

        started_at = time.monotonic()

        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL if background else subprocess.PIPE,
            stderr=subprocess.DEVNULL if background else subprocess.STDOUT,
            text=True,
            bufsize=1 if not background else -1,
        )

        self.poutput(f"[+] started custom scan {name}")
        self.poutput(f"CMD: {' '.join(cmd)}")
        self.poutput(f"OUTFILE: {outfile}")

        if background:
            self._register_job(name, target, proc, outfile, cmd, started_at=started_at)
            return

        self._stream_foreground_process(name, proc, started_at=started_at)

    def _run_bundle(
        self,
        bundle_kind: str,
        target: str,
        scan_dir: Path,
        background: bool = False,
    ) -> None:
        bundle_started_at = time.monotonic()
        kinds = self._expand_run_kind(bundle_kind)
        self.poutput(f"[+] starting {bundle_kind} bundle for {target}")
        self.poutput(f"[+] bundle plan: {', '.join(kinds)}")

        jobs: list[dict] = []
        failures: list[str] = []
        visible_kind = None if background else (kinds[-1] if kinds and kinds[-1] == "nmap" else None)

        for kind in kinds:
            template = self.builtin_scan_profiles.get(kind)
            if not template:
                failures.append(kind)
                self.perror(f"[!] failed to launch {kind}: no command configured")
                continue

            try:
                if kind == "nmap":
                    proc, outfile, cmd = run_nmap(
                        self._nmap_target(target),
                        self.config,
                        scan_dir,
                        verbosity="normal" if kind == visible_kind else "silent",
                        template_override=template,
                    )
                else:
                    proc, outfile, cmd = run_ffuf(
                        target,
                        kind,
                        self.config,
                        scan_dir,
                        verbosity="silent" if background or kind != visible_kind else "normal",
                        template_override=template,
                    )

                job = {
                    "kind": kind,
                    "target": target,
                    "proc": proc,
                    "outfile": outfile,
                    "cmd": cmd,
                    "reported": False,
                }
                jobs.append(job)
                self.poutput(f"[+] launched {kind}")

            except Exception as exc:
                failures.append(kind)
                self._print_error(f"[!] failed to launch {kind}:\n{exc}")

        if background:
            for job in jobs:
                self._register_job(job["kind"], target, job["proc"], job["outfile"], job["cmd"])
            self.poutput(f"[+] bundle {bundle_kind} launched in background")
            return

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
                self._run_auto_filter(job["target"], job["kind"], job["outfile"])
            else:
                failures.append(job["kind"])
                self.perror(f"[!] failed: {job['kind']} (code {rc})")
            job["reported"] = True

        bundle_elapsed = self._format_duration(time.monotonic() - bundle_started_at)

        if failures:
            failed = ", ".join(dict.fromkeys(failures))
            self.perror(f"[!] bundle {bundle_kind} completed with failures in {bundle_elapsed}: {failed}")
        else:
            self.poutput(f"[+] bundle {bundle_kind} completed in {bundle_elapsed}")

    def _stream_foreground_process(self, name: str, proc, started_at: float | None = None) -> bool:
        if proc.stdout:
            for line in iter(proc.stdout.readline, ""):
                if line == "" and proc.poll() is not None:
                    break
                line = line.rstrip()
                if line:
                    self.poutput(line)

        proc.wait()

        elapsed = None if started_at is None else self._format_duration(time.monotonic() - started_at)

        if proc.returncode == 0:
            if elapsed is None:
                self.poutput(f"[+] completed: {name}")
            else:
                self.poutput(f"[+] completed: {name} in {elapsed}")
            return True

        if elapsed is None:
            self.perror(f"[!] scan failed with code {proc.returncode}")
        else:
            self.perror(f"[!] scan failed with code {proc.returncode} after {elapsed}")
        return False

    def _register_job(
        self,
        scan: str,
        target: str,
        proc,
        outfile: Path,
        cmd: list[str],
        started_at: float | None = None,
    ) -> int:
        job_id = self.next_job_id
        self.next_job_id += 1

        self.jobs[job_id] = {
            "scan": scan,
            "target": target,
            "proc": proc,
            "outfile": outfile,
            "cmd": cmd,
            "started_at": started_at,
        }

        self.poutput(f"[+] job {job_id} started in background: {scan} -> {outfile}")
        return job_id

    def _job_status(self, job: dict) -> str:
        rc = job["proc"].poll()
        if rc is None:
            return "running"
        if rc == 0:
            return "done"
        return f"failed ({rc})"

    def _prune_finished_jobs(self) -> None:
        finished_ids = []

        for job_id, job in self.jobs.items():
            rc = job["proc"].poll()
            if rc is None:
                continue

            elapsed = None
            if job.get("started_at") is not None:
                elapsed = self._format_duration(time.monotonic() - job["started_at"])

            if rc == 0:
                if elapsed is None:
                    self.poutput(f"[+] background job {job_id} completed: {job['scan']}")
                else:
                    self.poutput(f"[+] background job {job_id} completed: {job['scan']} in {elapsed}")

                if job["scan"] in self.FILTERABLE_KINDS:
                    try:
                        scan_dir = self._get_scan_dir(job["target"])
                        filtered_file = run_filter(
                            config=self.config,
                            scan_dir=scan_dir,
                            kind=job["scan"],
                            source_file=job["outfile"],
                            mode="filtered",
                        )
                        self.poutput(f"[+] auto-filtered -> {filtered_file}")
                    except Exception as exc:
                        self.perror(f"[!] auto-filter failed for {job['scan']}: {exc}")
            else:
                if elapsed is None:
                    self.perror(f"[!] background job {job_id} failed: {job['scan']} (code {rc})")
                else:
                    self.perror(f"[!] background job {job_id} failed: {job['scan']} (code {rc}) after {elapsed}")

            finished_ids.append(job_id)

        for job_id in finished_ids:
            del self.jobs[job_id]

    def _report_finished_jobs(self, jobs: list[dict], failures: list[str]) -> None:
        for job in jobs:
            if job["reported"]:
                continue

            rc = job["proc"].poll()
            if rc is None:
                continue

            if rc == 0:
                self.poutput(f"[+] completed: {job['kind']}")
                self._run_auto_filter(job["target"], job["kind"], job["outfile"])
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
    def _result_display_name(cls, filename: str) -> str:
        if filename in cls.RESULT_DISPLAY_NAMES:
            return cls.RESULT_DISPLAY_NAMES[filename]
        if filename.endswith(".out"):
            return filename[:-4]
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
        if filename.endswith(".out"):
            return self._style("result_custom_scan")
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
        parsed = urlparse(target if "://" in target else f"http://{target}")
        scheme = (parsed.scheme or "http").lower()
        host = parsed.netloc or parsed.path
        path = parsed.path.strip("/")

        folder = f"{scheme}_{host}"
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