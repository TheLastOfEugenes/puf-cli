from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

FILTERABLE_KINDS = ("files", "dirs", "subs")

FILTER_SUFFIXES = {
    "filtered": "_f.json",
    "custom_filtered": "_cf.json",
}


def get_filtered_file(scan_dir: Path, kind: str, mode: str) -> Path:
    if kind not in FILTERABLE_KINDS:
        raise ValueError(f"filter not supported for kind: {kind}")
    if mode not in FILTER_SUFFIXES:
        raise ValueError(f"unknown filter mode: {mode}")
    return scan_dir / f"{kind}{FILTER_SUFFIXES[mode]}"


def load_json_results(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, dict):
        raise ValueError("results file is not a JSON object")

    results = data.get("results")
    if results is None:
        data["results"] = []
    elif not isinstance(results, list):
        raise ValueError("results file has invalid 'results'")

    return data


def write_json_results(path: Path, data: dict[str, Any]) -> None:
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def _parse_csv_ints(raw: str | None) -> set[int] | None:
    if raw is None:
        return None
    raw = raw.strip()
    if not raw:
        return None

    values: set[int] = set()
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        values.add(int(item))
    return values


def _normalize_optional_str(value: Any) -> str | None:
    if value is None:
        return None
    value = str(value).strip()
    return value or None


def build_auto_filter_options(config) -> dict[str, Any]:
    filter_cfg = {}
    if hasattr(config, "get_filter_config"):
        filter_cfg = config.get_filter_config() or {}
    elif hasattr(config, "get_section"):
        filter_cfg = config.get_section("filter") or {}
    elif hasattr(config, "parser") and hasattr(config.parser, "has_section") and config.parser.has_section("filter"):
        filter_cfg = dict(config.parser.items("filter"))

    return {
        "status": _normalize_optional_str(
            filter_cfg.get("status_codes")
            or filter_cfg.get("status")
            or "200,204,301,302,307,308,401,403"
        ),
        "min_words": _coerce_int(filter_cfg.get("min_words")),
        "max_words": _coerce_int(filter_cfg.get("max_words")),
        "match": _normalize_optional_str(filter_cfg.get("match")),
        "exclude": _normalize_optional_str(filter_cfg.get("exclude")),
        "regex": _normalize_optional_str(filter_cfg.get("regex")),
    }


def _coerce_int(value: Any) -> int | None:
    if value is None:
        return None
    value = str(value).strip()
    if not value or value.lower() in {"none", "null"}:
        return None
    return int(value)


def row_matches_filter(row: dict[str, Any], options: dict[str, Any]) -> bool:
    status = row.get("status")
    words = row.get("words")
    length = row.get("length")
    lines = row.get("lines")
    url = str(row.get("url", ""))
    host = str(row.get("host", ""))
    input_data = row.get("input", {})
    fuzz = str(input_data.get("FUZZ", "")) if isinstance(input_data, dict) else ""

    haystack = " ".join([url, host, fuzz])

    allowed_status = _parse_csv_ints(options.get("status"))
    if allowed_status is not None:
        try:
            if int(status) not in allowed_status:
                return False
        except (TypeError, ValueError):
            return False

    min_words = options.get("min_words")
    if min_words is not None:
        try:
            if int(words) < int(min_words):
                return False
        except (TypeError, ValueError):
            return False

    max_words = options.get("max_words")
    if max_words is not None:
        try:
            if int(words) > int(max_words):
                return False
        except (TypeError, ValueError):
            return False

    min_lines = options.get("min_lines")
    if min_lines is not None:
        try:
            if int(lines) < int(min_lines):
                return False
        except (TypeError, ValueError):
            return False

    max_lines = options.get("max_lines")
    if max_lines is not None:
        try:
            if int(lines) > int(max_lines):
                return False
        except (TypeError, ValueError):
            return False

    min_length = options.get("min_length")
    if min_length is not None:
        try:
            if int(length) < int(min_length):
                return False
        except (TypeError, ValueError):
            return False

    max_length = options.get("max_length")
    if max_length is not None:
        try:
            if int(length) > int(max_length):
                return False
        except (TypeError, ValueError):
            return False

    match = _normalize_optional_str(options.get("match"))
    if match and match.lower() not in haystack.lower():
        return False

    exclude = _normalize_optional_str(options.get("exclude"))
    if exclude and exclude.lower() in haystack.lower():
        return False

    regex = _normalize_optional_str(options.get("regex"))
    if regex and not re.search(regex, haystack, re.IGNORECASE):
        return False

    return True


def apply_filter_to_file(
    *,
    source_file: Path,
    output_file: Path,
    options: dict[str, Any],
) -> Path:
    data = load_json_results(source_file)
    results = data.get("results", [])

    filtered_results = [
        row for row in results
        if isinstance(row, dict) and row_matches_filter(row, options)
    ]

    out = dict(data)
    out["results"] = filtered_results
    out["total"] = len(filtered_results)
    write_json_results(output_file, out)
    return output_file


def run_filter(
    *,
    config,
    scan_dir: Path,
    kind: str,
    source_file: Path,
    mode: str,
    overrides: dict[str, Any] | None = None,
) -> Path:
    if kind not in FILTERABLE_KINDS:
        raise ValueError("filter only supports files, dirs, or subs")

    options = build_auto_filter_options(config) if mode == "filtered" else {}
    if overrides:
        options.update({k: v for k, v in overrides.items() if v is not None})

    output_file = get_filtered_file(scan_dir, kind, mode)
    return apply_filter_to_file(
        source_file=source_file,
        output_file=output_file,
        options=options,
    )


def preferred_result_file(scan_dir: Path, kind: str, base_file: Path) -> Path:
    if kind == "nmap":
        return base_file

    custom_filtered = get_filtered_file(scan_dir, kind, "custom_filtered")
    if custom_filtered.exists():
        return custom_filtered

    filtered = get_filtered_file(scan_dir, kind, "filtered")
    if filtered.exists():
        return filtered

    return base_file