from __future__ import annotations

import csv
import difflib
import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable


BASE = Path(r"G:\Users\julia\Desktop\Neuer Ordner (13)\Stolen Code\evidence-package-1.0.3-vs-comparison")
OUT_JSON = Path(r"G:\Users\julia\Desktop\Neuer Ordner (13)\Stolen Code\comparison-website\data\comparison-data.json")
OUT_JS = Path(r"G:\Users\julia\Desktop\Neuer Ordner (13)\Stolen Code\comparison-website\data\comparison-data.js")

ORIGINAL_ROOT = BASE / "01_original_release_1.0.3"
COMPARISON_ROOT = BASE / "02_comparison_artifact"
ATTACHMENTS_ROOT = BASE / "03_report" / "attachments"

ORIGINAL_DECOMPILED = ORIGINAL_ROOT / "decompiled" / "current_bin_release"
COMPARISON_DECOMPILED = COMPARISON_ROOT / "decompiled" / "comparison_artifact"

SCRIPT_PAIRS = [
    (
        ORIGINAL_ROOT / "source" / "SBActions.cs",
        COMPARISON_ROOT / "extracted_scripts" / "script-01-velora-bot-config-menu.cs",
        "Scripts/SBActions.cs",
    ),
    (
        ORIGINAL_ROOT / "source" / "SBActions.Actions.cs",
        COMPARISON_ROOT / "extracted_scripts" / "script-02-velora-bot-actions.cs",
        "Scripts/SBActions.Actions.cs",
    ),
]

HASH_FILES = [
    ATTACHMENTS_ROOT / "dll-pdb-hash-pairs-current-vs-comparison.csv",
    ATTACHMENTS_ROOT / "script-hash-pairs-current-vs-comparison.csv",
    ATTACHMENTS_ROOT / "ui-costura-pairs-current-vs-comparison.csv",
]

GROUP_SUMMARY_CSV = ATTACHMENTS_ROOT / "line-compare-group-summary-release-1.0.3-vs-comparison.csv"
PAIR_DETAILS_CSV = ATTACHMENTS_ROOT / "line-compare-pair-details-release-1.0.3-vs-comparison.csv"
OVERVIEW_JSON = ATTACHMENTS_ROOT / "dll-decompiled-comparison-overview-current-vs-comparison.json"

CODE_EXTENSIONS = {".cs", ".csproj"}

PRIMARY_REPORT_SCOPE_LABEL = "Gesamt (Scope dieses Dokuments)"


@dataclass
class HashInfo:
    sha256: str | None
    line_hash: str | None
    whitespace_free_hash: str | None
    size_bytes: int | None


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest().upper()


def normalized_line_hash(lines: list[str]) -> str:
    meaningful = [ln.rstrip() for ln in lines if ln.strip()]
    payload = "\n".join(meaningful).encode("utf-8")
    return sha256_bytes(payload)


def whitespace_free_hash(lines: list[str]) -> str:
    payload = "".join(re.sub(r"\s+", "", ln) for ln in lines if ln.strip()).encode("utf-8")
    return sha256_bytes(payload)


def read_bytes(path: Path | None) -> bytes | None:
    if not path or not path.exists():
        return None
    return path.read_bytes()


def read_text_lines(path: Path | None) -> list[str] | None:
    if not path or not path.exists():
        return None
    raw = path.read_bytes()
    if b"\x00" in raw and path.suffix.lower() not in {".cs", ".csproj", ".json", ".txt", ".md", ".xml", ".metadata"}:
        return None

    for enc in ("utf-8", "utf-8-sig", "utf-16", "utf-16-le", "utf-16-be", "cp1252"):
        try:
            return raw.decode(enc).splitlines()
        except UnicodeDecodeError:
            continue
    return None


def make_hash_info(path: Path | None, lines: list[str] | None) -> HashInfo:
    raw = read_bytes(path)
    return HashInfo(
        sha256=sha256_bytes(raw) if raw is not None else None,
        line_hash=normalized_line_hash(lines) if lines is not None else None,
        whitespace_free_hash=whitespace_free_hash(lines) if lines is not None else None,
        size_bytes=len(raw) if raw is not None else None,
    )


def meaningful_lines_with_numbers(lines: list[str]) -> list[tuple[int, str]]:
    return [(idx + 1, line) for idx, line in enumerate(lines) if line.strip()]


def diff_rows(left_lines: list[tuple[int, str]], right_lines: list[tuple[int, str]]) -> list[dict]:
    rows: list[dict] = []
    left_text = [line for _, line in left_lines]
    right_text = [line for _, line in right_lines]

    matcher = difflib.SequenceMatcher(a=left_text, b=right_text, autojunk=False)
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            for idx in range(i2 - i1):
                left_no, left_value = left_lines[i1 + idx]
                right_no, right_value = right_lines[j1 + idx]
                rows.append(
                    {
                        "left_no": left_no,
                        "right_no": right_no,
                        "left_text": left_value,
                        "right_text": right_value,
                        "row_type": "equal",
                    }
                )
            continue

        if tag == "replace":
            left_block = left_lines[i1:i2]
            right_block = right_lines[j1:j2]
            common = min(len(left_block), len(right_block))

            for idx in range(common):
                left_no, left_value = left_block[idx]
                right_no, right_value = right_block[idx]
                rows.append(
                    {
                        "left_no": left_no,
                        "right_no": right_no,
                        "left_text": left_value,
                        "right_text": right_value,
                        "row_type": "modified",
                    }
                )

            for idx in range(common, len(left_block)):
                left_no, left_value = left_block[idx]
                rows.append(
                    {
                        "left_no": left_no,
                        "right_no": None,
                        "left_text": left_value,
                        "right_text": "",
                        "row_type": "removed",
                    }
                )

            for idx in range(common, len(right_block)):
                right_no, right_value = right_block[idx]
                rows.append(
                    {
                        "left_no": None,
                        "right_no": right_no,
                        "left_text": "",
                        "right_text": right_value,
                        "row_type": "added",
                    }
                )
            continue

        if tag == "delete":
            for idx in range(i1, i2):
                left_no, left_value = left_lines[idx]
                rows.append(
                    {
                        "left_no": left_no,
                        "right_no": None,
                        "left_text": left_value,
                        "right_text": "",
                        "row_type": "removed",
                    }
                )
            continue

        if tag == "insert":
            for idx in range(j1, j2):
                right_no, right_value = right_lines[idx]
                rows.append(
                    {
                        "left_no": None,
                        "right_no": right_no,
                        "left_text": "",
                        "right_text": right_value,
                        "row_type": "added",
                    }
                )
            continue

    return rows


def summarize_rows(rows: Iterable[dict]) -> dict:
    counts = {"equal": 0, "added": 0, "removed": 0, "modified": 0}
    for row in rows:
        counts[row["row_type"]] += 1
    return counts


def make_all_equal_rows(left_lines: list[tuple[int, str]], right_lines: list[tuple[int, str]]) -> list[dict]:
    rows: list[dict] = []
    for idx in range(min(len(left_lines), len(right_lines))):
        left_no, left_text = left_lines[idx]
        right_no, right_text = right_lines[idx]
        rows.append(
            {
                "left_no": left_no,
                "right_no": right_no,
                "left_text": left_text,
                "right_text": right_text,
                "row_type": "equal",
            }
        )
    return rows


def collect_decompiled_code_pairs() -> list[tuple[Path | None, Path | None, str]]:
    left_files = {
        path.relative_to(ORIGINAL_DECOMPILED).as_posix(): path
        for path in ORIGINAL_DECOMPILED.rglob("*")
        if path.is_file() and path.suffix.lower() in CODE_EXTENSIONS
    }
    right_files = {
        path.relative_to(COMPARISON_DECOMPILED).as_posix(): path
        for path in COMPARISON_DECOMPILED.rglob("*")
        if path.is_file() and path.suffix.lower() in CODE_EXTENSIONS
    }
    rels = sorted(set(left_files) | set(right_files))
    return [(left_files.get(rel), right_files.get(rel), f"Decompiled/{rel}") for rel in rels]


def parse_int(text: str | None) -> int:
    if not text:
        return 0
    return int(str(text).replace("%", "").strip())


def parse_pct(text: str | None) -> float | None:
    if not text:
        return None
    value = str(text).replace("%", "").strip()
    if not value:
        return None
    return float(value)


def parse_bool_text(text: str | None) -> bool | None:
    if text is None:
        return None
    normalized = str(text).strip().lower()
    if normalized in {"true", "yes", "1"}:
        return True
    if normalized in {"false", "no", "0"}:
        return False
    return None


def basename_from_any_path(value: str) -> str:
    cleaned = value.replace("\\", "/").strip()
    if "/" in cleaned:
        return cleaned.rsplit("/", 1)[-1]
    return cleaned


def looks_like_path(value: str) -> bool:
    text = value.strip()
    if not text:
        return False
    if re.search(r"^[A-Za-z]:[\\/]", text):
        return True
    if ("/" in text or "\\" in text) and re.search(r"\.[A-Za-z0-9]{1,8}$", text):
        return True
    return False


def sanitize_report_cell(column: str, value: str) -> str:
    if value and ("file" in column.lower() or looks_like_path(value)):
        return basename_from_any_path(value)
    return value


def load_report_hash_tables() -> list[dict]:
    tables: list[dict] = []
    for csv_path in HASH_FILES:
        if not csv_path.exists():
            continue
        with csv_path.open("r", encoding="utf-8-sig", newline="") as f:
            reader = csv.DictReader(f)
            fieldnames = reader.fieldnames or []
            rows: list[dict] = []
            for raw_row in reader:
                normalized_row: dict[str, str] = {}
                for col in fieldnames:
                    value = raw_row.get(col, "") or ""
                    normalized_row[col] = sanitize_report_cell(col, value)
                rows.append(normalized_row)
        tables.append({"name": csv_path.name, "columns": fieldnames, "rows": rows})
    return tables


def map_pair_title_to_relative_path(title: str) -> str | None:
    if "Config Menu" in title:
        return "Scripts/SBActions.cs"
    if "Actions (Original-Hauptrepo" in title:
        return "Scripts/SBActions.Actions.cs"
    if "BotClient.cs" in title:
        return "Decompiled/Velora.Bot/BotClient.cs"
    if "VeloraClient.cs" in title:
        return "Decompiled/Velora.API/VeloraClient.cs"
    if "PluginConfig.cs" in title:
        return "Decompiled/Velora.Bot/PluginConfig.cs"
    if "SafeFileIO.cs" in title:
        return "Decompiled/Velora.Bot/SafeFileIO.cs"
    if "VeloraChatCommander.cs" in title:
        return "Decompiled/Velora.Bot/VeloraChatCommander.cs"
    return None


def load_report_metrics() -> tuple[dict, dict, dict, set[str]]:
    file_metrics: dict[str, dict] = {}
    group_metrics: dict[str, dict] = {}
    overview_metrics: dict = {}
    primary_paths: set[str] = set()

    if GROUP_SUMMARY_CSV.exists():
        with GROUP_SUMMARY_CSV.open("r", encoding="utf-8-sig", newline="") as f:
            rows = list(csv.DictReader(f))
        for row in rows:
            label = row.get("gruppe", "")
            group_metrics[label] = {
                "pairs": parse_int(row.get("paare")),
                "left_lines": parse_int(row.get("left_lines")),
                "right_lines": parse_int(row.get("right_lines")),
                "equal_lines": parse_int(row.get("equal_lines")),
                "equal_pct_right": row.get("equal_pct_right", ""),
                "added_right": parse_int(row.get("added_right")),
                "removed_left": parse_int(row.get("removed_left")),
            }

    if PAIR_DETAILS_CSV.exists():
        with PAIR_DETAILS_CSV.open("r", encoding="utf-8-sig", newline="") as f:
            rows = list(csv.DictReader(f))
        for row in rows:
            title = row.get("title", "")
            target_path = map_pair_title_to_relative_path(title)
            if not target_path:
                continue
            metric = {
                "source": "pair_details",
                "left_lines": parse_int(row.get("left_lines")),
                "right_lines": parse_int(row.get("right_lines")),
                "equal_lines": parse_int(row.get("equal_lines")),
                "equal_pct_right": row.get("equal_pct_right", ""),
                "added_right": parse_int(row.get("added_right")),
                "removed_left": parse_int(row.get("removed_left")),
                "changed_lines_display": parse_int(row.get("added_right")) + parse_int(row.get("removed_left")),
            }
            file_metrics[target_path] = metric
            primary_paths.add(target_path)

    script_hash_csv = ATTACHMENTS_ROOT / "script-hash-pairs-current-vs-comparison.csv"
    if script_hash_csv.exists():
        with script_hash_csv.open("r", encoding="utf-8-sig", newline="") as f:
            rows = list(csv.DictReader(f))
        for row in rows:
            pair_label = row.get("pair_label", "")
            target_path = None
            if "Config Menu" in pair_label:
                target_path = "Scripts/SBActions.cs"
            elif "Actions (Original-Hauptrepo" in pair_label:
                target_path = "Scripts/SBActions.Actions.cs"

            if not target_path:
                continue

            current = file_metrics.get(target_path, {})
            current["report_line_hash_original"] = row.get("line_hash_original", "")
            current["report_line_hash_comparison"] = row.get("line_hash_comparison_artifact", "")
            current["report_ws_hash_original"] = row.get("ws_hash_original", "")
            current["report_ws_hash_comparison"] = row.get("ws_hash_comparison_artifact", "")
            current["report_line_hash_equal"] = parse_bool_text(row.get("line_hash_equal"))
            file_metrics[target_path] = current

    if OVERVIEW_JSON.exists():
        data = json.loads(OVERVIEW_JSON.read_text(encoding="utf-8"))
        overview_root = data.get("opponent_vs_current_bin_release", {})
        overview_metrics = {
            "files_compared": int(overview_root.get("files_compared", 0)),
            "files_identical_line_hash": int(overview_root.get("files_identical_line_hash", 0)),
            "files_with_changes": int(overview_root.get("files_with_changes", 0)),
            "total_changed_right_lines": int(overview_root.get("total_changed_right_lines", 0)),
        }

        for item in overview_root.get("top_changed_files", []):
            rel = item.get("rel", "")
            if not rel:
                continue
            target_path = f"Decompiled/{rel.replace('\\\\', '/')}"
            current = file_metrics.get(target_path, {})
            file_metrics[target_path] = {
                **current,
                "source": current.get("source", "overview"),
                "left_meaningful": item.get("left_meaningful"),
                "right_meaningful": item.get("right_meaningful"),
                "changed_right": item.get("changed_right"),
                "line_hash_equal": item.get("line_hash_equal"),
                "changed_lines_display": current.get("changed_lines_display", item.get("changed_right", 0)),
            }

    return file_metrics, group_metrics, overview_metrics, primary_paths


def changed_lines_renderer(row_counts: dict) -> int:
    return int(row_counts.get("added", 0)) + int(row_counts.get("removed", 0)) + int(row_counts.get("modified", 0))


def build_entry(
    *,
    entry_id: str,
    group: str,
    relative_path: str,
    left_path: Path | None,
    right_path: Path | None,
    comparison_method: str,
    comparison_method_label: str,
    is_primary_scope: bool,
    report_metrics: dict | None,
) -> dict:
    left_lines = read_text_lines(left_path) or []
    right_lines = read_text_lines(right_path) or []

    left_nonempty = meaningful_lines_with_numbers(left_lines)
    right_nonempty = meaningful_lines_with_numbers(right_lines)

    rows = diff_rows(left_nonempty, right_nonempty)
    row_counts = summarize_rows(rows)

    if report_metrics and report_metrics.get("changed_lines_display", 1) == 0 and len(left_nonempty) == len(right_nonempty):
        rows = make_all_equal_rows(left_nonempty, right_nonempty)
        row_counts = summarize_rows(rows)

    left_hash = make_hash_info(left_path, left_lines)
    right_hash = make_hash_info(right_path, right_lines)

    if report_metrics:
        report_left_line_hash = report_metrics.get("report_line_hash_original")
        report_right_line_hash = report_metrics.get("report_line_hash_comparison")
        report_left_ws_hash = report_metrics.get("report_ws_hash_original")
        report_right_ws_hash = report_metrics.get("report_ws_hash_comparison")

        if report_left_line_hash:
            left_hash.line_hash = report_left_line_hash
        if report_right_line_hash:
            right_hash.line_hash = report_right_line_hash
        if report_left_ws_hash:
            left_hash.whitespace_free_hash = report_left_ws_hash
        if report_right_ws_hash:
            right_hash.whitespace_free_hash = report_right_ws_hash

    renderer_changed = changed_lines_renderer(row_counts)
    shown_changed = report_metrics.get("changed_lines_display", renderer_changed) if report_metrics else renderer_changed

    line_hash_equal = bool(left_hash.line_hash and right_hash.line_hash and left_hash.line_hash == right_hash.line_hash)
    if report_metrics and report_metrics.get("report_line_hash_equal") is not None:
        line_hash_equal = bool(report_metrics.get("report_line_hash_equal"))

    return {
        "id": entry_id,
        "group": group,
        "relative_path": relative_path,
        "kind": "text",
        "text_compare": True,
        "left_exists": left_path is not None,
        "right_exists": right_path is not None,
        "left_hash": left_hash.__dict__,
        "right_hash": right_hash.__dict__,
        "row_counts": row_counts,
        "left_line_count": len(left_nonempty),
        "right_line_count": len(right_nonempty),
        "rows": rows,
        "report_metrics": report_metrics,
        "is_primary_scope": is_primary_scope,
        "comparison_method": comparison_method,
        "comparison_method_label": comparison_method_label,
        "line_hash_equal": line_hash_equal,
        "changed_lines_renderer": renderer_changed,
        "changed_lines_display": shown_changed,
    }


def build_entries(report_file_metrics: dict, primary_paths: set[str]) -> list[dict]:
    entries: list[dict] = []

    for left_path, right_path, rel in collect_decompiled_code_pairs():
        entry = build_entry(
            entry_id=rel.replace("/", "__"),
            group="decompiled",
            relative_path=rel,
            left_path=left_path,
            right_path=right_path,
            comparison_method="dll_decompilation",
            comparison_method_label="DLL decompilation comparison",
            is_primary_scope=rel in primary_paths,
            report_metrics=report_file_metrics.get(rel),
        )
        entries.append(entry)

    for left_path, right_path, rel in SCRIPT_PAIRS:
        entry = build_entry(
            entry_id=rel.replace("/", "__"),
            group="scripts",
            relative_path=rel,
            left_path=left_path,
            right_path=right_path,
            comparison_method="direct_source_vs_script",
            comparison_method_label="Direct source-to-script comparison",
            is_primary_scope=rel in primary_paths,
            report_metrics=report_file_metrics.get(rel),
        )
        entries.append(entry)

    entries.sort(key=lambda x: (not x["is_primary_scope"], x["relative_path"].lower()))
    return entries


def scope_summary_from_entries(entries: list[dict], scope_note: str) -> dict:
    files_total = len(entries)
    files_changed = sum(1 for e in entries if int(e.get("changed_lines_display", 0)) > 0)
    lines_equal = sum(int(e["row_counts"]["equal"]) for e in entries)
    lines_added_right = sum(int(e["row_counts"]["added"]) for e in entries)
    lines_removed_left = sum(int(e["row_counts"]["removed"]) for e in entries)
    lines_modified = sum(int(e["row_counts"]["modified"]) for e in entries)

    right_scope_lines = lines_equal + lines_added_right + lines_modified
    code_match_pct = round((lines_equal / right_scope_lines) * 100, 2) if right_scope_lines else None

    line_hash_comparable_files = sum(
        1 for e in entries if e["left_hash"].get("line_hash") and e["right_hash"].get("line_hash")
    )
    line_hash_identical_files = sum(1 for e in entries if e.get("line_hash_equal"))

    return {
        "files_total": files_total,
        "files_changed": files_changed,
        "lines_equal": lines_equal,
        "lines_added_right": lines_added_right,
        "lines_removed_left": lines_removed_left,
        "lines_modified": lines_modified,
        "code_match_pct": code_match_pct,
        "line_hash_identical_files": line_hash_identical_files,
        "line_hash_comparable_files": line_hash_comparable_files,
        "scope_note": scope_note,
    }


def primary_scope_summary_from_report(
    primary_entries: list[dict],
    report_group_metrics: dict,
) -> dict:
    group = report_group_metrics.get(PRIMARY_REPORT_SCOPE_LABEL)
    if not group:
        return scope_summary_from_entries(primary_entries, "Primary evidence scope (fallback from renderer).")

    files_total = int(group.get("pairs", 0))
    files_changed = sum(1 for e in primary_entries if int(e.get("changed_lines_display", 0)) > 0)
    equal_lines = int(group.get("equal_lines", 0))
    added_right = int(group.get("added_right", 0))
    removed_left = int(group.get("removed_left", 0))

    line_hash_comparable_files = sum(
        1
        for e in primary_entries
        if e["left_hash"].get("line_hash") and e["right_hash"].get("line_hash")
    )
    line_hash_identical_files = sum(1 for e in primary_entries if e.get("line_hash_equal"))

    return {
        "files_total": files_total,
        "files_changed": files_changed,
        "lines_equal": equal_lines,
        "lines_added_right": added_right,
        "lines_removed_left": removed_left,
        "lines_modified": None,
        "code_match_pct": parse_pct(group.get("equal_pct_right", "")),
        "line_hash_identical_files": line_hash_identical_files,
        "line_hash_comparable_files": line_hash_comparable_files,
        "scope_note": f"Primary evidence scope from official report ({files_total} core comparisons).",
    }


def build():
    report_file_metrics, report_group_metrics, report_overview, primary_paths = load_report_metrics()
    entries = build_entries(report_file_metrics, primary_paths)

    primary_entries = [e for e in entries if e.get("is_primary_scope")]

    summary_primary_scope = primary_scope_summary_from_report(primary_entries, report_group_metrics)
    summary_expanded_scope = scope_summary_from_entries(
        entries,
        "Expanded technical scope (all compared code files: direct scripts + required DLL decompilation).",
    )

    method_counters = {
        "direct_source_vs_script_files": sum(1 for e in entries if e.get("comparison_method") == "direct_source_vs_script"),
        "dll_decompilation_files": sum(1 for e in entries if e.get("comparison_method") == "dll_decompilation"),
    }

    payload = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "labels": {
            "left": "Velora.Bot by Streamerforge",
            "right": "New plugin from Velora",
        },
        "default_scope": "expanded",
        "summary_primary_scope": summary_primary_scope,
        "summary_expanded_scope": summary_expanded_scope,
        "summary": summary_expanded_scope,
        "report_overview": report_overview,
        "report_group_metrics": report_group_metrics,
        "method_counters": method_counters,
        "scope_definitions": [
            {
                "id": "expanded",
                "label": "Complete Public Check",
                "description": "Complete code scope from direct script comparisons plus required DLL decompilation outputs.",
            },
            {
                "id": "primary",
                "label": "Primary Evidence Scope",
                "description": "Official report scope with 7 core file comparisons.",
            },
        ],
        "hash_tables_from_report": load_report_hash_tables(),
        "entries": entries,
    }

    OUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    json_text = json.dumps(payload, ensure_ascii=True)
    OUT_JSON.write_text(json_text, encoding="utf-8")
    OUT_JS.write_text(f"window.__COMPARISON_DATA__ = {json_text};", encoding="utf-8")
    print(str(OUT_JSON))


if __name__ == "__main__":
    build()
