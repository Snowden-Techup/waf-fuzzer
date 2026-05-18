from __future__ import annotations

import copy
import json
from collections import defaultdict
from pathlib import Path
from typing import Any, Literal

from modules.ssrf.module import SSRF_MODULE_REPORT_NAME

_SSRF_INTERNAL_CLASS = "SSRF-Internal"
_SSRF_OOB_CLASS = "SSRF-OOB"
_BRUTEFORCE_CLASS = "Bruteforce"
_STORED_XSS_CLASS = "stored_xss"

# Consolidated File Upload report classes (group 12+ fixed + Bypass_* variants).
_FILE_UPLOAD_WEBSHELL = "FileUpload-Webshell"
_FILE_UPLOAD_STORED_XSS = "FileUpload-StoredXSS"
_FILE_UPLOAD_PATH_TRAVERSAL = "FileUpload-PathTraversal"
_FILE_UPLOAD_TEMPLATE = "FileUpload-TemplateInjection"

_SQLI_REPORT_TYPES = frozenset(
    {"SQLi-error_based", "SQLi-boolean_blind", "SQLi-time_blind"}
)
_LFI_REPORT_TYPES = frozenset(
    {
        "LFI_Basic_Linux",
        "LFI_Basic_Windows",
        "LFI_PHP_Wrapper",
        "LFI_RCE_Wrapper",
    }
)


def severity_rank(raw: str) -> int:
    """Lower is more severe (critical first)."""
    key = str(raw or "").strip().lower()
    if key in ("critical", "crit"):
        return 0
    if key == "high":
        return 1
    if key in ("medium", "med"):
        return 2
    if key == "low":
        return 3
    return 4


# Evasion / encoding variants of the same logical attack (group under one finding).
_MUTATION_TYPE_SUFFIXES: tuple[str, ...] = (
    "_Double_Encoded",
    "_URL_Encoded",
    "_Null_Byte",
    "_Path_Bypass_1",
    "_Path_Bypass_2",
    "_Case_Bypass",
    "_path_encode",
    "_ip_decimal",
    "_ip_hex",
)


def canonical_attack_type_for_grouping(raw: str) -> str:
    """Strip known mutation suffixes so e.g. LFI_PHP_Wrapper_URL_Encoded -> LFI_PHP_Wrapper."""
    original = str(raw or "")
    s = original
    changed = True
    while changed:
        changed = False
        for suf in _MUTATION_TYPE_SUFFIXES:
            if s.endswith(suf):
                s = s[: -len(suf)]
                changed = True
                break
    return s if s else original


def _module_name(record: dict[str, Any]) -> str:
    return str(record.get("module") or "").strip()


def _raw_attack_type(record: dict[str, Any]) -> str:
    attack = record.get("attack_info") or {}
    return str(attack.get("type") or "").strip()


def _is_ssrf_record(record: dict[str, Any]) -> bool:
    return _module_name(record) == SSRF_MODULE_REPORT_NAME


def _is_oob_ssrf_record(record: dict[str, Any]) -> bool:
    return record.get("ssrf_channel") == "oob"


def _is_inband_ssrf_record(record: dict[str, Any]) -> bool:
    if _is_oob_ssrf_record(record):
        return False
    if record.get("ssrf_channel") == "inband":
        return True
    return _is_ssrf_record(record)


def _ssrf_report_type(record: dict[str, Any]) -> str:
    if _is_oob_ssrf_record(record):
        return _SSRF_OOB_CLASS
    return _SSRF_INTERNAL_CLASS


def _file_upload_report_type(raw_type: str) -> str:
    base = canonical_attack_type_for_grouping(raw_type)
    if base.startswith("Bypass_"):
        return _FILE_UPLOAD_WEBSHELL
    if base in {"Stored_XSS_SVG", "Stored_XSS_HTML"}:
        return _FILE_UPLOAD_STORED_XSS
    if base == "Path_Traversal_File_Write":
        return _FILE_UPLOAD_PATH_TRAVERSAL
    if base == "Template_Overwrite_EJS":
        return _FILE_UPLOAD_TEMPLATE
    if base.startswith("Magic_Byte") or base in {
        "Null_Byte_Injection_PHP",
        "Double_Extension_PHP",
    }:
        return _FILE_UPLOAD_WEBSHELL
    return _FILE_UPLOAD_WEBSHELL


def _osci_report_type(raw_type: str) -> str:
    normalized = raw_type.lower().replace("-", "_")
    if "time" in normalized:
        return "OSCi-time_based"
    return "OSCi-in_band"


def report_attack_type(record: dict[str, Any]) -> str:
    """
    Canonical ``attack_info.type`` for scan_report.json grouping and display.
    """
    module = _module_name(record)
    raw_type = _raw_attack_type(record)
    base_type = canonical_attack_type_for_grouping(raw_type)

    if _is_ssrf_record(record):
        return _ssrf_report_type(record)

    if module == "OS Command Injection":
        return _osci_report_type(raw_type)

    if module == "Brute Force" or base_type.startswith("BF-"):
        return _BRUTEFORCE_CLASS

    if module == "stored_xss" or base_type.lower() == _STORED_XSS_CLASS:
        return _STORED_XSS_CLASS

    if module == "File Upload":
        return _file_upload_report_type(raw_type)

    if base_type in _SQLI_REPORT_TYPES or base_type.startswith("SQLi-"):
        if base_type in _SQLI_REPORT_TYPES:
            return base_type
        lowered = base_type.lower()
        if "error" in lowered:
            return "SQLi-error_based"
        if "boolean" in lowered:
            return "SQLi-boolean_blind"
        if "time" in lowered:
            return "SQLi-time_blind"

    if base_type in _LFI_REPORT_TYPES:
        return base_type

    if raw_type in {"in-band", "time-based"}:
        return _osci_report_type(raw_type)

    if base_type.startswith("BF-"):
        return _BRUTEFORCE_CLASS

    return base_type or raw_type or "Unknown"


def grouping_attack_class(record: dict[str, Any]) -> str:
    """Logical attack class for dedupe keys (collapsed report types)."""
    return report_attack_type(record)


def presentation_for_vulnerability_record(record: dict[str, Any]) -> dict[str, Any]:
    """Apply consolidated report labels after dedupe."""
    out = copy.deepcopy(record)
    attack = out.setdefault("attack_info", {})
    original = str(attack.get("type") or "")
    report_type = report_attack_type(out)
    if report_type:
        attack["type"] = report_type
    if original and report_type and original != report_type:
        attack["attack_variant"] = original
        if _is_ssrf_record(out):
            attack["ssrf_variant"] = original
    return out


def vulnerability_group_key(record: dict[str, Any]) -> tuple[str, str, str, str, str]:
    """
    Group by URL, HTTP method, parameter placement, parameter name, and attack class.

    Uses consolidated report types (``report_attack_type``), e.g. in-band SSRF ->
    ``SSRF-Internal``, OOB SSRF -> ``SSRF-OOB``, File Upload bypass variants ->
    ``FileUpload-Webshell``.
    """
    target = record.get("target") or {}
    return (
        str(target.get("url") or ""),
        str(target.get("method") or ""),
        str(target.get("location") or ""),
        str(target.get("parameter") or ""),
        grouping_attack_class(record),
    )


def vulnerability_sort_key(record: dict[str, Any]) -> tuple[int, str, str]:
    attack = record.get("attack_info") or {}
    target = record.get("target") or {}
    return (
        severity_rank(str(attack.get("severity") or "high")),
        str(target.get("url") or ""),
        str(target.get("parameter") or ""),
    )


def dedupe_vulnerabilities(
    records: list[dict[str, Any]],
    *,
    mode: Literal["first_in_order", "best_evidence"] = "first_in_order",
) -> list[dict[str, Any]]:
    """
    Collapse records that share the same group key to a single entry (one PoC).

    - first_in_order: keep the first record per key (scan / discovery order).
    - best_evidence: for each key, pick the lowest severity rank, then shortest
      payload string, then earliest index in the input list (for offline JSON).
    """
    if mode == "first_in_order":
        seen: set[tuple[str, str, str, str, str]] = set()
        out: list[dict[str, Any]] = []
        for rec in records:
            key = vulnerability_group_key(rec)
            if key in seen:
                continue
            seen.add(key)
            out.append(presentation_for_vulnerability_record(rec))
        return out

    buckets: dict[tuple[str, str, str, str, str], list[tuple[int, dict[str, Any]]]] = (
        defaultdict(list)
    )
    for index, rec in enumerate(records):
        buckets[vulnerability_group_key(rec)].append((index, rec))

    picked: list[dict[str, Any]] = []
    for _key, items in sorted(buckets.items(), key=lambda kv: kv[0]):
        def score(item: tuple[int, dict[str, Any]]) -> tuple[int, int, int]:
            idx, rec = item
            attack = rec.get("attack_info") or {}
            payload = str(attack.get("payload_value") or "")
            return (severity_rank(str(attack.get("severity") or "high")), len(payload), idx)

        picked.append(min(items, key=score)[1])
    return [presentation_for_vulnerability_record(r) for r in picked]


def dedupe_report_document(
    report: dict[str, Any],
    *,
    mode: Literal["first_in_order", "best_evidence"] = "best_evidence",
) -> dict[str, Any]:
    """Return a deep-copied report with vulnerabilities deduped and summary updated."""
    data = copy.deepcopy(report)
    vulns = list(data.get("vulnerabilities") or [])
    raw_count = len(vulns)
    deduped = dedupe_vulnerabilities(vulns, mode=mode)
    deduped_sorted = sorted(deduped, key=vulnerability_sort_key)
    data["vulnerabilities"] = deduped_sorted
    meta = data.setdefault("metadata", {})
    summary = meta.setdefault("summary", {})
    summary["findings"] = len(deduped_sorted)
    summary["findings_raw"] = raw_count
    return data


def full_report_path(output_path: str | Path) -> Path:
    """scan_report.json -> scan_report_full.json"""
    p = Path(output_path)
    return p.with_name(f"{p.stem}_full{p.suffix}")
