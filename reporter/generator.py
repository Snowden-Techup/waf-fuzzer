from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from fuzzer import EngineStats, Finding

from reporter.dedupe import (
    dedupe_vulnerabilities,
    full_report_path,
    vulnerability_sort_key,
)


def _severity_rank(raw: str) -> int:
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


def _finding_sort_key(finding: Finding) -> tuple[int, str, str]:
    payload_obj = finding.payload
    severity = str(getattr(payload_obj, "risk_level", "high"))
    url = str(getattr(finding.surface, "url", "") or "")
    param = str(finding.parameter or "")
    return (_severity_rank(severity), url, param)


class ReportGenerator:
    """
    Converts fuzzing engine statistics and findings into readable reports.
    """

    def __init__(self, stats: EngineStats, findings: list[Finding]) -> None:
        self.stats = stats
        self.findings = findings
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def print_cli_report(self) -> None:
        """
        Prints the scan result in a table-like CLI format.
        """
        table_width = 126
        severity_width = 10
        location_width = 10
        parameter_width = 14
        type_width = 34

        print("\n" + "=" * table_width)
        print("Modular Web Scanner Security Scan Report")
        print(f"Scan completed at: {self.timestamp}")
        print("=" * table_width)

        print("\n[1] Summary")
        print(f"  - queued:    {self.stats.queued}")
        print(f"  - completed: {self.stats.completed}")
        print(f"  - failures:  {self.stats.failures}")
        print(f"  - findings:  {self.stats.findings}")

        if not self.findings:
            print("\nNo findings were detected.")
            print("=" * table_width + "\n")
            return

        print("\n[2] Findings")
        print("-" * table_width)
        print(
            f"{'Severity':<{severity_width}} | {'Location':<{location_width}} | "
            f"{'Parameter':<{parameter_width}} | {'Type':<{type_width}} | Payload"
        )
        print("-" * table_width)

        for finding in sorted(self.findings, key=_finding_sort_key):
            payload_obj = finding.payload
            severity = getattr(payload_obj, "risk_level", "HIGH")
            attack_type = getattr(payload_obj, "attack_type", "PotentialIssue")
            raw_payload = getattr(finding.payload, "value", str(finding.payload))
            safe_payload = raw_payload.replace("\n", "\\n").replace("\r", "\\r")
            payload_value = safe_payload

            param_location = getattr(finding.surface, "param_location", "unknown")
            location_text = getattr(param_location, "name", str(param_location))

            display_payload = (
                payload_value[:37] + "..." if len(payload_value) > 40 else payload_value
            )
            display_type = (
                attack_type[: type_width - 3] + "..."
                if len(attack_type) > type_width
                else attack_type
            )
            print(
                f"{severity:<{severity_width}} | {location_text:<{location_width}} | "
                f"{finding.parameter:<{parameter_width}} | {display_type:<{type_width}} | "
                f"{display_payload}"
            )

        print("-" * table_width)
        print(f"Total findings: {len(self.findings)}")
        print("=" * table_width + "\n")

    def _finding_to_dict(self, finding: Finding) -> dict[str, Any]:
        payload_obj = finding.payload
        payload_value = getattr(payload_obj, "value", str(payload_obj))
        attack_type = getattr(payload_obj, "attack_type", "Unknown")
        severity = getattr(payload_obj, "risk_level", "high")
        description = getattr(payload_obj, "description", "")

        response = finding.response
        status_code = getattr(response, "status", 0)
        response_time = getattr(response, "elapsed_time", getattr(response, "elapsed", 0.0))
        error_log = getattr(response, "error", None)

        method = getattr(finding.surface.method, "name", str(finding.surface.method))
        location = getattr(
            getattr(finding.surface, "param_location", "unknown"),
            "name",
            str(getattr(finding.surface, "param_location", "unknown")),
        )

        row: dict[str, Any] = {
            "target": {
                "url": finding.surface.url,
                "method": method,
                "location": location,
                "parameter": finding.parameter,
            },
            "attack_info": {
                "payload_value": payload_value,
                "type": attack_type,
                "severity": severity,
                "description": description,
            },
            "evidence": {
                "status_code": status_code,
                "response_time": round(float(response_time), 4),
                "error_log": error_log,
            },
        }
        if finding.module_name:
            row["module"] = finding.module_name
        ch = getattr(payload_obj, "channel", None)
        if ch is not None:
            row["ssrf_channel"] = ch
        return row

    def export_to_json(self, filepath: str = "scan_result.json") -> None:
        """
        Writes a deduplicated report to ``filepath`` (one PoC per URL / parameter / type)
        and the complete per-payload list to ``<stem>_full<suffix>``.
        """
        full_vulnerabilities = [
            self._finding_to_dict(f) for f in sorted(self.findings, key=_finding_sort_key)
        ]
        discovery_vulnerabilities = [self._finding_to_dict(f) for f in self.findings]
        deduped = dedupe_vulnerabilities(discovery_vulnerabilities, mode="first_in_order")
        deduped_sorted = sorted(deduped, key=vulnerability_sort_key)

        full_report: dict[str, Any] = {
            "metadata": {
                "scan_time": self.timestamp,
                "summary": {
                    "queued": self.stats.queued,
                    "completed": self.stats.completed,
                    "failures": self.stats.failures,
                    "findings": self.stats.findings,
                },
            },
            "vulnerabilities": full_vulnerabilities,
        }
        deduped_report: dict[str, Any] = {
            "metadata": {
                "scan_time": self.timestamp,
                "summary": {
                    "queued": self.stats.queued,
                    "completed": self.stats.completed,
                    "failures": self.stats.failures,
                    "findings": len(deduped_sorted),
                    "findings_raw": self.stats.findings,
                },
            },
            "vulnerabilities": deduped_sorted,
        }

        full_path = full_report_path(filepath)
        with open(filepath, "w", encoding="utf-8") as file:
            json.dump(deduped_report, file, ensure_ascii=False, indent=2)
        with open(full_path, "w", encoding="utf-8") as file:
            json.dump(full_report, file, ensure_ascii=False, indent=2)

        print(f"report saved (deduplicated): {filepath}")
        print(f"report saved (full payloads): {full_path}")