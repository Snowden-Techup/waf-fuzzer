from __future__ import annotations

import re

from modules.file_upload.payloads import FilePayload

SUCCESS_SIGNATURES = [
    r"succes+fully uploaded",
    r"upload complete",
    r"file uploaded successfully",
    r"the file.+has been uploaded",
    r"saved to",
    r"uploads?/",
]

# Phrase-level only — bare "error"/"failed" false-positive on board XSS titles (onerror=).
ERROR_PHRASES = (
    "upload failed",
    "failed to upload",
    "invalid file",
    "not uploaded",
    "not allowed",
    "forbidden file type",
    "file type not allowed",
)


def _response_indicates_upload_failure(res_lower: str) -> bool:
    return any(phrase in res_lower for phrase in ERROR_PHRASES)


def detect_file_upload(response, payload) -> tuple[bool, list[str]]:
    """
    Stage-1: probable upload success (WAF bypass / storage), before active verification.
    """
    if not isinstance(payload, FilePayload):
        return False, []

    evidences: list[str] = []
    res_text = response.text or ""
    res_lower = res_text.lower()

    if _response_indicates_upload_failure(res_lower):
        return False, evidences

    response_url = str(getattr(response, "url", "") or "").lower()
    if "/board" in response_url and (
        "board-table" in res_lower or "/board/view?id=" in res_lower
    ):
        evidences.append(f"[BoardRedirect] post-submit listing ({response_url})")

    for pattern in SUCCESS_SIGNATURES:
        if re.search(pattern, res_lower, re.IGNORECASE):
            evidences.append(f"[SuccessSignature] matched: {pattern}")
            break

    if payload.filename.lower() in res_lower:
        evidences.append(f"[FilenameReflection] {payload.filename}")

    return (len(evidences) > 0), evidences
