from __future__ import annotations

import re
from typing import Any

# Common file field names (no per-app exceptions such as DVWA-only "uploaded").
_FILE_PARAM_HEURISTICS = frozenset(
    {
        "attachment",
        "attachments",
        "file",
        "files",
        "uploaded",
        "uploadfile",
        "userfile",
        "image",
        "images",
        "document",
        "doc",
        "photo",
        "media",
        "avatar",
        "binary",
        "blob",
    }
)

# URL path segments that suggest an upload endpoint.
_URL_UPLOAD_HINTS = (
    "upload",
    "file",
    "attach",
    "attachment",
    "media",
    "avatar",
    "import",
    "document",
)

# Typical text/metadata fields — skip when inferring from upload-like surfaces.
_TEXT_LIKE_PARAMS = frozenset(
    {
        "title",
        "content",
        "subject",
        "body",
        "description",
        "message",
        "summary",
        "name",
        "username",
        "email",
        "password",
        "keyword",
        "search",
        "query",
        "post_type",
        "type",
        "category",
        "order_id",
        "external_url",
        "url",
        "link",
        "csrf",
        "token",
        "nonce",
        "_token",
        "authenticity_token",
        "MAX_FILE_SIZE",
        "max_file_size",
    }
)

# Single-word names often used by submit buttons, not file inputs.
_SUBMIT_LIKE_PARAMS = frozenset(
    {
        "submit",
        "upload",
        "send",
        "save",
        "go",
        "ok",
        "search",
        "login",
        "register",
    }
)

_UPLOAD_FORM_DEFAULTS: dict[str, str] = {
    "title": "waf-fuzzer-test",
    "content": "waf-fuzzer-test",
    "subject": "waf-fuzzer-test",
    "body": "waf-fuzzer-test",
    "description": "waf-fuzzer-test",
    "message": "waf-fuzzer-test",
    "name": "waf-fuzzer-test",
    "summary": "waf-fuzzer-test",
}

_URL_HINT_PATTERN = re.compile(
    r"(?:^|[/?_\-])(?:" + "|".join(re.escape(h) for h in _URL_UPLOAD_HINTS) + r")(?:$|[/?_\-])",
    re.IGNORECASE,
)


def _is_heuristic_file_param(name: str) -> bool:
    lower = name.lower()
    if lower in _SUBMIT_LIKE_PARAMS:
        return False
    return (
        lower in _FILE_PARAM_HEURISTICS
        or lower.endswith("_file")
        or lower.endswith("_upload")
        or lower.endswith("_attachment")
    )


def _surface_likely_upload(surface: Any) -> bool:
    url = str(getattr(surface, "url", "") or "")
    if _URL_HINT_PATTERN.search(url):
        return True
    source_url = str(getattr(surface, "source_url", "") or "")
    return bool(source_url and _URL_HINT_PATTERN.search(source_url))


def select_upload_target_parameters(surface: Any, parameter_list: list[str]) -> list[str]:
    """
    Pick parameters likely to accept file content (module-local heuristics).

    Priority:
    1. Parameter name heuristics (uploaded, attachment, file, …)
    2. Upload-like URL with non-text-like remaining fields
    """
    targets: list[str] = []
    seen: set[str] = set()

    for name in parameter_list:
        key = str(name)
        if key in seen:
            continue
        if _is_heuristic_file_param(key):
            seen.add(key)
            targets.append(key)

    if targets:
        return targets

    if _surface_likely_upload(surface):
        for name in parameter_list:
            key = str(name)
            if key in seen:
                continue
            if key.lower() in _TEXT_LIKE_PARAMS:
                continue
            seen.add(key)
            targets.append(key)

    return targets


def fill_upload_form_defaults(req_params: dict[str, Any], attack_parameter: str) -> None:
    """Fill empty non-file fields so server-side validation does not block uploads."""
    for key, default in _UPLOAD_FORM_DEFAULTS.items():
        if key == attack_parameter or key not in req_params:
            continue
        if str(req_params.get(key, "")).strip():
            continue
        req_params[key] = default
