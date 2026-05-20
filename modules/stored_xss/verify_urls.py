"""
Stored XSS 2차 검증용 후보 URL 수집 (앱/게시판 하드코딩 없음).

우선순위:
1. 주입 응답 최종 URL · Location/Refresh 헤더
2. 응답 HTML/JSON에서 상세·목록 페이지 링크 (공통 패턴)
3. 폼 surface / source / Referer / 관련 상위 경로
"""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import urljoin, urlsplit

from modules.file_upload.path_discovery import (
    extract_post_detail_urls,
    iter_related_crawl_urls,
)

_JSON_URL_KEYS = frozenset(
    {
        "url",
        "uri",
        "link",
        "href",
        "path",
        "location",
        "redirect",
        "redirecturl",
        "redirect_url",
        "next",
        "continue",
    }
)

_REFRESH_URL_RE = re.compile(r"url\s*=\s*['\"]?([^;'\"]+)", re.IGNORECASE)


def _append_unique(ordered: list[str], seen: set[str], raw_url: str) -> None:
    url = (raw_url or "").strip()
    if not url or url in seen:
        return
    seen.add(url)
    ordered.append(url)


def _normalize_absolute(base_url: str, raw: str) -> str:
    raw = (raw or "").strip()
    if not raw:
        return ""
    if raw.startswith(("http://", "https://")):
        return raw
    if raw.startswith("//"):
        split = urlsplit(base_url)
        if split.scheme:
            return f"{split.scheme}:{raw}"
        return raw
    return urljoin(base_url, raw)


def _location_from_headers(headers: dict[str, Any] | None, base_url: str) -> list[str]:
    if not headers:
        return []
    found: list[str] = []
    for key, value in headers.items():
        if not value:
            continue
        key_lower = str(key).lower()
        if key_lower == "location":
            found.append(_normalize_absolute(base_url, str(value)))
        elif key_lower == "refresh":
            match = _REFRESH_URL_RE.search(str(value))
            if match:
                found.append(_normalize_absolute(base_url, match.group(1)))
    return [u for u in found if u]


def _urls_from_json(node: Any, base_url: str, found: set[str], *, depth: int = 0) -> None:
    if depth > 6:
        return
    if isinstance(node, dict):
        for key, value in node.items():
            key_lower = str(key).lower()
            if key_lower in _JSON_URL_KEYS and isinstance(value, str) and value.strip():
                found.add(_normalize_absolute(base_url, value))
            else:
                _urls_from_json(value, base_url, found, depth=depth + 1)
    elif isinstance(node, list):
        for item in node:
            _urls_from_json(item, base_url, found, depth=depth + 1)


def _urls_from_json_body(body: str, base_url: str) -> list[str]:
    text = (body or "").strip()
    if not text or text[0] not in "{[":
        return []
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return []
    found: set[str] = set()
    _urls_from_json(data, base_url, found)
    return list(found)


def collect_verify_candidate_urls(
    *,
    base_url: str,
    surface: Any,
    injection_res: Any,
    max_detail_pages: int = 5,
) -> list[str]:
    """
    저장형 XSS 재검증에 GET할 URL 후보 목록 (중복 제거, 삽입 순서 유지).
    """
    ordered: list[str] = []
    seen: set[str] = set()

    def add(raw: str) -> None:
        normalized = _normalize_absolute(resolve_base, raw)
        if normalized:
            _append_unique(ordered, seen, normalized)

    resolve_base = (base_url or "").strip()
    if not resolve_base:
        resolve_base = str(getattr(injection_res, "url", "") or getattr(surface, "url", "") or "")

    final_url = str(getattr(injection_res, "url", "") or "")
    if final_url:
        add(final_url)
        if not resolve_base:
            resolve_base = final_url

    inj_headers = getattr(injection_res, "headers", None) or {}
    for header_url in _location_from_headers(inj_headers, resolve_base):
        add(header_url)

    injection_body = getattr(injection_res, "text", "") or ""
    if injection_body:
        for detail_url in extract_post_detail_urls(
            injection_body,
            resolve_base,
            max_posts=max_detail_pages,
        ):
            add(detail_url)
        for json_url in _urls_from_json_body(injection_body, resolve_base):
            add(json_url)

    surface_url = str(getattr(surface, "url", "") or "")
    source_url = getattr(surface, "source_url", None)
    for related in iter_related_crawl_urls(
        surface_url=surface_url,
        source_url=str(source_url) if source_url else None,
    ):
        add(related)

    if surface_url:
        add(surface_url)

    req_headers = getattr(surface, "headers", {}) or {}
    referer = req_headers.get("Referer") or req_headers.get("referer")
    if referer:
        add(str(referer))

    if base_url:
        add(base_url)
    elif resolve_base and resolve_base not in seen:
        add(resolve_base)

    return ordered
