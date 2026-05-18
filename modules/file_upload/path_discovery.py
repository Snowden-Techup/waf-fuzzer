"""
Upload path discovery for stage-2 verification (no hardcoded /uploads/).

Strategies (in priority order):
1. Parse upload response (JSON fields, HTML attributes, loose URL regex)
2. GET related pages (form source, parent routes) and parse DOM for filename
3. Probe common upload directory wordlist (fallback)
"""

from __future__ import annotations

import json
import re
from html import unescape
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urljoin, urlsplit

from bs4 import BeautifulSoup

from modules.file_upload.markers import VERIFY_TEMPLATE

# Frequently used static upload roots (fallback only).
COMMON_UPLOAD_DIRS: tuple[str, ...] = (
    "/uploads/",
    "/upload/",
    "/images/",
    "/files/",
    "/file/",
    "/media/",
    "/assets/",
    "/static/uploads/",
    "/public/uploads/",
    "/public/",
    "/data/",
    "/storage/",
    "/attachments/",
    "/attachment/",
    "/wp-content/uploads/",
    "/content/uploads/",
)

_JSON_URL_KEYS = frozenset(
    {
        "url",
        "path",
        "file",
        "filename",
        "fileurl",
        "file_url",
        "filepath",
        "file_path",
        "location",
        "src",
        "href",
        "download",
        "downloadurl",
        "link",
    }
)

_HTML_ATTRS = (
    ("img", "src"),
    ("a", "href"),
    ("script", "src"),
    ("source", "src"),
    ("link", "href"),
    ("embed", "src"),
    ("object", "data"),
    ("video", "src"),
    ("audio", "src"),
)


class _FilenamePathCollector(HTMLParser):
    def __init__(self, filename: str) -> None:
        super().__init__()
        self._needle = filename.lower()
        self.paths: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        for _key, value in attrs:
            if value:
                self._maybe_add(value)

    def handle_data(self, data: str) -> None:
        self._maybe_add(data)

    def _maybe_add(self, value: str) -> None:
        raw = unescape(value).strip().strip("'\"")
        if raw and self._needle in raw.lower():
            self.paths.add(raw)


def _normalize_to_url(base_url: str, raw_path: str) -> str:
    raw = unescape(raw_path).strip().strip("'\"")
    if not raw:
        return ""
    if raw.startswith(("http://", "https://")):
        return raw
    if raw.startswith("//"):
        split = urlsplit(base_url)
        return f"{split.scheme}:{raw}"
    normalized = raw if raw.startswith("/") else f"/{raw.lstrip('./')}"
    return urljoin(base_url, normalized)


def _extract_loose_url_regex(response_text: str, filename: str) -> set[str]:
    escaped = re.escape(filename)
    found: set[str] = set()
    for match in re.findall(
        rf"([^\s\"'<>]+{escaped}[^\s\"'<>]*)",
        response_text,
        re.IGNORECASE,
    ):
        found.add(unescape(match).strip().strip("'\""))
    return found


def _walk_json_for_filename(node: Any, filename: str, found: set[str]) -> None:
    needle = filename.lower()

    if isinstance(node, dict):
        for key, value in node.items():
            key_lower = str(key).lower()
            if isinstance(value, str) and needle in value.lower():
                if key_lower in _JSON_URL_KEYS or "/" in value or value.startswith("http"):
                    found.add(value)
            _walk_json_for_filename(value, filename, found)
    elif isinstance(node, list):
        for item in node:
            _walk_json_for_filename(item, filename, found)
    elif isinstance(node, str) and needle in node.lower():
        if "/" in node or node.startswith("http"):
            found.add(node)


def extract_paths_from_text(response_text: str, filename: str) -> list[str]:
    """Strategy 1: upload response body (JSON + HTML + regex)."""
    if not response_text or not filename:
        return []

    paths: set[str] = set()
    paths.update(_extract_loose_url_regex(response_text, filename))

    stripped = response_text.strip()
    if stripped.startswith(("{", "[")):
        try:
            parsed = json.loads(stripped)
            _walk_json_for_filename(parsed, filename, paths)
        except json.JSONDecodeError:
            pass

    collector = _FilenamePathCollector(filename)
    try:
        collector.feed(response_text)
    except Exception:
        pass
    paths.update(collector.paths)

    try:
        soup = BeautifulSoup(response_text, "html.parser")
        needle = filename.lower()
        for tag, attr in _HTML_ATTRS:
            for element in soup.find_all(tag):
                value = element.get(attr)
                if value and needle in str(value).lower():
                    paths.add(str(value))
    except Exception:
        pass

    return [path for path in paths if path]


def build_fallback_urls(base_url: str, filename: str) -> list[str]:
    """Strategy 3: common upload directories + filename."""
    urls: list[str] = []
    for directory in COMMON_UPLOAD_DIRS:
        urls.append(urljoin(base_url, f"{directory.rstrip('/')}/{filename}"))
    return urls


# Patterns that indicate a "post/item detail" URL.
# Matched against href values in listing pages.
_POST_DETAIL_PATTERNS: tuple[re.Pattern, ...] = (
    re.compile(r"/board/view\?", re.IGNORECASE),
    re.compile(r"/post/view\?", re.IGNORECASE),
    re.compile(r"/article/view\?", re.IGNORECASE),
    re.compile(r"/bbs/view\?", re.IGNORECASE),
    re.compile(r"[?&]id=\d+", re.IGNORECASE),
    re.compile(r"/posts?/\d+", re.IGNORECASE),
    re.compile(r"/articles?/\d+", re.IGNORECASE),
    re.compile(r"/board/\d+", re.IGNORECASE),
)

_ID_FROM_URL = re.compile(r"[?&]id=(\d+)|/(\d+)(?:[/?#]|$)")


def _extract_post_id(href: str) -> int:
    m = _ID_FROM_URL.search(href)
    if m:
        return int(m.group(1) or m.group(2))
    return -1


def extract_post_detail_urls(
    response_text: str,
    base_url: str,
    *,
    max_posts: int = 5,
) -> list[str]:
    """
    Strategy 2a: From a board-listing page (upload redirect target),
    extract the most recently created post detail URLs so the next step
    can scan them for embedded file links.

    Posts are sorted by numeric ID descending (newest first).
    """
    if not response_text:
        return []
    try:
        soup = BeautifulSoup(response_text, "html.parser")
    except Exception:
        return []

    candidates: list[tuple[int, str]] = []
    for tag in soup.find_all("a", href=True):
        href = str(tag["href"])
        if any(pat.search(href) for pat in _POST_DETAIL_PATTERNS):
            full_url = urljoin(base_url, href)
            post_id = _extract_post_id(href)
            candidates.append((post_id, full_url))

    # Highest ID first (newest post)
    candidates.sort(key=lambda t: t[0], reverse=True)
    seen: set[str] = set()
    result: list[str] = []
    for _, url in candidates:
        if url not in seen:
            seen.add(url)
            result.append(url)
            if len(result) >= max_posts:
                break
    return result


def extract_file_links_from_page(page_text: str, base_url: str, filename: str) -> list[str]:
    """
    Strategy 2b: Inside a post detail page, find any hyperlink (a/img/…)
    whose href/src contains the uploaded filename.
    """
    paths = extract_paths_from_text(page_text, filename)
    urls: list[str] = []
    seen: set[str] = set()
    for raw in paths:
        url = _normalize_to_url(base_url, raw)
        if url and url not in seen:
            seen.add(url)
            urls.append(url)
    return urls


def iter_related_crawl_urls(*, surface_url: str, source_url: str | None) -> list[str]:
    """Strategy 2c: Parent/sibling pages of the upload form."""
    seen: set[str] = set()
    ordered: list[str] = []

    def add(raw: str) -> None:
        if not raw or raw in seen:
            return
        seen.add(raw)
        ordered.append(raw)

    for raw in (source_url, surface_url):
        if not raw:
            continue
        add(raw)
        split = urlsplit(raw)
        if not split.scheme or not split.netloc:
            continue
        base = f"{split.scheme}://{split.netloc}"
        parts = [part for part in split.path.split("/") if part]
        if len(parts) > 1:
            parent_path = "/" + "/".join(parts[:-1])
            add(urljoin(base, parent_path))
            if split.query:
                add(urljoin(base, f"{parent_path}?{split.query}"))
        add(base)

    return ordered


def merge_verify_urls(
    *,
    base_url: str,
    filename: str,
    discovered_paths: list[str],
    payload: Any,
    surface_url: str = "",
    include_fallback: bool = True,
) -> list[str]:
    """Dedupe with priority: explicit paths > discovered > fallback > template routes."""
    ordered: list[str] = []
    seen: set[str] = set()

    def add_url(url: str) -> None:
        if not url or url in seen:
            return
        seen.add(url)
        ordered.append(url)

    for path in getattr(payload, "verify_paths", None) or ():
        add_url(urljoin(base_url, str(path)))

    if (getattr(payload, "verify_mode", "") or "").lower() == VERIFY_TEMPLATE:
        split = urlsplit(surface_url or base_url)
        if split.scheme and split.netloc:
            add_url(f"{split.scheme}://{split.netloc}/")

    for raw_path in discovered_paths:
        add_url(_normalize_to_url(base_url, raw_path))

    if include_fallback:
        for url in build_fallback_urls(base_url, filename):
            add_url(url)

    return ordered


async def _fetch_text(
    session: Any,
    url: str,
    request_kwargs: dict[str, Any],
) -> str | None:
    try:
        async with session.get(url, **request_kwargs) as resp:
            if resp.status >= 400:
                return None
            return await resp.text(errors="replace")
    except Exception:
        return None


async def discover_verify_urls(
    session: Any,
    *,
    base_url: str,
    filename: str,
    upload_response_text: str,
    surface_url: str,
    source_url: str | None,
    payload: Any,
    headers: dict[str, Any] | None = None,
    cookies: dict[str, Any] | None = None,
) -> list[str]:
    """
    Run all discovery strategies and return absolute URLs to probe.

    Priority order:
    1. Parse upload response text directly (JSON / HTML / regex)
    2a. If upload response is a post listing, follow newest post detail pages
        and extract file links from them  (stored_xss-style post tracking)
    2b. GET related pages (form source / parent routes) and parse for filename
    3. Common upload directory wordlist (fallback)
    """
    discovered_file_urls: list[str] = []
    seen_file_urls: set[str] = set()

    def add_file_url(url: str) -> None:
        if url and url not in seen_file_urls:
            seen_file_urls.add(url)
            discovered_file_urls.append(url)

    request_kwargs: dict[str, Any] = {}
    if headers:
        request_kwargs["headers"] = headers
    if cookies:
        request_kwargs["cookies"] = cookies

    # --- Strategy 1: parse upload response directly ---
    for path in extract_paths_from_text(upload_response_text, filename):
        add_file_url(_normalize_to_url(base_url, path))

    # --- Strategy 2a: post listing → detail page → file link ---
    # The upload response is often a redirect to a board/listing page.
    # Replicate stored_xss logic: find newest post links, visit each,
    # and look for the uploaded filename inside.
    post_detail_urls = extract_post_detail_urls(upload_response_text, base_url)

    for detail_url in post_detail_urls:
        detail_text = await _fetch_text(session, detail_url, request_kwargs)
        if not detail_text:
            continue
        for url in extract_file_links_from_page(detail_text, base_url, filename):
            add_file_url(url)
        if discovered_file_urls:
            # Filename found in a post → stop scanning more posts
            break

    # --- Strategy 2b: related pages (source, parent routes) ---
    if not discovered_file_urls:
        for page_url in iter_related_crawl_urls(
            surface_url=surface_url, source_url=source_url
        ):
            page_text = await _fetch_text(session, page_url, request_kwargs)
            if not page_text:
                continue
            for path in extract_paths_from_text(page_text, filename):
                add_file_url(_normalize_to_url(base_url, path))

            # This page itself might be a listing — follow its post detail links too
            for detail_url in extract_post_detail_urls(page_text, base_url):
                detail_text = await _fetch_text(session, detail_url, request_kwargs)
                if not detail_text:
                    continue
                for url in extract_file_links_from_page(detail_text, base_url, filename):
                    add_file_url(url)

    # --- Strategy 3: common directory fallback ---
    return merge_verify_urls(
        base_url=base_url,
        filename=filename,
        discovered_paths=discovered_file_urls,
        payload=payload,
        surface_url=surface_url,
        include_fallback=True,
    )
