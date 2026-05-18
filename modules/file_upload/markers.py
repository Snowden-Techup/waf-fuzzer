"""Markers and verification modes for active file-upload confirmation."""

from __future__ import annotations

# Backward-compatible PHP RCE marker (also used in generated webshells).
RCE_PHP_MARKER = "WAF_UPLOAD_VULN_DETECTED"
RCE_NODE_MARKER = "WAF_NODE_RCE_DETECTED"
XSS_MARKER = "WAF_XSS_UPLOAD_DETECTED"

VERIFY_RCE = "rce"
VERIFY_STATIC = "static"
VERIFY_TEMPLATE = "template"

# If any of these appear alongside the marker, the response is source — not execution.
PHP_SHELL_TAGS = ("<?php", "<?=", "<?", "&lt;?php", "&lt;?=")
NODE_TEMPLATE_TAGS = ("<%=", "<%", "&lt;%=", "&lt;%")
JSP_SHELL_TAGS = ("<%", "%>", "&lt;%")

DEFAULT_SHELL_TAGS_BY_MODE: dict[str, tuple[str, ...]] = {
    VERIFY_RCE: PHP_SHELL_TAGS + JSP_SHELL_TAGS,
    VERIFY_TEMPLATE: NODE_TEMPLATE_TAGS,
}
