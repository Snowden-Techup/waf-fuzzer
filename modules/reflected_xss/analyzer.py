from __future__ import annotations

import re
import html
import urllib.parse
from enum import Enum, auto
from dataclasses import dataclass
from functools import lru_cache
from typing import Optional, List, Tuple
import logging

logger = logging.getLogger(__name__)

# ============================================================
# 마커 패턴 (payloads.py와 동기화)
# ============================================================
_MARKER_PATTERN = re.compile(r"xSsM4rK3r[a-z0-9]{6}", re.IGNORECASE)


# ============================================================
# Enum & DataClass
# ============================================================
class Confidence(Enum):
    NONE = auto()
    LOW = auto()
    MEDIUM = auto()
    HIGH = auto()


class XSSContext(Enum):
    UNKNOWN = auto()
    HTML_TEXT = auto()
    HTML_ATTRIBUTE_DOUBLE = auto()
    HTML_ATTRIBUTE_SINGLE = auto()
    HTML_ATTRIBUTE_UNQUOTED = auto()
    HTML_ATTRIBUTE_EVENT = auto()
    HTML_COMMENT = auto()
    JAVASCRIPT_STRING = auto()
    JAVASCRIPT_CODE = auto()


@dataclass
class XSSResult:
    is_vulnerable: bool
    confidence: Confidence
    context: XSSContext
    evidence: str = ""


# ============================================================
# 사전 컴파일 정규식
# ============================================================
_RE_HTML_COMMENT = re.compile(r'<!--[\s\S]*?-->')
_RE_SCRIPT_OPEN = re.compile(r'<script[^>]*>', re.I)
_RE_SCRIPT_CLOSE = re.compile(r'</script', re.I)
_RE_EVENT_HANDLER = re.compile(
    r'\bon(load|error|click|mouse\w*|focus|blur|key\w*|submit|change|input'
    r'|toggle|start|begin|animationstart|animationend|transitionend)\s*=',
    re.I
)
_RE_DANGEROUS_JS = re.compile(
    r'\b(alert|confirm|prompt|eval|console\s*\.\s*(log|error|warn|info)'
    r'|document\.|window\.|location[.=]'
    r'|constructor\s*[\[(]|setTimeout|setInterval|Function\s*\()\s*',
    re.I
)

_RE_JS_URI = re.compile(
    r'(?:href|src|action|formaction|data)\s*=\s*["\']?\s*'
    r'(?:javascript\s*:|javascript\s*&(?:colon|#58|#x3a);)',
    re.I
)
_RE_DATA_URI = re.compile(
    r'(?:href|src|srcdoc)\s*=\s*["\']?\s*data\s*:',
    re.I
)


# ============================================================
# 유틸리티 함수
# ============================================================
def _strip_comments(text: str) -> str:
    return _RE_HTML_COMMENT.sub('', text)


@lru_cache(maxsize=512)
def _get_payload_variants(payload: str) -> Tuple[str, ...]:
    """페이로드 변형 생성"""
    variants = {payload, payload.lower()}

    try:
        decoded = urllib.parse.unquote(payload)
        variants.add(decoded)
        variants.add(decoded.lower())
        double = urllib.parse.unquote(decoded)
        variants.add(double)
        variants.add(double.lower())
    except Exception:
        pass

    try:
        html_decoded = html.unescape(payload)
        variants.add(html_decoded)
        variants.add(html_decoded.lower())
    except Exception:
        pass

    normalized = re.sub(r'[\t\n\r]+', ' ', payload)
    variants.add(normalized)
    variants.add(normalized.lower())

    return tuple(v for v in variants if v)


# ============================================================
# 마커 기반 탐지
# ============================================================
def _extract_marker(payload: str) -> Optional[str]:
    match = _MARKER_PATTERN.search(payload)
    return match.group(0) if match else None


def _check_marker_reflection(res_text: str, payload: str) -> Tuple[bool, str]:
    marker = _extract_marker(payload)
    if not marker:
        return False, ""
    if marker.lower() in res_text.lower():
        return True, marker
    return False, ""


# ============================================================
# 컨텍스트 분석
# ============================================================
def _get_context(text: str, pos: int) -> XSSContext:
    start = max(0, pos - 2000)
    before = text[start:pos]
    before_lower = before.lower()

    if before.rfind('<!--') > before.rfind('-->'):
        return XSSContext.HTML_COMMENT

    last_script_open = -1
    for m in _RE_SCRIPT_OPEN.finditer(before_lower):
        last_script_open = m.end()

    if last_script_open > 0:
        last_script_close = -1
        for m in _RE_SCRIPT_CLOSE.finditer(before_lower):
            last_script_close = m.start()
        if last_script_open > last_script_close:
            return _analyze_js_context(before[last_script_open:])

    last_lt = before.rfind('<')
    last_gt = before.rfind('>')

    if last_lt > last_gt:
        return _analyze_attr_context(before[last_lt:])

    return XSSContext.HTML_TEXT


def _analyze_js_context(js_content: str) -> XSSContext:
    in_single = in_double = in_template = False
    i = 0
    while i < len(js_content):
        c = js_content[i]
        if c == '\\' and i + 1 < len(js_content):
            i += 2
            continue
        if c == "'" and not in_double and not in_template:
            in_single = not in_single
        elif c == '"' and not in_single and not in_template:
            in_double = not in_double
        elif c == '`' and not in_single and not in_double:
            in_template = not in_template
        i += 1

    if in_single or in_double or in_template:
        return XSSContext.JAVASCRIPT_STRING
    return XSSContext.JAVASCRIPT_CODE


def _analyze_attr_context(tag_content: str) -> XSSContext:
    if _RE_EVENT_HANDLER.search(tag_content):
        return XSSContext.HTML_ATTRIBUTE_EVENT

    eq_pos = tag_content.rfind('=')
    if eq_pos == -1:
        return XSSContext.HTML_TEXT

    after = tag_content[eq_pos + 1:].lstrip()
    if not after:
        return XSSContext.HTML_ATTRIBUTE_UNQUOTED

    if after[0] == '"':
        return XSSContext.HTML_ATTRIBUTE_DOUBLE if '"' not in after[1:] else XSSContext.HTML_TEXT
    if after[0] == "'":
        return XSSContext.HTML_ATTRIBUTE_SINGLE if "'" not in after[1:] else XSSContext.HTML_TEXT

    if ' ' not in after and '>' not in after:
        return XSSContext.HTML_ATTRIBUTE_UNQUOTED

    return XSSContext.HTML_TEXT


# ============================================================
# 이스케이프 검사
# ============================================================
def _is_escaped(text: str, pos: int, length: int) -> bool:
    if pos <= 0:
        return False

    backslash_count = 0
    i = pos - 1
    while i >= 0 and text[i] == '\\':
        backslash_count += 1
        i -= 1

    return backslash_count % 2 == 1


# ============================================================
# 위험도 분석 (전체/부분 매칭 분리)
# ============================================================
def _analyze_danger(
        area: str,
        payload: str,
        context: XSSContext,
        is_partial: bool = False
) -> Tuple[bool, str]:
    area_lower = area.lower()
    payload_lower = payload.lower()
    evidence_parts: List[str] = []

    if is_partial:
        # 1. 이벤트 핸들러 검사 (on, = 가 있을 때만 정규식 실행)
        if "on" in area_lower and "=" in area_lower:
            if re.search(r'on\w+\s*=\s*["\']?[^"\'>\s]*xSsM4rK3r', area, re.I):
                evidence_parts.append("Marker in event handler")

            if _RE_EVENT_HANDLER.search(area) and _MARKER_PATTERN.search(area):
                if "Marker in event handler" not in evidence_parts:
                    evidence_parts.append("Marker near event handler")

        # 2. Script 태그 검사
        if "<script" in area_lower:
            if re.search(r'<script[^>]*>[^<]*xSsM4rK3r', area, re.I):
                evidence_parts.append("Marker in script tag")

        # 3. JavaScript URI 검사
        if "javascript:" in area_lower:
            if re.search(r'javascript\s*:[^"\'>\s]*xSsM4rK3r', area, re.I):
                evidence_parts.append("Marker in JavaScript URI")

        # 4. 위험한 JS 함수 검사
        if any(func in area_lower for func in ['alert', 'confirm', 'prompt', 'eval', 'console.log']):
            if re.search(
                r'(alert|confirm|prompt|eval|console\s*\.\s*log)\s*[(`][^)`]*xSsM4rK3r',
                area, re.I
            ):
                evidence_parts.append("Marker in JS function call")

            if _RE_DANGEROUS_JS.search(area) and _MARKER_PATTERN.search(area):
                if "Marker in JS function call" not in evidence_parts:
                    evidence_parts.append("Marker near dangerous JS")

    else:
        # ============================================================
        # 전체 매칭: 교차 검증 (오탐 방지)
        # ============================================================
        if '<script' in area_lower or '</script' in area_lower:
            if '<script' in payload_lower or '</script' in payload_lower:
                evidence_parts.append("Script tag injection")

        if _RE_EVENT_HANDLER.search(area):
            if _RE_EVENT_HANDLER.search(payload):
                evidence_parts.append("Event handler detected")

        if _RE_DANGEROUS_JS.search(area):
            if _RE_DANGEROUS_JS.search(payload):
                evidence_parts.append("Dangerous JS function")

        if _RE_JS_URI.search(area):
            if _RE_JS_URI.search(payload):
                evidence_parts.append("JavaScript URI injection")

        if _RE_DATA_URI.search(area):
            if _RE_DATA_URI.search(payload):
                evidence_parts.append("Data URI injection")

    # 컨텍스트별 추가 체크 (공통)
    if context in (XSSContext.HTML_ATTRIBUTE_DOUBLE, XSSContext.HTML_ATTRIBUTE_SINGLE):
        quote = '"' if context == XSSContext.HTML_ATTRIBUTE_DOUBLE else "'"
        if quote in payload or '>' in payload:
            evidence_parts.append("Attribute boundary escape")

    elif context == XSSContext.JAVASCRIPT_STRING:
        if any(c in payload for c in "'\"`"):
            evidence_parts.append("JS string escape")

    elif context == XSSContext.HTML_TEXT:
        if '<' in payload and '>' in payload and not is_partial:
            evidence_parts.append("Tag injection in HTML")

    elif context == XSSContext.HTML_ATTRIBUTE_EVENT:
        evidence_parts.append("Event handler context")

    return bool(evidence_parts), "; ".join(evidence_parts)


# ============================================================
# 신뢰도 계산
# ============================================================
def _calc_confidence(
        context: XSSContext,
        has_danger: bool,
        evidence: str,
        payload: str,
        is_partial: bool = False
) -> Confidence:
    if not has_danger:
        return Confidence.NONE

    strong_indicators = [
        "Script tag injection",
        "Event handler detected",
        "JavaScript URI injection",
        "Dangerous JS function",
        "Marker in event handler",
        "Marker in script tag",
        "Marker in JavaScript URI",
        "Marker in JS function call",
    ]

    has_strong = any(ind in evidence for ind in strong_indicators)

    high_risk_contexts = {
        XSSContext.JAVASCRIPT_CODE,
        XSSContext.HTML_ATTRIBUTE_EVENT,
    }

    if context in high_risk_contexts or has_strong:
        base = Confidence.HIGH
    elif context == XSSContext.HTML_TEXT and "Tag injection" in evidence:
        base = Confidence.HIGH
    elif "Attribute boundary escape" in evidence:
        base = Confidence.MEDIUM
    elif "near" in evidence.lower():
        base = Confidence.MEDIUM
    else:
        base = Confidence.LOW

    if is_partial and not has_strong:
        if base == Confidence.HIGH:
            return Confidence.MEDIUM
        elif base == Confidence.MEDIUM:
            return Confidence.LOW

    return base


def _is_better(new: Confidence, old: Confidence) -> bool:
    order = {Confidence.NONE: 0, Confidence.LOW: 1, Confidence.MEDIUM: 2, Confidence.HIGH: 3}
    return order.get(new, 0) > order.get(old, 0)


# ============================================================
# 위치 검색
# ============================================================
def _find_positions(text_lower: str, payload: str, search_term: str) -> List[int]:
    positions: List[int] = []
    seen: set = set()

    start = 0
    while len(positions) < 10:
        pos = text_lower.find(search_term.lower(), start)
        if pos == -1:
            break
        if pos not in seen:
            seen.add(pos)
            positions.append(pos)
        start = pos + 1

    for variant in _get_payload_variants(payload):
        if len(positions) >= 10:
            break
        start = 0
        while len(positions) < 10:
            pos = text_lower.find(variant.lower(), start)
            if pos == -1:
                break
            if pos not in seen:
                seen.add(pos)
                positions.append(pos)
            start = pos + 1

    return sorted(positions)


# ============================================================
# Baseline 검증
# ============================================================
def _verify_diff(res_text: str, orig_text: str, check_value: str) -> bool:
    if not orig_text:
        return True

    res_lower = res_text.lower()
    orig_lower = orig_text.lower()
    check_lower = check_value.lower()

    if check_lower not in orig_lower:
        return True

    return res_lower.count(check_lower) > orig_lower.count(check_lower)


# ============================================================
# 메인 탐지 함수
# ============================================================
def detect_reflected_xss(
        res_text: str,
        orig_text: Optional[str],
        payload_value: str,
) -> XSSResult:
    """
    Reflected XSS 탐지

    전략:
    1. 전체 매칭 시도 → 성공 시 교차 검증으로 오탐 방지
    2. 실패 시 마커 기반 부분 매칭 → 필터 우회 탐지
    """
    if not res_text or not payload_value:
        return XSSResult(False, Confidence.NONE, XSSContext.UNKNOWN)

    clean_res = _strip_comments(res_text)
    clean_orig = _strip_comments(orig_text) if orig_text else ""
    res_lower = clean_res.lower()

    # 1단계: 전체 매칭
    variants = _get_payload_variants(payload_value)
    full_match = any(v.lower() in res_lower for v in variants)

    # 조기 종료 (성능 최적화)
    marker = _MARKER_PATTERN.search(payload_value)
    if not full_match:
        if not marker or marker.group(0).lower() not in res_lower:
            return XSSResult(False, Confidence.NONE, XSSContext.UNKNOWN)

    # 2단계: 마커 매칭 (전체 실패 시)
    marker_match = False
    matched_marker = ""

    if not full_match:
        marker_match, matched_marker = _check_marker_reflection(clean_res, payload_value)

    if not full_match and not marker_match:
        return XSSResult(False, Confidence.NONE, XSSContext.UNKNOWN)

    is_partial = not full_match and marker_match
    search_term = matched_marker if is_partial else payload_value

    # 3단계: Baseline 검증
    check_value = matched_marker if is_partial else payload_value
    if clean_orig and not _verify_diff(clean_res, clean_orig, check_value):
        return XSSResult(False, Confidence.NONE, XSSContext.UNKNOWN, "Exists in baseline")

    # 4단계: 위치 검색
    positions = _find_positions(res_lower, payload_value, search_term)
    if not positions:
        return XSSResult(False, Confidence.NONE, XSSContext.UNKNOWN)

    # 5단계: 각 위치 분석
    best = (Confidence.NONE, XSSContext.UNKNOWN, "")

    for pos in positions[:10]:
        context = _get_context(clean_res, pos)

        if context == XSSContext.HTML_COMMENT:
            continue

        if _is_escaped(clean_res, pos, len(search_term)):
            continue

        area_size = max(200, len(payload_value) + 100)
        area = clean_res[max(0, pos - area_size):pos + area_size]

        has_danger, evidence = _analyze_danger(area, payload_value, context, is_partial)
        conf = _calc_confidence(context, has_danger, evidence, payload_value, is_partial)

        # ============================================================
        # [2차 검증 로직 추가] 
        # 페이로드가 닫힌 괄호('>')를 포함하고 있고 결과 신뢰도가 HIGH가 나온 경우,
        # 주변 문자열의 따옴표 개수나 태그 시작점 밸런스를 한 번 더 체크하여 
        # 속성값 내부에 포함된 '>'에 의해 HTML_TEXT로 오판되었는지 교차 검증합니다.
        # ============================================================
        if conf == Confidence.HIGH and any('>' in v for v in variants):
            start_idx = max(0, pos - 1000)
            before_snippet = clean_res[start_idx:pos]
            last_lt_idx = before_snippet.rfind('<')
            if last_lt_idx != -1:
                tag_snippet = before_snippet[last_lt_idx:]
                double_quotes = tag_snippet.count('"')
                single_quotes = tag_snippet.count("'")
                # 따옴표 개수가 홀수라면 현재 위치는 속성값 스트링 내부로 판정되므로 LOW로 재조정(Recalibrate)
                if double_quotes % 2 != 0 or single_quotes % 2 != 0:
                    conf = Confidence.LOW
                    evidence = f"[Context Recalibrated] Downgraded due to attribute quote imbalance; {evidence}"

        if _is_better(conf, best[0]):
            best = (conf, context, evidence)

        if best[0] == Confidence.HIGH:
            break

    confidence, context, evidence = best

    if is_partial and confidence != Confidence.NONE:
        evidence = f"[Partial: {matched_marker}] {evidence}"

    return XSSResult(
        is_vulnerable=confidence != Confidence.NONE,
        confidence=confidence,
        context=context,
        evidence=evidence,
    )