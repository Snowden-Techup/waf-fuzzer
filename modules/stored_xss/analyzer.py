import html
import re
import difflib
import base64
from html.parser import HTMLParser
from typing import List, Optional, Any, Dict
from bs4 import BeautifulSoup
from core.models import Payload

# =====================================================================
# 상수 및 설정 분리
# =====================================================================
MAX_RESPONSE_LENGTH = 2000000
MAX_PAYLOAD_LENGTH = 10000
OBFUSCATION_THRESHOLD = 0.8

_DANGEROUS_PATTERNS = [
    re.compile(r'on(?:error|load|click|focus|mouseover|start|toggle|begin)\s*=\s*[^\s"\'>=]+', re.I),
    re.compile(r'javascript\s*:[^"\'>\s]{1,1000}', re.I),
    re.compile(r'data\s*:[^"\'>\s]{1,1000}', re.I),
]

_OBFUSCATION_PATTERNS = [
    (re.compile(r'<script[^>]*>([^<]*)</script>', re.I), 'script'),
    (re.compile(r'<[^>]+\s+(on\w+)\s*=', re.I), 'event'),
    (re.compile(r'(javascript)\s*:', re.I), 'protocol'),
    (re.compile(r'<(svg|iframe|object|embed|img)[^>]*>', re.I), 'dangerous_tag'),
]

_FUNC_PATTERNS = [
    re.compile(r'alert\s*\([^)]*\)', re.I),
    re.compile(r'eval\s*\([^)]*\)', re.I),
    re.compile(r'prompt\s*\([^)]*\)', re.I),
    re.compile(r'confirm\s*\([^)]*\)', re.I),
    re.compile(r'atob\s*\([^)]*\)', re.I),
    re.compile(r'document\s*\.\s*cookie', re.I),
    re.compile(r'document\s*\.\s*location', re.I),
]

_ATOB_PATTERN = re.compile(r"atob\s*\(\s*['\"]([^'\"]+)['\"]", re.I)
_JS_COMMENT_SAFE_PATTERN = re.compile(r'/\*[^*]*\*+(?:[^/*][^*]*\*+)*/|//[^\n]*')
_DOM_SINK_PATTERN = re.compile(r'(innerHTML|outerHTML|document\.write|eval|setTimeout|setInterval)\s*\(?\s*[=(]', re.I)

_EXECUTABLE_XSS_PATTERNS = [
    re.compile(r'<script[^>]*>.*?</script>', re.I | re.DOTALL),
    re.compile(r'<[a-zA-Z][^>]*\s+on\w+\s*=\s*["\'][^"\']+["\'][^>]*>', re.I),
    re.compile(r'<[a-zA-Z][^>]*\s+on\w+\s*=\s*[^\s>]+[^>]*>', re.I),
    re.compile(r'<[^>]+(?:href|src|action|formaction|data)\s*=\s*["\']?\s*javascript:[^>]+>', re.I),
    re.compile(r'<(?:svg|img|body|iframe|input|details|marquee)[^>]*\s+on\w+\s*=', re.I),
]


class XSSContextParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.in_script = False
        self.in_textarea = False
        self.in_style = False
        self.in_noscript = False
        self.in_title = False
        self.in_template = False
        self.in_xmp = False
        self.in_iframe = False

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        if tag == 'script':
            self.in_script = True
        elif tag == 'textarea':
            self.in_textarea = True
        elif tag == 'style':
            self.in_style = True
        elif tag == 'noscript':
            self.in_noscript = True
        elif tag == 'title':
            self.in_title = True
        elif tag == 'template':
            self.in_template = True
        elif tag == 'xmp':
            self.in_xmp = True
        elif tag == 'iframe':
            self.in_iframe = True

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag == 'script':
            self.in_script = False
        elif tag == 'textarea':
            self.in_textarea = False
        elif tag == 'style':
            self.in_style = False
        elif tag == 'noscript':
            self.in_noscript = False
        elif tag == 'title':
            self.in_title = False
        elif tag == 'template':
            self.in_template = False
        elif tag == 'xmp':
            self.in_xmp = False
        elif tag == 'iframe':
            self.in_iframe = False

    def is_safe_context(self) -> bool:
        return any([
            self.in_textarea, self.in_noscript, self.in_style,
            self.in_title, self.in_template, self.in_xmp, self.in_iframe
        ])


def _is_waf_blocked(response: Any, original_res: Any, baseline_text: Optional[str] = None) -> bool:
    target_status = getattr(response, 'status_code', getattr(response, 'status', 200))
    orig_status = getattr(original_res, 'status_code', getattr(original_res, 'status', 200)) if original_res else 200

    if target_status in [403, 406, 429, 501, 503] and orig_status < 400:
        return True

    if target_status == 200 and baseline_text and hasattr(response, 'text'):
        current_text = response.text
        if len(current_text) > 0 and len(baseline_text) > 0:
            length_ratio = len(current_text) / len(baseline_text)
            if length_ratio < 0.1:
                return True
            similarity = difflib.SequenceMatcher(None, current_text[:1000], baseline_text[:1000]).ratio()
            if similarity < 0.5:
                return True

    return False


def _is_safely_escaped(body: str, payload_value: str) -> bool:
    """
    페이로드가 HTML 이스케이프되었는지 확인
    """
    if not payload_value:
        return False

    if payload_value in body:
        return False

    escaped_variants = [
        html.escape(payload_value),
        html.escape(payload_value, quote=True),
        payload_value.replace('<', '&lt;').replace('>', '&gt;'),
        payload_value.replace('<', '&#60;').replace('>', '&#62;'),
        payload_value.replace('<', '&#x3c;').replace('>', '&#x3e;'),
        payload_value.replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;'),
    ]
    for variant in escaped_variants:
        if variant != payload_value and variant in body:
            return True

    return False


def _extract_injected_marker(payload_value: str) -> Optional[str]:
    """페이로드 문자열에서 주입된 고유 마커(xss_xxxxxx)를 추출합니다."""
    # 1. 평문 탐색 (xss_a1b2c3)
    match = re.search(r"xss_[a-f0-9]{6}", payload_value)
    if match: return match.group(0)

    # 2. Base64 디코딩 후 탐색
    b64_matches = re.findall(r"atob\(['\"]([A-Za-z0-9+/=]+)['\"]\)", payload_value)
    for b64 in b64_matches:
        try:
            decoded = base64.b64decode(b64).decode('utf-8', errors='ignore')
            m = re.search(r"xss_[a-f0-9]{6}", decoded)
            if m: return m.group(0)
        except Exception:
            continue

    # 3. String.fromCharCode 디코딩 후 탐색
    char_matches = re.findall(r"fromCharCode\(([\d,\s]+)\)", payload_value)
    for char_str in char_matches:
        try:
            chars = [int(c.strip()) for c in char_str.split(",")]
            decoded = "".join(chr(c) for c in chars)
            m = re.search(r"xss_[a-f0-9]{6}", decoded)
            if m: return m.group(0)
        except Exception:
            continue
    return None


def _check_executable_in_response(body: str, payload_value: str, marker: Optional[str] = None) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "executable": False,
        "evidence": None,
        "pattern_type": None
    }

    if payload_value not in body and (marker and marker not in body):
        return result

    payload_idx = body.find(payload_value)
    if payload_idx == -1 and marker:
        payload_idx = body.find(marker)

    unique_markers = [marker] if marker else _extract_unique_markers(payload_value)

    # 🌟 [개선 1] lxml 파서 우선 사용 및 html.parser 폴백
    try:
        soup = BeautifulSoup(body, 'lxml')
    except Exception:
        soup = BeautifulSoup(body, 'html.parser')

    try:
        for m in unique_markers:
            if not m: continue

            m_lower = m.lower()

            # 🌟 [개선 2] 단순히 속성 값이 아닌, "실행 가능한 속성"인지 엄격하게 검증
            def is_executable_attr_injection(tag):
                for attr_name, attr_val in tag.attrs.items():
                    attr_val_str = str(attr_val).lower()

                    if m_lower in attr_val_str:
                        if attr_name.lower().startswith('on'):
                            return True
                        if attr_name.lower() in ['href', 'src', 'action', 'formaction', 'data']:
                            if 'javascript:' in attr_val_str:
                                return True
                return False

            suspect_tags = soup.find_all(is_executable_attr_injection)
            if suspect_tags:
                result["executable"] = True
                result["evidence"] = str(suspect_tags[0])[:200]
                result["pattern_type"] = "bs4_dom_attribute_injection (Event/URI Protocol)"
                return result

            script_tags = soup.find_all('script', string=re.compile(m, re.I))
            if script_tags:
                result["executable"] = True
                result["evidence"] = str(script_tags[0])[:200]
                result["pattern_type"] = "bs4_dom_script_injection"
                return result
    except Exception:
        pass

    if soup.find() is not None:
        return result

    for pattern in _EXECUTABLE_XSS_PATTERNS:
        matches = pattern.finditer(body)
        for match in matches:
            matched_str = match.group(0)
            is_related = False

            if payload_value in matched_str:
                is_related = True

            for m in unique_markers:
                if m and m.lower() in matched_str.lower():
                    is_related = True
                    break

            match_start = match.start()
            match_end = match.end()
            payload_end = payload_idx + len(payload_value)

            if (match_start <= payload_idx <= match_end) or (match_start <= payload_end <= match_end):
                is_related = True

            if is_related:
                result["executable"] = True
                result["evidence"] = matched_str[:200]
                result["pattern_type"] = pattern.pattern[:50]
                return result

    return result


def _extract_unique_markers(payload: str) -> List[str]:
    """페이로드에서 고유 식별 가능한 문자열 추출"""
    markers = []

    string_matches = re.findall(r'["\']([^"\']{2,30})["\']', payload)
    markers.extend(string_matches)

    func_matches = re.findall(r'(alert|prompt|confirm|eval)\s*\(', payload, re.I)
    markers.extend(func_matches)

    event_matches = re.findall(r'(on\w+)\s*=', payload, re.I)
    markers.extend(event_matches)

    return list(set(m for m in markers if m and len(m) >= 2))


def _analyze_context_robust(body: str, payload_value: str, marker: Optional[str] = None) -> Dict[str, Any]:
    """
    페이로드가 위치한 정확한 컨텍스트를 파악합니다. (오탐 방지 개선 로직 적용)
    """
    payload_idx = body.find(payload_value)

    if payload_idx == -1:
        if marker and marker in body:
            payload_idx = body.find(marker)
        else:
            return {"executable": False, "location": "not_reflected"}

    try:
        soup = BeautifulSoup(body, 'lxml')
        texts = soup.find_all(string=True)
        for text_node in texts:
            if payload_value in text_node or (marker and marker in text_node):
                parent_tag = text_node.parent.name if text_node.parent else ""
                if parent_tag not in ['script', 'style', 'iframe']:
                    return {"executable": False, "location": "safe_text_node"}
    except Exception:
        pass

    html_before_payload = body[:payload_idx]
    recent_html = html_before_payload[-500:] if len(html_before_payload) > 500 else html_before_payload

    last_open_tag = recent_html.rfind('<')
    last_close_tag = recent_html.rfind('>')

    if last_open_tag != -1 and last_open_tag > last_close_tag:
        tag_content = recent_html[last_open_tag:]
        single_quotes = tag_content.count("'")
        double_quotes = tag_content.count('"')

        last_single = tag_content.rfind("'")
        last_double = tag_content.rfind('"')

        in_single_quote = single_quotes % 2 != 0 and last_single > last_double
        in_double_quote = double_quotes % 2 != 0 and last_double > last_single

        if in_single_quote or in_double_quote:
            quote_char = "'" if in_single_quote else '"'

            is_js_attr = re.search(r"\b(on\w+|href|src|action|formaction)\s*=\s*['\"]$", tag_content, re.I)
            if is_js_attr:
                return {"executable": True, "location": "js_attribute_value"}

            if quote_char in payload_value or '>' in payload_value:
                return {"executable": True, "location": "attribute_breakout"}
            else:
                exec_check = _check_executable_in_response(body, payload_value, marker)
                if exec_check["executable"]:
                    return {
                        "executable": True,
                        "location": "html_body_executable (recovered from attribute trap)",
                        "evidence": exec_check["evidence"]
                    }
                return {"executable": False, "location": "attribute_trapped"}

    parser = XSSContextParser()
    try:
        parser.feed(html_before_payload[-2000:])
    except Exception:
        pass

    if parser.is_safe_context():
        return {"executable": False, "location": "safe_tag"}

    if parser.in_script:
        script_start_idx = html_before_payload.rfind('<script')
        if script_start_idx != -1:
            js_content = body[script_start_idx:payload_idx]
            clean_js = _JS_COMMENT_SAFE_PATTERN.sub('', js_content)

            single_quotes = clean_js.count("'") - clean_js.count("\\'")
            double_quotes = clean_js.count('"') - clean_js.count('\\"')
            backticks = clean_js.count('`') - clean_js.count('\\`')

            in_string = (single_quotes % 2 != 0) or (double_quotes % 2 != 0) or (backticks % 2 != 0)

            if in_string:
                if any(c in payload_value for c in ["'", '"', '`', '</script', '\\n', '\\r']):
                    return {"executable": True, "location": "script_string_breakout"}
                else:
                    return {"executable": False, "location": "script_string_trapped"}
            else:
                return {"executable": True, "location": "script_code_area"}

    exec_check = _check_executable_in_response(body, payload_value, marker)
    if exec_check["executable"]:
        return {
            "executable": True,
            "location": "html_body_executable",
            "evidence": exec_check["evidence"]
        }

    return {"executable": False, "location": "html_body_filtered"}


def _check_partial_escape(body: str, payload_value: str, marker: Optional[str] = None) -> bool:
    """위험한 패턴이 부분적으로 이스케이프를 우회했는지 확인"""
    for pattern in _DANGEROUS_PATTERNS:
        matches = pattern.findall(payload_value)
        for match in matches:
            if match in body:
                escaped = html.escape(match)
                if escaped != match and escaped not in body:
                    context_state = _analyze_context_robust(body, match, marker)
                    if context_state["executable"]:
                        return True
    return False


def _check_obfuscated_reflection(body: str, payload_value: str, baseline: Optional[str] = None) -> bool:
    """난독화되거나 변형된 페이로드가 실행 가능하게 반사되었는지 확인"""
    body_lower = body.lower()
    baseline_lower = baseline.lower() if baseline else ""

    for pattern, pattern_type in _OBFUSCATION_PATTERNS:
        current_matches = pattern.findall(body_lower)
        if not current_matches:
            continue

        baseline_matches = pattern.findall(baseline_lower) if baseline else []

        if len(current_matches) > len(baseline_matches):
            payload_markers = _extract_unique_markers(payload_value)
            for match in current_matches:
                match_str = match if isinstance(match, str) else str(match)
                for marker in payload_markers:
                    if marker.lower() in match_str.lower():
                        return True

    fragments = _extract_payload_fragments(payload_value)
    for fragment in fragments:
        fragment_lower = fragment.lower()

        current_count = body_lower.count(fragment_lower)
        baseline_count = baseline_lower.count(fragment_lower) if baseline else 0

        if current_count > baseline_count:
            for match in re.finditer(re.escape(fragment_lower), body_lower):
                fragment_idx = match.start()
                start = max(0, fragment_idx - 50)
                end = min(len(body_lower), fragment_idx + len(fragment) + 50)
                surrounding = body_lower[start:end]

                if re.search(
                        r'<script[^>]*>|on\w+\s*=\s*["\']|(?:href|src|action|formaction)\s*=\s*["\']?\s*javascript:',
                        surrounding, re.I):
                    return True

    return False


def _extract_payload_fragments(payload: str) -> List[str]:
    """페이로드에서 위험한 함수 호출 패턴 추출"""
    fragments = []
    for pattern in _FUNC_PATTERNS:
        fragments.extend(pattern.findall(payload))
    fragments.extend(_ATOB_PATTERN.findall(payload))
    return list(set(f for f in fragments if len(f) >= 4))


def analyze_stored_xss(
        response: Any,
        payload: Payload,
        elapsed_time: float,
        original_res: Any = None,
        requester: Any = None,
        baseline: Optional[str] = None,
) -> Dict[str, Any]:
    """
    [범용] Stored XSS 취약점 분석
    """
    _ = requester

    result = {
        "is_vulnerable": False,
        "context": "unknown",
        "evidence": "",
        "waf_blocked": False,
        "needs_manual_dom_review": False,
        "elapsed_time": elapsed_time
    }

    if not response or not hasattr(response, 'text') or not response.text:
        result["context"] = "no_response"
        return result

    response_body = response.text[:MAX_RESPONSE_LENGTH]
    payload_value = (payload.value or "")[:MAX_PAYLOAD_LENGTH] if payload.value else ""

    if not payload_value:
        result["context"] = "empty_payload"
        return result

    marker = _extract_injected_marker(payload_value)

    if _is_waf_blocked(response, original_res, baseline):
        result["waf_blocked"] = True
        result["context"] = "waf_blocked"
        return result

    if _DOM_SINK_PATTERN.search(response_body):
        result["needs_manual_dom_review"] = True

    if _is_safely_escaped(response_body, payload_value):
        result["context"] = "safely_escaped"
        result["evidence"] = "Payload was HTML-escaped"
        return result

    if payload_value in response_body or (marker and marker in response_body):
        context_state = _analyze_context_robust(response_body, payload_value, marker)

        result["context"] = context_state["location"]

        if context_state["executable"]:
            result["is_vulnerable"] = True
            result["evidence"] = f"Payload reflected in executable context: {context_state['location']}"
            if "evidence" in context_state:
                result["evidence"] += f" | {context_state['evidence'][:100]}"
            return result
        else:
            result["evidence"] = f"Payload reflected but not executable ({context_state['location']})"
            return result

    if _check_partial_escape(response_body, payload_value, marker):
        result["is_vulnerable"] = True
        result["context"] = "partial_escape_bypass"
        result["evidence"] = "Dangerous handlers bypassed escaping"
        return result

    baseline_body = baseline[:MAX_RESPONSE_LENGTH] if baseline else None
    if _check_obfuscated_reflection(response_body, payload_value, baseline_body):
        result["is_vulnerable"] = True
        result["context"] = "obfuscated_reflection"
        result["evidence"] = "Payload fragments reflected in executable context"
        return result

    result["context"] = "filtered_or_not_reflected"
    result["evidence"] = "Payload not found in response"

    if result["needs_manual_dom_review"] and not result["is_vulnerable"]:
        result["evidence"] = "Payload filtered, but DOM sinks detected. Manual review recommended."

    return result