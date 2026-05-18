from __future__ import annotations

import random
import urllib.parse
import dataclasses
from urllib.parse import urlparse, parse_qs
import logging
from typing import List, Any
import asyncio
import atexit
from concurrent.futures import ProcessPoolExecutor

from modules.base_module import BaseModule
from modules.reflected_xss.payloads import get_xss_payloads
from modules.reflected_xss.analyzer import detect_reflected_xss, Confidence
from core.models import Payload

logger = logging.getLogger(__name__)

_executor = None


def _get_executor():
    global _executor
    if _executor is None:
        _executor = ProcessPoolExecutor(max_workers=4)
        atexit.register(_executor.shutdown, wait=False)
    return _executor


class ReflectedXSSModule(BaseModule):
    """Reflected XSS 취약점 탐지 모듈"""

    def __init__(self, **kwargs):
        super().__init__("rxss")
        self.max_response_size: int = kwargs.get('max_response_size', 5 * 1024 * 1024)

        # evasion_level 범위 클램핑 (0~3 외 값 방어)
        raw_level = kwargs.get('evasion_level', 0)
        self.evasion_level: int = max(0, min(3, int(raw_level)))

        # 페이로드 폭발 제어: None이면 전체 사용, 정수면 무작위 샘플링
        self.max_payloads: int | None = kwargs.get('max_payloads', None)

        self.reported_findings = set()

        # 초기화 시점에 샘플링된 페이로드를 한 번만 생성하여 고정
        # → get_payloads() / get_payload_count() 중복 샘플링으로 인한
        #   페이로드 셋 불일치 버그 방지
        self._cached_payloads: List[Payload] = self._get_sampled_payloads()

    def _get_sampled_payloads(self) -> List[Payload]:
        """페이로드 로드 후 max_payloads 기준으로 샘플링 (1회만 호출됨)"""
        all_payloads = list(get_xss_payloads(evasion_level=self.evasion_level))

        if self.max_payloads is None or len(all_payloads) <= self.max_payloads:
            return all_payloads

        # HIGH 리스크 우선 보존 후 나머지 무작위 샘플링
        high = [p for p in all_payloads if getattr(p, 'risk_level', '') == 'HIGH']
        others = [p for p in all_payloads if getattr(p, 'risk_level', '') != 'HIGH']

        if len(high) >= self.max_payloads:
            sampled = random.sample(high, self.max_payloads)
        else:
            remaining = self.max_payloads - len(high)
            sampled = high + random.sample(others, min(remaining, len(others)))

        # 로그 메시지에 max_payloads 값 포함
        logger.info(
            f"[XSS] 페이로드 샘플링: {len(all_payloads)} → {len(sampled)}개 "
            f"(max_payloads={self.max_payloads})"
        )
        return sampled

    def get_payloads(self) -> List[Payload]:
        """캐싱된 페이로드 리스트 반환"""
        return self._cached_payloads

    def get_payload_count(self) -> int:
        """캐싱된 페이로드 수 반환"""
        return len(self._cached_payloads)

    async def analyze(
            self,
            response: Any,
            payload: Any,
            elapsed_time: float,
            original_res: Any = None,
            requester: Any = None,
    ):
        """XSS 취약점 분석"""
        # 실패 시 엔진 규격에 맞게 반환할 기본 튜플 (False, 증거없음, 원본페이로드)
        FAIL = (False, [], payload)

        try:
            # 1. Content-Type 필터
            content_type = str(getattr(response, 'content_type', '') or
                               getattr(response, 'headers', {}).get('content-type', '')).lower()
            allowed_types = ('text/html', 'application/xhtml', 'text/javascript', 
                             'application/javascript', 'text/plain')

            if content_type and not any(ct in content_type for ct in allowed_types):
                return FAIL

            # 2. URL 및 파라미터 추출
            req_url = ""
            if requester and hasattr(requester, 'url'):
                req_url = str(requester.url)
            else:
                req_url = str(getattr(response, 'url', ''))

            target_parameter = self._extract_parameter(requester, response)
            if target_parameter == "unknown" and req_url:
                target_parameter = self._smart_recover_parameter(req_url, payload)

            # 3. 텍스트 추출 및 길이 제한
            res_text = getattr(response, 'text', None)
            if not res_text:
                return FAIL

            if len(res_text) > self.max_response_size:
                res_text = res_text[:self.max_response_size]

            orig_text = ""
            if original_res:
                orig_text = getattr(original_res, 'text', "") or ""
                if len(orig_text) > self.max_response_size:
                    orig_text = orig_text[:self.max_response_size]

            payload_value = getattr(payload, 'value', str(payload))

            # ========================================================
            # 분석 (ProcessPoolExecutor 적용 부분)
            # ========================================================
            loop = asyncio.get_running_loop()
            result = await loop.run_in_executor(
                _get_executor(),
                detect_reflected_xss,
                res_text,
                orig_text,
                payload_value
            )

            # 실패 시 엔진에 반환할 기본 튜플 (엔진 호환용)
            FAIL = (False, [], payload)

            # ========================================================
            # 중복 제거 (Dedup) 및 리포트 기록 부분
            # ========================================================
            if result.is_vulnerable and result.confidence != Confidence.NONE:
                status_code = getattr(response, 'status', getattr(response, 'status_code', 200))
                
                # 상태 코드 노이즈 튜닝 (미탐 방지 + 강등)
                if status_code != 200:
                    if status_code in (403, 406):
                        result.confidence = Confidence.LOW
                        result.evidence = f"[WAF Block] {result.evidence}"
                    elif status_code in (400, 404):
                        if result.confidence == Confidence.HIGH:
                            result.confidence = Confidence.MEDIUM
                        result.evidence = f"[{status_code} Error] {result.evidence}"
                    elif status_code >= 500:
                        if result.confidence == Confidence.HIGH:
                            result.confidence = Confidence.MEDIUM
                        result.evidence = f"[500 Error Downgraded] {result.evidence}"

                    # LOW 등급(찌꺼기)은 보고서 오염을 막기 위해 여기서 버림
                    if result.confidence == Confidence.LOW:
                        return FAIL

                attack_type = getattr(payload, 'attack_type', '')
                parts = attack_type.split(':')
                
                # 카테고리를 대분류까지만 자름 (예: reflected_xss:event_handler)
                if len(parts) >= 2:
                    category = f"{parts[0]}:{parts[1]}"
                else:
                    category = attack_type

                raw_url = str(getattr(response, 'url', ''))
                parsed = urlparse(raw_url)
                base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

                dedup_key = (base_url, target_parameter, category)

                if dedup_key not in self.reported_findings:
                    self.reported_findings.add(dedup_key)
                    self._attach_metadata(payload, result, target_parameter, response)
                    
                    final_risk = result.confidence.name
                    if final_risk != payload.risk_level:
                        payload = dataclasses.replace(payload, risk_level=final_risk)

                    # 엔진 규격에 맞게 상세 증거(evidences) 리스트 작성
                    evidences = [
                        f"Confidence: {result.confidence.name}",
                        f"Context: {result.context.name}",
                        f"Evidence: {result.evidence}",
                        f"Category: {category}",
                        f"Status: {status_code}"
                    ]
                    
                    # 엔진에 (True, 증거, 덮어씌운 페이로드) 튜플 반환!
                    return (True, evidences, payload)
                else:
                    return FAIL  # 중복 공격 무시

            return FAIL

        except Exception as e:
            logger.error(f"[XSS] 분석 중 오류: {e}", exc_info=True)
            return (False, [], payload)  # 에러 발생 시에도 엔진 호환 규격으로 반환

    def _smart_recover_parameter(self, url: str, payload: Any) -> str:
        """URL에서 페이로드가 주입된 파라미터 역추적"""
        try:
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query, keep_blank_values=True)

            if not query_params:
                return "unknown"

            raw_payload = payload if isinstance(payload, str) else getattr(payload, 'value', str(payload))
            clean_payload = urllib.parse.unquote(str(raw_payload))

            for key, values in query_params.items():
                for val in values:
                    clean_val = urllib.parse.unquote(str(val))

                    if clean_payload == clean_val:
                        logger.info(f"🎯 [스마트복구] 파라미터 '{key}' 발견 (정확 일치)")
                        return key

                    if len(clean_payload) > 3 and clean_payload in clean_val:
                        logger.info(f"🎯 [스마트복구] 파라미터 '{key}' 발견 (부분 일치)")
                        return key

            first_param = list(query_params.keys())[0]
            logger.warning(f"⚠️ 파라미터 특정 불가, '{first_param}' 사용")
            return first_param

        except Exception as e:
            logger.debug(f"스마트 복구 실패: {e}")
            return "unknown"

    def _extract_parameter(self, requester: Any, response: Any) -> str:
        """Parameter 추출"""
        if requester is not None:
            if hasattr(requester, 'current_param') and requester.current_param:
                return str(requester.current_param)
            if hasattr(requester, 'parameter') and requester.parameter:
                return str(requester.parameter)
            if hasattr(requester, 'meta'):
                meta = requester.meta
                if isinstance(meta, dict):
                    param = meta.get('parameter') or meta.get('param')
                    if param:
                        return str(param)
                else:
                    param = getattr(meta, 'parameter', None) or getattr(meta, 'param', None)
                    if param:
                        return str(param)
        return "unknown"

    def _attach_metadata(self, payload: Any, result, parameter: str, response: Any) -> None:
        """결과 메타데이터 첨부"""
        pass