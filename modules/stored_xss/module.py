from typing import List, Optional, Any, Dict
import threading
import logging
import re
import uuid
import time
from enum import Enum
from dataclasses import dataclass, asdict
import aiohttp
import copy
import asyncio

from modules.base_module import BaseModule
from core.models import Payload
from modules.stored_xss.payloads import build_stored_xss_payloads, PayloadCategory, reload_payloads
from modules.stored_xss.analyzer import analyze_stored_xss, _extract_injected_marker, _analyze_context_robust
from fuzzer.request_builder import build_and_send_request

logger = logging.getLogger(__name__)


class ScanMode(Enum):
    QUICK = "quick"
    FULL = "full"
    STEALTH = "stealth"


@dataclass
class ScanStats:
    total_payloads: int = 0
    tested: int = 0
    vulnerable: int = 0
    waf_blocked: int = 0
    dom_potential: int = 0


class StoredXSSModule(BaseModule):
    def __init__(
            self,
            target_params: list = None,
            bypass_level: int = 1,
            scan_mode: str = "full",
            max_risk_level: str = "Critical",
            categories: list = None
    ):
        super().__init__(name="stored_xss")
        self.description = "Advanced Stored XSS Scanner (Micro-Batch Verification)"
        self.version = "4.0.0"

        self.target_params = target_params or []
        self.bypass_level = bypass_level
        self.scan_mode = ScanMode(scan_mode)
        self.max_risk_level = max_risk_level
        self.categories = categories or []
        self.config = {
            "target_params": self.target_params,
            "bypass_level": self.bypass_level,
            "scan_mode": self.scan_mode.value,
            "max_risk_level": self.max_risk_level,
            "categories": self.categories
        }
        self._baseline_response: Optional[str] = None
        self.stats = ScanStats()
        self._last_analysis_result: Optional[Dict[str, Any]] = None
        self._stats_lock = threading.Lock()  # 동기 함수용
        self._async_stats_lock = asyncio.Lock()  # 비동기 함수(verify)용

        #  묶음 검증(배치)을 위한 캐시 및 Lock 변수
        self._target_locks: Dict[str, asyncio.Lock] = {}
        self._html_cache: Dict[str, Dict[str, Any]] = {}
        self._logged_progress_blocks: set = set()

    def reset_stats(self) -> None:
        with self._stats_lock:
            self.stats = ScanStats()
            self._last_analysis_result = None
            self._logged_progress_blocks.clear()
            self._html_cache.clear()

    def set_baseline(self, response: Any) -> None:
        if response and hasattr(response, 'text') and response.text:
            self._baseline_response = response.text

    def reload_database(self) -> None:
        reload_payloads()

    def get_target_parameters(self, surface, parameters: List[str]) -> List[str]:
        destructive_keys = {"btnclear", "clear", "reset", "delete", "destroy", "remove"}

        if hasattr(surface, 'parameters') and isinstance(surface.parameters, dict):
            keys_to_remove = [k for k in surface.parameters.keys() if str(k).lower() in destructive_keys]
            for k in keys_to_remove:
                del surface.parameters[k]

            for key, value in surface.parameters.items():
                if value == "" or value is None:
                    key_lower = str(key).lower()
                    skip_dummy = {"submit", "action", "login", "logout", "cancel", "update", "btnsign", "button"}
                    number_hints = {"price", "id", "amount", "qty", "count", "num", "book_id"}

                    if key_lower in skip_dummy:
                        surface.parameters[key] = "Submit"
                    elif any(hint in key_lower for hint in number_hints):
                        surface.parameters[key] = "1"  # 숫자 타입 검증 회피 (400 에러 방지)
                    else:
                        surface.parameters[key] = "test"

        valid_targets = []

        skip_keys = {
            "submit", "action", "login", "logout", "cancel", "update", "btnsign", "search", "page",
            "lang", "theme", "csrf_token", "user_token", "_token", "authenticity_token"
        }.union(destructive_keys)

        if self.target_params:
            for p in parameters:
                if p in self.target_params and str(p).lower() not in skip_keys:
                    valid_targets.append(p)
            return valid_targets

        for p in parameters:
            if str(p).lower() not in skip_keys:
                valid_targets.append(p)

        return valid_targets

    def get_payloads(self) -> List[Payload]:
        try:
            categories = [PayloadCategory.BASIC,
                          PayloadCategory.EVENT_HANDLER] if self.scan_mode == ScanMode.QUICK else None
            if not categories:
                raw_cats = self.categories
                categories = [PayloadCategory(c) for c in raw_cats] if raw_cats else None

            payloads = build_stored_xss_payloads(
                categories=categories,
                max_risk_level=self.max_risk_level,
                mutation_level=self.bypass_level
            )
            with self._stats_lock:
                self.stats.total_payloads = len(payloads)
            return payloads
        except ValueError as e:
            logger.error(f"[{self.name}] 잘못된 카테고리 설정: {e}")
            return []

    def get_payload_count(self) -> int:
        from modules.stored_xss.payloads import get_payload_count as get_db_count
        counts = get_db_count()
        if self.scan_mode == ScanMode.QUICK:
            return counts.get("basic", 0) + counts.get("event_handler", 0)
        raw_cats = self.categories
        if raw_cats:
            return sum(counts.get(c, 0) for c in raw_cats)
        return sum(counts.values())

    def analyze(
            self, response: Any, payload: Payload, elapsed_time: float, original_res: Any = None, requester: Any = None
    ) -> bool:
        with self._stats_lock:
            self.stats.tested += 1
        try:
            baseline_text = self._baseline_response
            if not baseline_text and original_res and hasattr(original_res, 'text'):
                baseline_text = original_res.text

            result = analyze_stored_xss(
                response, payload, elapsed_time, original_res, requester, baseline_text
            )
            self._last_analysis_result = result
            is_hit = bool(result.get("is_vulnerable", False))

            with self._stats_lock:
                if is_hit:
                    if result.get("waf_blocked"):
                        self.stats.waf_blocked += 1
                    if result.get("needs_manual_dom_review"):
                        self.stats.dom_potential += 1
            return is_hit
        except Exception as e:
            logger.exception(f"[{self.name}] 분석 중 오류 발생: {e}")
            self._last_analysis_result = {
                "is_vulnerable": False,
                "context": "error",
                "evidence": f"Analysis failed: {str(e)}",
            }
            return False

    async def verify(self, session: aiohttp.ClientSession, surface: Any, parameter: str, payload: Payload,
                     response: Any, baseline_response: Any) -> bool:
        """
        [보완된 verify 로직]
        1. 새 글 상세 페이지 직접 파싱 접근 로직 추가
        2. HTML 캐시 제거로 항상 최신 응답 확인
        """
        try:
            payload_value = payload.value or ""
            original_marker = _extract_injected_marker(payload_value)
            if not original_marker:
                return False

            safe_surface = copy.deepcopy(surface)
            safe_param_name = re.sub(r'[^a-zA-Z0-9_]', '', parameter)
            verify_id = uuid.uuid4().hex[:6]
            verify_marker = f"vfy_{safe_param_name}_{verify_id}"
            verify_payload_value = payload_value.replace(original_marker, verify_marker)

            class MockPayload:
                def __init__(self, val):
                    self.value = val

            target_url = str(response.url) if hasattr(response, 'url') else getattr(surface, 'url', '')
            base_url = target_url

            # 1. 고유 마커 2차 주입 (POST)
            injection_res = await build_and_send_request(
                session, safe_surface, parameter, MockPayload(verify_payload_value)
            )

            status_code = getattr(injection_res, 'status', 500) if injection_res else 500

            if status_code >= 400:
                logger.warning(
                    f"[{self.name}] 2차 주입 시 응답 에러 (Status: {status_code}) - 파라미터: {parameter}. ")

            # =========================================================================
            #  동적 URL 수집 로직 (상세 페이지 파싱 추가)
            # =========================================================================
            candidate_urls = []

            # (1) 자동 리다이렉트된 최종 URL 수집
            final_url = str(getattr(injection_res, 'url', ''))
            if final_url and final_url not in candidate_urls:
                candidate_urls.append(final_url)

            # (2) 응답 HTML 내부에서 "가장 최근에 작성된 것으로 보이는 게시물 링크" 추출 시도
            # (게시판 목록 등으로 리다이렉트 되었을 경우 대비)
            injection_body = getattr(injection_res, 'text', '')
            if injection_body and '/board' in final_url:
                try:
                    from bs4 import BeautifulSoup
                    try:
                        soup = BeautifulSoup(injection_body, 'lxml')
                    except Exception:
                        soup = BeautifulSoup(injection_body, 'html.parser')

                    # <a> 태그 중 상세조회용 URL 패턴을 포함하는 링크 추출
                    links = soup.find_all('a', href=lambda href: href and '/board/view?id=' in href)

                    if links:
                        from urllib.parse import urljoin
                        for link in links[:5]:  # 상위 5개의 최신 게시물 탐색
                            full_url = urljoin(base_url, link['href'])
                            if full_url not in candidate_urls:
                                candidate_urls.append(full_url)
                except Exception as e:
                    logger.debug(f"응답 본문에서 링크 추출 실패: {e}")

            # (3) 폼을 제출했던 원래 URL 추가
            surface_url = getattr(surface, 'url', base_url)
            if surface_url not in candidate_urls:
                candidate_urls.append(surface_url)

            # (4) Referer 헤더 출처 추가
            req_headers = getattr(surface, 'headers', {}) or {}
            referer = req_headers.get('Referer') or req_headers.get('referer')
            if referer and referer not in candidate_urls:
                candidate_urls.append(referer)

            if base_url not in candidate_urls:
                candidate_urls.append(base_url)
            # =========================================================================

            # DB 반영을 위한 공통 대기시간 (2.5초) -> URL 전체 탐색 전 한 번만 대기
            await asyncio.sleep(2.5)

            is_vulnerable = False
            verified_location = ""
            hit_url = ""

            # 여러 후보 URL을 순회하며 마커가 반사된 곳을 끈질기게 추적
            for check_url in candidate_urls:
                if check_url not in self._target_locks:
                    self._target_locks[check_url] = asyncio.Lock()

                verify_body = ""
                async with self._target_locks[check_url]:
                    # 무조건 최신 데이터를 요청하여 검증 신뢰도 상승
                    try:
                        req_cookies = getattr(surface, 'cookies', None)
                        async with session.get(check_url, headers=req_headers, cookies=req_cookies,
                                               timeout=15) as verify_res:
                            verify_body = await verify_res.text()
                    except Exception as get_err:
                        logger.debug(f"[{self.name}] 검증 GET 요청 실패 ({check_url}): {repr(get_err)}")
                        continue

                # 다중 출력 지점 전수 검사 (하나라도 성공할 때까지 분석)
                if verify_marker in verify_body:
                    marker_indices = [m.start() for m in re.finditer(re.escape(verify_marker), verify_body)]

                    for idx in marker_indices:
                        slice_start = max(0, idx - 2000)
                        slice_end = min(len(verify_body), idx + 2000)
                        body_slice = verify_body[slice_start:slice_end]

                        context_state = _analyze_context_robust(body_slice, verify_marker, verify_marker)

                        # 하나라도 실행 가능한 컨텍스트를 찾으면 즉시 취약점 확정
                        if context_state.get("executable"):
                            is_vulnerable = True
                            verified_location = context_state.get('location', 'unknown_location')
                            hit_url = check_url
                            break

                if is_vulnerable:
                    break  # 취약점을 찾았으면 불필요한 다음 URL 검사 중지

            # 로깅 및 결과 반환
            if is_vulnerable:
                current_tested = self.stats.tested
                progress_block = current_tested // 10

                if progress_block not in self._logged_progress_blocks:
                    logger.warning(
                        f"[ST_XSS CONFIRMED] Param: {parameter} | Marker: {verify_marker} | Found at: {hit_url}"
                    )
                    self._logged_progress_blocks.add(progress_block)
                else:
                    logger.debug(
                        f"[ST_XSS MORE HITS] Param: {parameter} | Marker: {verify_marker}"
                    )

                if self._last_analysis_result:
                    self._last_analysis_result["context"] = f"Verified Stored | {verified_location}"
                    self._last_analysis_result[
                        "evidence"] = f"Re-injection success with marker: {verify_marker} at {hit_url}"

                await self._async_record_verified_stats()

            return is_vulnerable

        except Exception as e:
            logger.error(f"[{self.name}] 검증 중 에러 발생: {repr(e)}")
            return False

    def _record_verified_stats(self):
        with self._stats_lock:
            self.stats.vulnerable += 1

    async def _async_record_verified_stats(self):
        async with self._async_stats_lock:
            self.stats.vulnerable += 1

    def get_last_analysis_result(self) -> Optional[Dict[str, Any]]:
        return self._last_analysis_result

    def get_module_info(self) -> dict:
        with self._stats_lock:
            stats_copy = asdict(self.stats)
        return {
            "name": self.name,
            "version": self.version,
            "mode": self.scan_mode.value,
            "stats": stats_copy,
            "config": self.config
        }