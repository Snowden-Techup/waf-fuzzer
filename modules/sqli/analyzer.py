import re
import html
import asyncio
from urllib.parse import unquote
from difflib import SequenceMatcher

# 블라인드 인젝션 시 에러 상태 분류를 위한 범용 키워드
GENERIC_DB_ERROR_KEYWORDS = re.compile(
    r'(error|syntax|mysql|mariadb|oracle|postgres|sql server|xpath|exception|unclosed|statement)', 
    re.I
)

def _get_pure_text(html_content: str) -> str:
    if not html_content:
        return ""
    text = re.sub(r'<(script|style).*?>.*?</\1>', '', html_content, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r'<[^>]+?>', ' ', text)
    text = html.unescape(text)
    text = re.sub(r'\s+', ' ', text).strip()
    return text

def get_text_ratio(text1: str, text2: str) -> float:
    pure1 = _get_pure_text(text1)
    pure2 = _get_pure_text(text2)
    if not pure1 and not pure2: return 1.0
    if not pure1 or not pure2: return 0.0
    return SequenceMatcher(None, pure1, pure2).ratio()

# 반사 제거 함수
def _remove_direct_reflection(text: str, payload_value: str) -> str:
    scrubbed = text
    payload_variants = [
        payload_value,
        unquote(payload_value),
        unquote(unquote(payload_value)),
        html.escape(payload_value),
        html.unescape(payload_value)
    ]
    for variant in filter(None, set(payload_variants)):
        scrubbed = scrubbed.replace(variant, "[DIRECT_REFLECTION_REMOVED]")
    return scrubbed

def detect_sqli(response, payload, elapsed_time, exploit_signatures, syntax_signatures, mismatch_signatures, original_res=None):
    evidences = []
    res_text = response.text
    
    orig_elapsed = getattr(original_res, "elapsed_time", getattr(getattr(original_res, "elapsed", object()), "total_seconds", lambda: 0.0)()) if original_res else 0.0

    attack_type = payload.attack_type.lower()
    payload_value = payload.value
    marker_start = "SVSDAAAA"
    marker_stop = "VASDAAAA"
    dynamic_marker_pattern = re.compile(f"{marker_start}(.*?){marker_stop}", re.I | re.DOTALL)

    has_syntax_error = False
    has_execution_error = False

    is_time_related = "time" in attack_type or "stacked" in attack_type
    
    # [1] 시간 페이로드 타임아웃 탐지
    if is_time_related:
        if response is None and elapsed_time >= 4.5:
            evidences.append(f"[Time] Request Timed Out: {elapsed_time:.2f}s")
            return True, evidences, False
        elif elapsed_time >= (4.5 + orig_elapsed):
            evidences.append(f"[Time] Response delayed: {elapsed_time:.2f}s")
            return True, evidences, False

    # [2] 문법 오류 식별
    scrubbed_text = res_text
    for pattern in syntax_signatures:
        if re.search(pattern, scrubbed_text, re.I | re.DOTALL):
            has_syntax_error = True
            scrubbed_text = re.sub(pattern, "[FULL_SYNTAX_ERROR_REMOVED]", scrubbed_text, flags=re.I | re.DOTALL)
            break 

    # [3] 직접 반사 제거 적용
    scrubbed_text = _remove_direct_reflection(scrubbed_text, payload_value)

    # [4] 에러 기반 탐지
    for pattern in exploit_signatures:
        if re.search(pattern, scrubbed_text, re.I | re.DOTALL):
            marker_match = dynamic_marker_pattern.search(res_text)
            if marker_match:
                extracted_data = marker_match.group(1)
                evidences.append(f"[Error] SQL Execution Error (Marker Found: '{extracted_data}')")
            else:
                evidences.append(f"[PotentialError] SQL Execution Error (No Marker): {pattern}")
            
            has_execution_error = True
            break

    # [5] 미스매치 탐지
    if not has_execution_error:
        for pattern in mismatch_signatures:
            if re.search(pattern, scrubbed_text, re.I | re.DOTALL):
                evidences.append(f"[PotentialMismatch] DBMS Mismatch Error")
                has_execution_error = True 
                break

    # [6] 마커 단독 검증
    if not has_execution_error:
        if dynamic_marker_pattern.search(scrubbed_text):
            if has_syntax_error:
                evidences.append(f"[Error] SQLi execution marker confirmed in DB output context")
                has_execution_error = True
            else:
                evidences.append(f"[Potential] Marker reflected (requires Boolean verification)")

    return len(evidences) > 0, evidences, has_syntax_error


async def verify_sqli_logic(response, payload, original_res, requester, is_vuln_1st, evidences, has_syntax_error, syntax_signatures=None):
    if not requester:
        return is_vuln_1st, evidences

    val = payload.value
    res_text = response.text
    
    # 1. 확정 증거
    if is_vuln_1st and any(tag in str(evidences) for tag in ["[Error]", "[Time]"]):
        return True, evidences

    # 2. 페이로드 논리 분석
    logic_pattern = r"(['\"]?\w+['\"]?)\s*=\s*\1|true|exists"
    has_logic = re.search(logic_pattern, val, re.I) or "1=1" in val
    
    # 3. 논리 구조가 있으면 T!=F 대조 시도
    if has_logic or is_vuln_1st:
        
        true_logic = ""
        false_logic = ""
        
        if "1=1" in val:
            true_logic = "1=1"
            false_logic = "1=2"
            false_payload = val.replace(true_logic, false_logic)
        else:
            match = re.search(logic_pattern, val, re.I)
            if match:
                true_logic = match.group(0)
                false_logic = "1=2"
                false_payload = val.replace(true_logic, false_logic)
            else:
                true_logic = ""
                false_logic = "AND 1=2"
                false_payload = val + " AND 1=2"
            
        try:
            false_res = await requester(false_payload)
            
            scrubbed_true = _remove_direct_reflection(res_text, val)
            scrubbed_false = _remove_direct_reflection(false_res.text, false_payload)
            
            if true_logic and false_logic:
                for t_var in filter(None, set([true_logic, unquote(true_logic), html.escape(true_logic)])):
                    scrubbed_true = scrubbed_true.replace(t_var, "[LOGIC_NORMALIZED]")
                for f_var in filter(None, set([false_logic, unquote(false_logic), html.escape(false_logic)])):
                    scrubbed_false = scrubbed_false.replace(f_var, "[LOGIC_NORMALIZED]")
            
            t_f_ratio = get_text_ratio(scrubbed_true, scrubbed_false)
            
            # 일치도가 0에 수렴할 경우 재검증
            if t_f_ratio <= 0.05:
                await asyncio.sleep(3.0) # 3초 대기
                
                retry_true_res = await requester(val)
                retry_false_res = await requester(false_payload)
                
                retry_scrubbed_true = _remove_direct_reflection(retry_true_res.text, val)
                retry_scrubbed_false = _remove_direct_reflection(retry_false_res.text, false_payload)
                
                if true_logic and false_logic:
                    for t_var in filter(None, set([true_logic, unquote(true_logic), html.escape(true_logic)])):
                        retry_scrubbed_true = retry_scrubbed_true.replace(t_var, "[LOGIC_NORMALIZED]")
                    for f_var in filter(None, set([false_logic, unquote(false_logic), html.escape(false_logic)])):
                        retry_scrubbed_false = retry_scrubbed_false.replace(f_var, "[LOGIC_NORMALIZED]")
                        
                retry_t_f_ratio = get_text_ratio(retry_scrubbed_true, retry_scrubbed_false)
                
                # 재검증에서 두 응답이 같으면 오탐으로 간주
                if retry_t_f_ratio >= 0.98:
                    return False, evidences
                    
                t_f_ratio = retry_t_f_ratio
                false_res = retry_false_res
                scrubbed_false = retry_scrubbed_false

            #  일치도가 98미만이면 정탐으로 확정
            if t_f_ratio < 0.98:
                pure_false = _get_pure_text(scrubbed_false)
                
                if GENERIC_DB_ERROR_KEYWORDS.search(pure_false):
                    evidences.append(f"[Verified] Conditional Error SQLi. T!=F ratio: {t_f_ratio:.4f}")
                else:
                    evidences.append(f"[Verified] Boolean SQLi. T!=F ratio: {t_f_ratio:.4f}")
                    
                return True, evidences
                
        except Exception:
            pass 

    return False, evidences