# ═══════════════════════════════════════════════════════════════
# verify.py — Xác thực finding bằng kiến trúc Hybrid (Rule + AI)
# AI đóng vai trò Giám định ngữ nghĩa chống False Positive/Negative
# ═══════════════════════════════════════════════════════════════

import json
import re
import logging
import httpx
import ollama

from config import AI_SERVER, LLM_MODEL, TEMP_VERIFY, TARGET_HOST, LOG_FILE
from fuzzer import XSS_MARKER
from dvwa_auth import get_dvwa_cookies

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [verify] %(message)s"
)

DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"
}

SQLI_ERROR_MARKERS = [
    "syntax error", "sqlite", "sql", "ora-", "mysql", "odbc", 
    "unclosed quotation", "near \"", "unrecognized token", "sqlite_error"
]

XSS_ENCODED_FORMS = ["&lt;", "&#60;", "\\u003c", "%3C", "%3c"]

def _rule_check_response(body: str, vuln_type: str) -> bool:
    if vuln_type == "sqli":
        return any(m in body.lower() for m in SQLI_ERROR_MARKERS)
    elif vuln_type == "xss":
        if XSS_MARKER not in body:
            return False
        idx     = body.find(XSS_MARKER)
        snippet = body[max(0, idx - 50): idx + len(XSS_MARKER) + 50]
        if any(enc in snippet for enc in XSS_ENCODED_FORMS):
            return False
        return True
    return False

def _execute_request_and_rule_check(finding: dict) -> tuple[bool, str]:
    """Thực thi request, trả về đánh giá tĩnh (Rule) và mã nguồn HTML phản hồi."""
    url    = f"{TARGET_HOST}{finding['url']}"
    param  = finding["param"]
    method = finding.get("method", "GET")
    vuln   = finding.get("type", "sqli")
    dvwa_cookies = get_dvwa_cookies()

    payloads_to_try = finding.get("exploit_payloads", [])
    if not payloads_to_try:
        original = finding.get("payload", "")
        if original: payloads_to_try = [original]

    if vuln == "xss":
        marker_payloads = [p for p in payloads_to_try if XSS_MARKER in p]
        if not marker_payloads:
            payloads_to_try = [
                f"<script>{XSS_MARKER}</script>",
                f'"><script>{XSS_MARKER}</script>',
                f"<img src=x onerror='{XSS_MARKER}'>",
            ] + payloads_to_try

    last_html = ""
    for payload in payloads_to_try:
        try:
            request_data = {param: payload, "Submit": "Submit"}
            
            if method == "GET":
                r = httpx.get(url, params=request_data, headers=DEFAULT_HEADERS, cookies=dvwa_cookies, timeout=10, follow_redirects=True)
            else:
                r = httpx.post(url, data=request_data, headers=DEFAULT_HEADERS, cookies=dvwa_cookies, timeout=10, follow_redirects=True)
            
            last_html = r.text
            if _rule_check_response(r.text, vuln):
                return True, last_html

        except Exception as e:
            logging.warning(f"Lỗi gửi request trong Verify: {e}")

    return False, last_html

def _build_hybrid_prompt(finding: dict, rule_confirmed: bool, html_response: str) -> str:
    vuln_type = finding.get("type", "sqli")
    
    # Trích xuất tối đa 2000 ký tự HTML để AI đọc, tránh tràn cửa sổ token
    html_snippet = html_response[:2000] if html_response else "[Không có phản hồi từ server]"

    # Định hướng AI dựa trên kết quả của hệ thống tĩnh
    if rule_confirmed:
        mission = f"""Hệ thống Regex tĩnh đã báo cáo CÓ lỗ hổng {vuln_type}. 
Nhiệm vụ của bạn là đọc mã HTML và kiểm tra xem đây có phải là CẢNH BÁO GIẢ (False Positive) không.
- Nếu thông báo lỗi chỉ là văn bản tĩnh vô hại hoặc marker XSS bị vô hiệu hóa an toàn -> Hãy trả về confirmed=false.
- Nếu lỗ hổng thực sự tồn tại -> Trả về confirmed=true."""
    else:
        mission = f"""Hệ thống Regex tĩnh báo cáo KHÔNG CÓ lỗ hổng {vuln_type}.
Nhiệm vụ của bạn là đọc HTML để kiểm tra xem có CẢNH BÁO BỊ BỎ LỌT (False Negative) do WAF chặn mập mờ hay không.
- Nếu trang có biểu hiện bị WAF đánh chặn (captcha, thông báo 'hành vi bất thường') -> Mã khai thác đã thất bại, trả về confirmed=false.
- Nếu bypass thực sự thành công nhưng Regex quét trượt -> Trả về confirmed=true."""

    return f"""Bạn là chuyên gia Security Review cao cấp. Đánh giá độ tin cậy của finding sau.
--- THÔNG TIN FINDING ---
Loại: {vuln_type}
URL: {finding.get('url')}
Tham số: {finding.get('param')}
Payload: {finding.get('payload')}

--- NHIỆM VỤ ---
{mission}

--- HTML SERVER PHẢN HỒI (Trích xuất) ---
{html_snippet}

--- BẮT BUỘC TRẢ VỀ JSON THUẦN (Không giải thích ngoài lề) ---
{{
  "confirmed": true hoặc false,
  "confidence": 0.0 đến 1.0,
  "reason": "Lý do ngắn gọn giải thích tại sao bạn chốt kết quả này"
}}"""

def _ai_hybrid_verify(finding: dict, rule_confirmed: bool, html_response: str) -> dict:
    client = ollama.Client(host=AI_SERVER)
    prompt = _build_hybrid_prompt(finding, rule_confirmed, html_response)
    
    try:
        response = client.chat(
            model=LLM_MODEL, 
            messages=[{"role": "user", "content": prompt}],
            options={"temperature": TEMP_VERIFY}
        )
        # Bóc tách JSON an toàn khỏi text thừa
        match = re.search(r'(\{.*\})', response["message"]["content"], re.DOTALL)
        if match:
            result = json.loads(match.group(1))
            return {
                "is_confirmed": bool(result.get("confirmed", rule_confirmed)),
                "confidence": float(result.get("confidence", 0.8 if rule_confirmed else 0.2)),
                "ai_reason": str(result.get("reason", "AI phân tích thành công.")),
                "verified_by": "hybrid_ai"
            }
    except Exception as e:
        logging.error(f"Lỗi gọi AI Verify: {e}")
        
    # Cơ chế Fallback an toàn: Nếu API lỗi, tin tưởng vào phán quyết tĩnh
    return {
        "is_confirmed": rule_confirmed,
        "confidence": 0.5,
        "ai_reason": "Lỗi API AI, fallback về kết quả Rule-based.",
        "verified_by": "rule_based_fallback"
    }

def verify_finding(finding: dict) -> dict:
    vuln = finding.get("type", "?")
    url  = finding.get("url", "?")

    print(f"\n[Verify] 🛡️ Bắn thử payload vào mục tiêu: {vuln} @ {url}")
    
    # Bước 1: Quét tĩnh để lấy HTML thực tế
    rule_confirmed, html_response = _execute_request_and_rule_check(finding)
    print(f"[Verify] ➔ Rule-based đánh giá thô: {'CÓ LỖI' if rule_confirmed else 'KHÔNG LỖI'}")
    
    # Bước 2: Bơm HTML cho AI để thẩm định lại ngữ nghĩa
    print(f"[Verify] ➔ Đang giao cho AI thẩm định ngữ nghĩa (Hybrid mode)...")
    ai_eval = _ai_hybrid_verify(finding, rule_confirmed, html_response)
    
    # Ghi đè đánh giá cuối cùng vào finding
    finding.update(ai_eval)
    
    status_icon = "✅ CONFIRMED" if finding["is_confirmed"] else "✗ REJECTED"
    print(f"[Verify] ➔ Kết quả chốt: {status_icon} (Tin cậy: {finding['confidence']})")
    print(f"[Verify] ➔ Lý do AI: {finding['ai_reason']}")

    return finding

def verify_all(findings: list) -> list:
    if not findings: return []
    print(f"\n[Verify] KHỞI ĐỘNG XÁC THỰC {len(findings)} FINDINGS BẰNG KIẾN TRÚC HYBRID...")
    verified = [verify_finding(f) for f in findings]
    
    with open("verified_findings.json", "w", encoding="utf-8") as f:
        json.dump(verified, f, ensure_ascii=False, indent=2)
        
    confirmed_count = sum(1 for f in verified if f["is_confirmed"])
    rejected_count  = len(verified) - confirmed_count

    print(f"\n[Verify] 🏁 TỔNG KẾT: Xác nhận thành công {confirmed_count} lỗi | Loại bỏ {rejected_count} báo động giả.")
    print(f"[Verify] 💾 Đã kết xuất kết quả vào: verified_findings.json")
    return verified