# ═══════════════════════════════════════════════════════════════
# verify.py — Xác thực finding bằng 2 tầng: rule-based → AI
# Đã cập nhật: Dùng TARGET_HOST, Auto-Cookie, và kẹp param Submit
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

DVWA_COOKIES = get_dvwa_cookies()

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

def _rule_verify(finding: dict) -> tuple[bool, str]:
    # Sử dụng TARGET_HOST để ghép URL chuẩn
    url    = f"{TARGET_HOST}{finding['url']}"
    param  = finding["param"]
    method = finding.get("method", "GET")
    vuln   = finding.get("type", "sqli")

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

    for payload in payloads_to_try:
        try:
            # Ép thêm tham số Submit
            request_data = {param: payload, "Submit": "Submit"}
            
            if method == "GET":
                r = httpx.get(url, params=request_data, headers=DEFAULT_HEADERS, cookies=DVWA_COOKIES, timeout=10, follow_redirects=True)
            else:
                r = httpx.post(url, data=request_data, headers=DEFAULT_HEADERS, cookies=DVWA_COOKIES, timeout=10, follow_redirects=True)

            if _rule_check_response(r.text, vuln):
                logging.info(f"Rule verify CONFIRMED [{vuln}] {url} payload='{payload[:50]}'")
                return True, "rule_based"

        except Exception as e:
            logging.warning(f"Rule verify lỗi: {e}")

    return False, "rule_based"

def _build_verify_prompt(finding: dict) -> str:
    relevant_data = {
        "type": finding.get("type"), "url": finding.get("url"),
        "param": finding.get("param"), "payload": finding.get("payload"),
        "evidence": finding.get("evidence", "")[:300],
        "exploit_payloads": finding.get("exploit_payloads", [])
    }
    extra = "Với XSS: confirmed=true nếu payload không bị encode." if finding.get("type") == "xss" else "Với SQLi: confirmed=true nếu có error string."
    return f"""Bạn là chuyên gia security review. Đánh giá finding sau:\n{json.dumps(relevant_data, ensure_ascii=False, indent=2)}\n{extra}\nTrả về JSON THUẦN:\n{{\n  "confirmed": true hoặc false,\n  "confidence": 0.0 đến 1.0,\n  "reason": "lý do"\n}}"""

def _ai_verify(finding: dict) -> tuple[bool, str]:
    client = ollama.Client(host=AI_SERVER)
    try:
        response = client.chat(
            model=LLM_MODEL, messages=[{"role": "user", "content": _build_verify_prompt(finding)}],
            options={"temperature": TEMP_VERIFY}
        )
        match = re.search(r'(\{.*\})', response["message"]["content"], re.DOTALL)
        if match:
            return bool(json.loads(match.group(1)).get("confirmed", False)), "ai"
    except Exception: pass
    return False, "ai"

def verify_finding(finding: dict) -> dict:
    vuln = finding.get("type", "?")
    url  = finding.get("url", "?")

    confirmed, verifier = _rule_verify(finding)
    if confirmed:
        print(f"[Verify]   ✅ CONFIRMED (rule_based)  {vuln} @ {url}")
    else:
        print(f"[Verify]   rule_based fail → thử AI verify...")
        confirmed, verifier = _ai_verify(finding)
        print(f"[Verify]   {'✅ CONFIRMED' if confirmed else '✗  NOT confirmed'} (ai)          {vuln} @ {url}")

    finding["is_confirmed"] = confirmed
    finding["verified_by"]  = verifier
    return finding

def verify_all(findings: list) -> list:
    if not findings: return []
    print(f"\n[Verify] Bắt đầu xác thực {len(findings)} findings (Tầng 1: Rule, Tầng 2: AI)...")
    verified = [verify_finding(f) for f in findings]
    
    with open("verified_findings.json", "w", encoding="utf-8") as f:
        json.dump(verified, f, ensure_ascii=False, indent=2)
        
    confirmed_count = sum(1 for f in verified if f["is_confirmed"])
    rule_count = sum(1 for f in verified if f["is_confirmed"] and f.get("verified_by") == "rule_based")
    ai_count   = sum(1 for f in verified if f["is_confirmed"] and f.get("verified_by") == "ai")

    print(f"\n[Verify] ✅ Kết quả: Confirmed {confirmed_count}/{len(verified)} (Rule: {rule_count}, AI: {ai_count}) → verified_findings.json")
    return verified