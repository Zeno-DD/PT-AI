# ═══════════════════════════════════════════════════════════════
# verify.py — Xác thực finding bằng 2 tầng: rule-based → AI
#
# Input : findings.json (sau bypass_loop)
# Output: verified_findings.json
#
# Fix: bỏ "from auth import HEADERS" → dùng header đơn giản
#      vì target mới không cần JWT authentication
# ═══════════════════════════════════════════════════════════════

import json
import re
import logging
import httpx
import ollama

from config import (
    AI_SERVER, LLM_MODEL,
    TEMP_VERIFY, JUICE_SHOP_URL,
    LOG_FILE
)

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [verify] %(message)s"
)

# Headers đơn giản — không cần JWT auth cho target mới
DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                  "AppleWebKit/537.36 (KHTML, like Gecko) "
                  "Chrome/120.0.0.0 Safari/537.36"
}

SQLI_ERROR_MARKERS = [
    "syntax error", "sqlite", "sql", "ora-",
    "mysql", "odbc", "unclosed quotation",
    "near \"", "unrecognized token", "sqlite_error"
]
SSTI_MATH_MARKER = "60481729"


def _rule_check_response(body: str, vuln_type: str) -> bool:
    """Kiểm tra response có chứa marker xác nhận lỗ hổng không."""
    if vuln_type == "ssti":
        return SSTI_MATH_MARKER in body
    return any(marker in body.lower() for marker in SQLI_ERROR_MARKERS)


def _rule_verify(finding: dict) -> tuple[bool, str]:
    """
    Tầng 1: Gửi lại exploit_payloads đến target — check response.
    Không gọi AI, không cần auth.
    """
    url    = f"{JUICE_SHOP_URL}{finding['url']}"
    param  = finding["param"]
    method = finding.get("method", "GET")
    vuln   = finding.get("type", "sqli")

    payloads_to_try = finding.get("exploit_payloads", [])
    if not payloads_to_try:
        original = finding.get("payload", "")
        if original:
            payloads_to_try = [original]

    for payload in payloads_to_try:
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

            if _rule_check_response(r.text, vuln):
                logging.info(
                    f"Rule verify CONFIRMED [{vuln}] {url} "
                    f"payload='{payload[:50]}'"
                )
                return True, "rule_based"

        except httpx.TimeoutException:
            logging.warning(f"Rule verify timeout: {url}")
        except Exception as e:
            logging.warning(f"Rule verify lỗi: {e}")

    return False, "rule_based"


def _build_verify_prompt(finding: dict) -> str:
    """Xây dựng prompt cho AI cross-check."""
    relevant_data = {
        "type":             finding.get("type"),
        "url":              finding.get("url"),
        "param":            finding.get("param"),
        "payload":          finding.get("payload"),
        "evidence":         finding.get("evidence", "")[:300],
        "time_based":       finding.get("time_based", False),
        "severity":         finding.get("severity"),
        "confidence":       finding.get("confidence"),
        "explanation":      finding.get("explanation", "")[:300],
        "exploit_payloads": finding.get("exploit_payloads", []),
        "bypass_history": [
            {
                "payload":   h.get("payload"),
                "technique": h.get("technique"),
                "success":   h.get("success"),
                "snippet":   h.get("snippet", "")[:80]
            }
            for h in finding.get("bypass_history", [])
        ]
    }

    return f"""Bạn là chuyên gia security review. Đánh giá finding bảo mật sau:

{json.dumps(relevant_data, ensure_ascii=False, indent=2)}

Dựa trên evidence, bypass_history và exploit_payloads,
hãy quyết định: Đây có phải lỗ hổng THỰC SỰ không?

Trả về JSON THUẦN (không markdown, không text thừa):
{{
  "confirmed": true hoặc false,
  "confidence": 0.0 đến 1.0,
  "reason": "giải thích ngắn gọn lý do quyết định"
}}"""


def _ai_verify(finding: dict) -> tuple[bool, str]:
    """
    Tầng 2: LLM cross-check finding.
    Chỉ gọi khi rule_verify() trả về False.
    """
    client = ollama.Client(host=AI_SERVER)
    prompt = _build_verify_prompt(finding)

    try:
        response = client.chat(
            model=LLM_MODEL,
            messages=[{"role": "user", "content": prompt}],
            options={"temperature": TEMP_VERIFY}
        )
        raw = response["message"]["content"]
        logging.info(
            f"AI verify [{finding.get('type')}] "
            f"{finding.get('url')}: {raw[:100]}"
        )
    except Exception as e:
        logging.error(f"AI verify LLM lỗi: {e}")
        return False, "ai_error"

    match = re.search(r'(\{.*\})', raw, re.DOTALL)
    if match:
        try:
            obj       = json.loads(match.group(1))
            confirmed = bool(obj.get("confirmed", False))
            reason    = obj.get("reason", "")
            logging.info(f"AI verify: confirmed={confirmed} reason={reason[:80]}")
            return confirmed, "ai"
        except json.JSONDecodeError:
            logging.warning(f"AI verify JSON parse fail: {raw[:100]}")

    return False, "ai"


def verify_finding(finding: dict) -> dict:
    """Verify một finding qua 2 tầng: rule-based → AI."""
    vuln = finding.get("type", "?")
    url  = finding.get("url", "?")

    # Tầng 1: Rule-based
    confirmed, verifier = _rule_verify(finding)

    if confirmed:
        print(f"[Verify]   ✅ CONFIRMED (rule_based)  {vuln} @ {url}")
    else:
        # Tầng 2: AI cross-check
        print(f"[Verify]   rule_based: not confirmed → thử AI verify...")
        confirmed, verifier = _ai_verify(finding)

        if confirmed:
            print(f"[Verify]   ✅ CONFIRMED (ai)         {vuln} @ {url}")
        else:
            print(f"[Verify]   ✗  NOT confirmed          {vuln} @ {url}")

    finding["is_confirmed"] = confirmed
    finding["verified_by"]  = verifier
    return finding


def verify_all(findings: list) -> list:
    """Verify toàn bộ findings và lưu verified_findings.json."""
    if not findings:
        print("[Verify] ⚠️  Không có finding nào để verify")
        return []

    print(f"\n[Verify] Verify {len(findings)} findings...")
    print(f"         Tầng 1: rule-based (không gọi AI)")
    print(f"         Tầng 2: AI cross-check nếu tầng 1 fail")

    verified = []
    for i, finding in enumerate(findings, 1):
        print(f"\n[Verify] [{i}/{len(findings)}] "
              f"{finding.get('type','?').upper()} @ {finding.get('url','?')}")
        result = verify_finding(finding)
        verified.append(result)

    with open("verified_findings.json", "w", encoding="utf-8") as f:
        json.dump(verified, f, ensure_ascii=False, indent=2)

    confirmed_count = sum(1 for f in verified if f["is_confirmed"])
    rule_count = sum(1 for f in verified
                     if f["is_confirmed"] and f.get("verified_by") == "rule_based")
    ai_count   = sum(1 for f in verified
                     if f["is_confirmed"] and f.get("verified_by") == "ai")

    print(f"\n[Verify] ✅ Kết quả:")
    print(f"         Confirmed  : {confirmed_count}/{len(verified)}")
    print(f"         rule_based : {rule_count}")
    print(f"         ai         : {ai_count}")
    print(f"         → verified_findings.json")

    logging.info(
        f"verify_all: {confirmed_count}/{len(verified)} confirmed "
        f"(rule={rule_count}, ai={ai_count})"
    )
    return verified
