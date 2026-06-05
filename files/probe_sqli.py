# ═══════════════════════════════════════════════════════════════
# probe_sqli.py — Probe SQL Injection
#
# Input : action dict từ agent_classifier
#         {"type":"sqli_probe","url":"/path","param":"id","method":"GET"}
# Output: list probe result dicts
#
# Không dùng AI — thuần HTTP + rule-based detection
# Import fuzzer.py để lấy payload list + mutations
# ═══════════════════════════════════════════════════════════════

import logging
import httpx

from config import JUICE_SHOP_URL as BASE, LOG_FILE
from fuzzer import get_sqli_payloads

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [probe_sqli] %(message)s"
)

# ── Markers detect SQL error ─────────────────────────────────
ERROR_MARKERS = [
    "syntax error",
    "sqlite",
    "sqlite_error",
    "sql syntax",
    "ora-",
    "mysql_fetch",
    "mysql",
    "odbc",
    "unclosed quotation",
    "unrecognized token",
    "near \"",
    "pg_query",
    "psql",
    "mssql",
    "microsoft sql",
]

# Delay tối thiểu để coi là time-based (giây)
TIME_THRESHOLD = 2.5


def _send(method: str, url: str, param: str,
          payload: str, timeout: int = 10) -> tuple[str, float, int]:
    """
    Gửi HTTP request với payload.

    Returns:
        (response_body, elapsed_seconds, status_code)
    """
    try:
        if method == "GET":
            r = httpx.get(
                url,
                params={param: payload},
                timeout=timeout,
                follow_redirects=True
            )
        else:
            r = httpx.post(
                url,
                data={param: payload},
                timeout=timeout,
                follow_redirects=True
            )
        return r.text, r.elapsed.total_seconds(), r.status_code

    except httpx.TimeoutException:
        logging.warning(f"[SQLI] Timeout: {url} {param}={payload[:30]}")
        return "", timeout, 0
    except Exception as e:
        logging.warning(f"[SQLI] Error: {url}: {e}")
        return "", 0, 0


def _detect_error(body: str) -> tuple[bool, str]:
    """
    Kiểm tra response có chứa SQL error marker không.

    Returns:
        (found: bool, marker: str)
    """
    body_lower = body.lower()
    for marker in ERROR_MARKERS:
        if marker in body_lower:
            return True, marker
    return False, ""


def run_sqli_probe(action: dict) -> list:
    """
    Probe SQL Injection cho 1 endpoint + param.

    Quy trình:
        1. Lấy baseline response time (payload bình thường)
        2. Với mỗi payload (base + mutations):
           - Gửi HTTP request
           - Check error string → error-based SQLi
           - Check elapsed > baseline + threshold → time-based SQLi
        3. Dừng ngay khi tìm được hit đầu tiên (tiết kiệm thời gian)
           Trừ time-based — test hết để confirm

    Args:
        action: dict từ agent_classifier
            {"url": "/path", "param": "name", "method": "GET"}

    Returns:
        List probe result dicts (rỗng nếu không tìm thấy)
    """
    url    = f"{BASE}{action['url']}"
    param  = action["param"]
    method = action.get("method", "GET")

    print(f"[SQLi Probe] {method} {action['url']} ?{param}")

    # ── Baseline time ─────────────────────────────────────────
    _, baseline, _ = _send(method, url, param, "1")
    logging.info(f"SQLi baseline {url} {param}: {baseline:.2f}s")

    payloads = get_sqli_payloads()
    results  = []
    found_error_based = False

    for payload in payloads:
        # Nếu đã tìm được error-based thì bỏ qua payload không phải time-based
        is_time = "SLEEP" in payload.upper() or "WAITFOR" in payload.upper()
        if found_error_based and not is_time:
            continue

        body, elapsed, status = _send(method, url, param, payload)

        # ── Error-based detection ─────────────────────────────
        error_found, marker = _detect_error(body)
        if error_found and not found_error_based:
            found_error_based = True
            result = {
                "type":       "sqli",
                "detection":  "error_based",
                "url":        action["url"],
                "param":      param,
                "method":     method,
                "payload":    payload,
                "marker":     marker,
                "evidence":   body[:400],
                "status":     status,
                "time_based": False
            }
            results.append(result)
            print(f"[SQLi Probe]   ✅ ERROR-BASED: {payload[:50]!r} → marker: {marker}")
            logging.info(f"SQLi error-based hit: {url} {param} payload={payload[:50]}")

        # ── Time-based detection ──────────────────────────────
        if is_time and elapsed > baseline + TIME_THRESHOLD:
            result = {
                "type":       "sqli",
                "detection":  "time_based",
                "url":        action["url"],
                "param":      param,
                "method":     method,
                "payload":    payload,
                "marker":     f"delay {elapsed:.1f}s > baseline {baseline:.1f}s",
                "evidence":   body[:200],
                "status":     status,
                "time_based": True
            }
            results.append(result)
            print(f"[SQLi Probe]   ✅ TIME-BASED: delay={elapsed:.1f}s baseline={baseline:.1f}s")
            logging.info(f"SQLi time-based hit: {url} {param} elapsed={elapsed:.1f}s")

    if not results:
        print(f"[SQLi Probe]   ✗  Không tìm thấy SQLi")

    return results
