# ═══════════════════════════════════════════════════════════════
# probe_sqli.py — Probe SQL Injection (Phiên bản DVWA Tự động)
# Đã fix lỗi: Gọi cookie trong hàm thực thi thay vì global
# ═══════════════════════════════════════════════════════════════

import logging
import httpx

from config import TARGET_HOST, LOG_FILE
from fuzzer import get_sqli_payloads
from dvwa_auth import get_dvwa_cookies

# Dùng TARGET_HOST để nối URL (với trick chuỗi rỗng từ config thì nó sẽ an toàn)
BASE = TARGET_HOST

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [probe_sqli] %(message)s"
)

ERROR_MARKERS = [
    "syntax error", "sqlite", "sqlite_error", "sql syntax",
    "ora-", "mysql_fetch", "mysql", "odbc",
    "unclosed quotation", "unrecognized token", "near \"",
    "pg_query", "psql", "mssql", "microsoft sql",
]

TIME_THRESHOLD = 2.5

def _send(method: str, url: str, param: str,
          payload: str, cookies: dict, timeout: int = 10) -> tuple[str, float, int]:
    """Gửi HTTP request với payload kèm theo Cookie xác thực DVWA và nút Submit."""
    request_data = {param: payload, "Submit": "Submit"}
    
    try:
        if method == "GET":
            r = httpx.get(
                url,
                params=request_data,
                cookies=cookies,
                timeout=timeout,
                follow_redirects=True
            )
        else:
            r = httpx.post(
                url,
                data=request_data,
                cookies=cookies,
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
    body_lower = body.lower()
    for marker in ERROR_MARKERS:
        if marker in body_lower:
            return True, marker
    return False, ""

def run_sqli_probe(action: dict) -> list:
    url    = f"{BASE}{action['url']}"
    param  = action["param"]
    method = action.get("method", "GET")

    # Lấy Session DVWA tại thời điểm hàm thực sự chạy
    dvwa_cookies = get_dvwa_cookies()

    print(f"[SQLi Probe] {method} {action['url']} ?{param}")

    _, baseline, _ = _send(method, url, param, "1", dvwa_cookies)
    logging.info(f"SQLi baseline {url} {param}: {baseline:.2f}s")

    payloads = get_sqli_payloads()
    results  = []
    found_error_based = False

    for payload in payloads:
        is_time = "SLEEP" in payload.upper() or "WAITFOR" in payload.upper()
        if found_error_based and not is_time:
            continue

        body, elapsed, status = _send(method, url, param, payload, dvwa_cookies)
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