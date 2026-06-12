# ═══════════════════════════════════════════════════════════════
# probe_xss.py — Probe Reflected XSS (Phiên bản DVWA Tự động)
# ═══════════════════════════════════════════════════════════════

import logging
import httpx

from config import TARGET_HOST, LOG_FILE
from fuzzer import get_xss_payloads, XSS_MARKER
from dvwa_auth import get_dvwa_cookies

BASE = TARGET_HOST

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [probe_xss] %(message)s"
)

DVWA_COOKIES = get_dvwa_cookies()

ENCODED_FORMS = [
    "&lt;", "&#60;", "\\u003c", "%3C", "%3c"
]

DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"
}

def _send(method: str, url: str, param: str,
          payload: str, timeout: int = 10) -> tuple[str, int]:
    request_data = {param: payload, "Submit": "Submit"}
    try:
        if method == "GET":
            r = httpx.get(url, params=request_data, headers=DEFAULT_HEADERS, cookies=DVWA_COOKIES, timeout=timeout, follow_redirects=True)
        else:
            r = httpx.post(url, data=request_data, headers=DEFAULT_HEADERS, cookies=DVWA_COOKIES, timeout=timeout, follow_redirects=True)
        return r.text, r.status_code
    except httpx.TimeoutException:
        logging.warning(f"[XSS] Timeout: {url} {param}={payload[:30]}")
        return "", 0
    except Exception as e:
        logging.warning(f"[XSS] Error {url}: {e}")
        return "", 0

def _is_reflected(body: str, payload: str) -> tuple[bool, str]:
    if XSS_MARKER not in body:
        return False, ""

    idx     = body.find(XSS_MARKER)
    snippet = body[max(0, idx - 50): idx + len(XSS_MARKER) + 50]

    # Kiểm tra encode bất kể payload có ký tự < hay không
    if any(enc in snippet for enc in ENCODED_FORMS):
        return False, snippet

    # Chặn False Positive: Server reflect literal string dạng URL-encoded
    if "%3C" in payload.upper() or "%25" in payload.upper():
        return False, snippet

    return True, snippet

def run_xss_probe(action: dict) -> list:
    url    = f"{BASE}{action['url']}"
    param  = action["param"]
    method = action.get("method", "GET")

    print(f"[XSS Probe] {method} {action['url']} ?{param}")

    payloads = get_xss_payloads()
    results  = []
    found    = False

    for payload in payloads:
        body, status = _send(method, url, param, payload)
        reflected, snippet = _is_reflected(body, payload)

        if reflected:
            result = {
                "type":      "xss",
                "detection": "reflection",
                "url":       action["url"],
                "param":     param,
                "method":    method,
                "payload":   payload,
                "marker":    XSS_MARKER,
                "evidence":  snippet,
                "status":    status,
                "time_based": False
            }
            results.append(result)
            print(f"[XSS Probe]   ✅ REFLECTED: {payload[:60]!r}")
            logging.info(f"XSS hit: {url} {param} payload={payload!r}")

            if not found:
                found = True
            if len(results) >= 3:
                break

    if not results:
        print(f"[XSS Probe]   ✗  Không tìm thấy XSS reflection")

    return results