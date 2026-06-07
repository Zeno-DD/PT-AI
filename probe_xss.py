# ═══════════════════════════════════════════════════════════════
# probe_xss.py — Probe Reflected XSS (Phiên bản DVWA)
# ═══════════════════════════════════════════════════════════════

import logging
import httpx

# Lấy cấu hình LOG_FILE, tạm bỏ JUICE_SHOP_URL để dùng link DVWA
from config import LOG_FILE
from fuzzer import get_xss_payloads, XSS_MARKER

# ── Cấu hình URL mục tiêu DVWA ───────────────────────────────
BASE = "http://192.168.0.104"

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [probe_xss] %(message)s"
)

# ── [QUAN TRỌNG] Cấu hình Cookie sống của DVWA ───────────────
DVWA_COOKIES = {
    "PHPSESSID": "5eebef159783c02bbdee94932adc8b4e", 
    "security": "low"
}

# Các dạng encode của < — nếu response trả về dạng này
# thì payload đã bị encode → KHÔNG phải XSS
ENCODED_FORMS = [
    "&lt;",      # HTML entity
    "&#60;",     # Decimal entity
    "\\u003c",   # Unicode escape
    "%3C",       # URL encode (case sensitive)
    "%3c",       # URL encode (lowercase)
]

DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                  "AppleWebKit/537.36 (KHTML, like Gecko) "
                  "Chrome/120.0.0.0 Safari/537.36"
}


def _send(method: str, url: str, param: str,
          payload: str, timeout: int = 10) -> tuple[str, int]:
    """Gửi request kèm Cookie xác thực và trả về (body, status_code)."""
    try:
        if method == "GET":
            r = httpx.get(
                url,
                params={param: payload},
                headers=DEFAULT_HEADERS,
                cookies=DVWA_COOKIES,      # <--- ĐÃ CHÈN COOKIE
                timeout=timeout,
                follow_redirects=True
            )
        else:
            r = httpx.post(
                url,
                data={param: payload},
                headers=DEFAULT_HEADERS,
                cookies=DVWA_COOKIES,      # <--- ĐÃ CHÈN COOKIE
                timeout=timeout,
                follow_redirects=True
            )
        return r.text, r.status_code
    except httpx.TimeoutException:
        logging.warning(f"[XSS] Timeout: {url} {param}={payload[:30]}")
        return "", 0
    except Exception as e:
        logging.warning(f"[XSS] Error {url}: {e}")
        return "", 0


def _is_reflected(body: str, payload: str) -> tuple[bool, str]:
    """
    Kiểm tra payload có được reflect trong response không.
    """
    # Marker không có trong response → không reflected
    if XSS_MARKER not in body:
        return False, ""

    # Tìm vị trí marker trong body để lấy context
    idx     = body.find(XSS_MARKER)
    snippet = body[max(0, idx - 50): idx + len(XSS_MARKER) + 50]

    # Kiểm tra < bị encode không (chỉ áp dụng nếu payload có <)
    if "<" in payload:
        if any(enc in snippet for enc in ENCODED_FORMS):
            # Bị encode → server đã escape → không phải XSS thực sự
            return False, snippet

    return True, snippet


def run_xss_probe(action: dict) -> list:
    """
    Probe Reflected XSS cho 1 endpoint + param.
    """
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
            logging.info(
                f"XSS hit: {url} {param} payload={payload!r}"
            )

            if not found:
                found = True
                # Vẫn tiếp tục test để tìm thêm vector khác
                # nhưng sau 3 hits thì dừng
            if len(results) >= 3:
                break

    if not results:
        print(f"[XSS Probe]   ✗  Không tìm thấy XSS reflection")

    return results