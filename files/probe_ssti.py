# ═══════════════════════════════════════════════════════════════
# probe_ssti.py — Probe Server-Side Template Injection (SSTI)
#
# Input : action dict từ agent_classifier
#         {"type":"ssti_probe","url":"/path","param":"name","method":"POST"}
# Output: list probe result dicts
#
# Không dùng AI — thuần HTTP + math marker detection
# Import fuzzer.py để lấy payload list + mutations
# ═══════════════════════════════════════════════════════════════

import logging
import httpx

from config import JUICE_SHOP_URL as BASE, LOG_FILE
from fuzzer import get_ssti_payloads

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [probe_ssti] %(message)s"
)

# ── Math marker ──────────────────────────────────────────────
# 7777 × 7777 = 60481729
# Số này không thể xuất hiện ngẫu nhiên trong response
# Nếu template engine evaluate thì sẽ thấy số này trong response
MATH_MARKER   = "60481729"
MATH_PAYLOAD  = "{{7777*7777}}"

# Markers phụ — một số engine render khác nhau
ALT_MARKERS = {
    "49":       "{{7*7}}",           # Jinja2 / Twig basic
    "60481729": "{{7777*7777}}",     # Full precision
}


def _send(method: str, url: str, param: str,
          payload: str, as_json: bool = False,
          timeout: int = 10) -> tuple[str, int]:
    """
    Gửi HTTP request với payload.

    Args:
        as_json: True nếu endpoint nhận JSON body (API endpoint)

    Returns:
        (response_body, status_code)
    """
    try:
        if method == "GET":
            r = httpx.get(
                url,
                params={param: payload},
                timeout=timeout,
                follow_redirects=True
            )
        elif as_json:
            r = httpx.post(
                url,
                json={param: payload},
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
        return r.text, r.status_code

    except httpx.TimeoutException:
        logging.warning(f"[SSTI] Timeout: {url} {param}={payload[:30]}")
        return "", 0
    except Exception as e:
        logging.warning(f"[SSTI] Error: {url}: {e}")
        return "", 0


def _detect_ssti(body: str) -> tuple[bool, str, str]:
    """
    Kiểm tra response có chứa kết quả evaluate template không.

    Kiểm tra MATH_MARKER trước (60481729) — chắc chắn nhất.
    Sau đó kiểm tra các marker phụ.

    Returns:
        (found: bool, marker: str, matched_payload: str)
    """
    # Marker chính
    if MATH_MARKER in body:
        return True, MATH_MARKER, MATH_PAYLOAD

    # Markers phụ
    for marker, payload in ALT_MARKERS.items():
        if marker in body:
            return True, marker, payload

    return False, "", ""


def _is_json_endpoint(action: dict) -> bool:
    """
    Đoán endpoint có nhận JSON body không.
    Dựa vào URL pattern — /api/ thường nhận JSON.
    """
    url = action.get("url", "")
    return "/api/" in url or url.endswith(".json")


def run_ssti_probe(action: dict) -> list:
    """
    Probe SSTI cho 1 endpoint + param.

    Quy trình:
        1. Thử MATH_PAYLOAD trước để detect nhanh
        2. Nếu không hit → thử toàn bộ payload list + mutations
        3. Thử cả form-data và JSON body (nếu là API endpoint)

    Args:
        action: dict từ agent_classifier
            {"url": "/path", "param": "name", "method": "POST"}

    Returns:
        List probe result dicts (rỗng nếu không tìm thấy)
    """
    url     = f"{BASE}{action['url']}"
    param   = action["param"]
    method  = action.get("method", "POST")
    is_json = _is_json_endpoint(action)

    print(f"[SSTI Probe] {method} {action['url']} param={param}")

    payloads = get_ssti_payloads()
    results  = []

    for payload in payloads:
        # Thử form-data trước
        body, status = _send(method, url, param, payload, as_json=False)
        found, marker, _ = _detect_ssti(body)

        # Nếu không thấy và là API endpoint → thử JSON body
        if not found and is_json and method == "POST":
            body, status = _send(method, url, param, payload, as_json=True)
            found, marker, _ = _detect_ssti(body)

        if found:
            result = {
                "type":      "ssti",
                "detection": "math_marker",
                "url":       action["url"],
                "param":     param,
                "method":    method,
                "payload":   payload,
                "marker":    marker,
                "evidence":  body[:400],
                "status":    status,
                "time_based": False,
                "sent_as_json": is_json
            }
            results.append(result)
            print(f"[SSTI Probe]   ✅ HIT: {payload!r} → marker: {marker}")
            logging.info(
                f"SSTI hit: {url} {param} "
                f"payload={payload!r} marker={marker}"
            )
            # Dừng sau hit đầu tiên — đã confirm SSTI
            break

    if not results:
        print(f"[SSTI Probe]   ✗  Không tìm thấy SSTI")

    return results
