# ═══════════════════════════════════════════════════════════════
# crawler.py — Thu thập endpoint từ web target (Phiên bản DVWA)
# ═══════════════════════════════════════════════════════════════

import sys
sys.stdout.reconfigure(encoding='utf-8')

import json
import logging
from urllib.parse import urlparse, parse_qs, urljoin
from collections import defaultdict

import httpx
from bs4 import BeautifulSoup

from config import TARGET_BASE_URL, LOG_FILE
from dvwa_auth import get_dvwa_cookies

TARGET_URL = f"{TARGET_BASE_URL}/index.php"

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [crawler] %(message)s"
)

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Accept-Language": "vi-VN,vi;q=0.9,en;q=0.8"
}

SKIP_EXT = {
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif",
    ".ico", ".svg", ".woff", ".woff2", ".ttf", ".pdf",
    ".zip", ".mp4", ".mp3"
}

def _should_skip(url: str) -> bool:
    parsed = urlparse(url)
    base = urlparse(TARGET_URL)
    if parsed.netloc and parsed.netloc != base.netloc:
        return True
    path = parsed.path.lower()
    if any(path.endswith(ext) for ext in SKIP_EXT):
        return True
    if url.startswith("#") or "logout.php" in url:
        return True
    return False

def _extract_params(url: str) -> list:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    params = []
    for name, values in qs.items():
        sample = values[0] if values else ""
        if sample.isdigit(): hint = "int"
        elif sample == "": hint = "empty"
        else: hint = "string"
        params.append({
            "name": name, "location": "query",
            "type_hint": hint, "sample_values": [sample]
        })
    return params

def _extract_forms(soup: BeautifulSoup, page_url: str) -> list:
    forms = []
    for form in soup.find_all("form"):
        action = form.get("action", "")
        action = urljoin(page_url, action) if action else page_url
        method = form.get("method", "get").upper()
        inputs = []
        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name", "")
            if not name: continue
            inputs.append({
                "name": name, "type": inp.get("type", inp.name),
                "value": inp.get("value", "")
            })
        if inputs:
            forms.append({"method": method, "action": action, "inputs": inputs})
    return forms

def _extract_links(soup: BeautifulSoup, page_url: str) -> list:
    links = []
    for tag in soup.find_all(["a", "link"], href=True):
        href = tag.get("href", "").strip()
        if href and not href.startswith(("javascript:", "mailto:", "tel:")):
            links.append(urljoin(page_url, href))
    return links

def crawl(max_pages: int = 100) -> list:
    print(f"\n[Crawler] Target: {TARGET_URL}")
    print(f"[Crawler] Max pages: {max_pages}")

    # Lấy Cookie tự động (có bao gồm security=low)
    dvwa_cookies = get_dvwa_cookies()
    client = httpx.Client(headers=HEADERS, cookies=dvwa_cookies, timeout=10, follow_redirects=True)
    
    print("[Crawler] Đã nạp Cookie tự động. Bắt đầu rải bọ cào dữ liệu...\n")

    visited  = set()
    queue    = [TARGET_URL]
    entries  = defaultdict(lambda: {
        "params": {}, "forms": [], "statuses": set(),
        "seen_count": 0, "discovered_from": set(), "examples": set()
    })

    while queue and len(visited) < max_pages:
        url = queue.pop(0)
        parsed = urlparse(url)
        clean  = parsed._replace(fragment="").geturl()

        if clean in visited or _should_skip(clean):
            continue
        visited.add(clean)

        try:
            r = client.get(clean)
        except Exception as e:
            logging.warning(f"Error {clean}: {e}")
            continue

        status       = r.status_code
        content_type = r.headers.get("content-type", "")
        path = parsed.path or "/"
        key  = ("GET", path)

        entry = entries[key]
        entry["method"]         = "GET"
        entry["path"]           = path
        entry["url"]            = clean
        entry["response_content_type"] = content_type
        entry["statuses"].add(status)
        entry["seen_count"]    += 1
        entry["examples"].add(clean)

        for p in _extract_params(clean):
            name = p["name"]
            if name not in entry["params"]:
                entry["params"][name] = p
            else:
                existing = entry["params"][name]["sample_values"]
                merged   = list(dict.fromkeys(existing + p["sample_values"]))[:3]
                entry["params"][name]["sample_values"] = merged

        if "html" in content_type and status == 200:
            try: soup = BeautifulSoup(r.text, "html.parser")
            except Exception: continue

            for form in _extract_forms(soup, clean):
                form_inputs = tuple(sorted(i["name"] for i in form["inputs"]))
                if not any(tuple(sorted(i["name"] for i in f["inputs"])) == form_inputs for f in entry["forms"]):
                    entry["forms"].append(form)

                    act_parsed = urlparse(form["action"])
                    act_path   = act_parsed.path or "/"
                    post_entry = entries[(form["method"], act_path)]
                    
                    post_entry["method"] = form["method"]
                    post_entry["path"]   = act_path
                    post_entry["url"]    = form["action"]
                    post_entry["statuses"].add(0)
                    post_entry["seen_count"] += 1
                    post_entry["examples"].add(form["action"])
                    post_entry["forms"].append(form)

                    for inp in form["inputs"]:
                        name = inp["name"]
                        if name not in post_entry["params"]:
                            sample = inp.get("value", "")
                            hint   = "int" if sample.isdigit() else "empty" if not sample else "string"
                            post_entry["params"][name] = {
                                "name": name, "location": "body",
                                "type_hint": hint, "sample_values": [sample] if sample else [""]
                            }

            for link in _extract_links(soup, clean):
                norm = urlparse(link)._replace(fragment="").geturl()
                if norm not in visited and not _should_skip(norm):
                    queue.append(norm)
                    entry["discovered_from"].add(clean)

        print(f"[Crawler] [{len(visited):3d}] {status} {path}")

    inventory = []
    for (method, path), e in entries.items():
        inventory.append({
            "method": method,
            "url": e.get("url", urljoin(TARGET_BASE_URL, path)),
            "path": path,
            "canonical_path": path,
            "response_content_type": e.get("response_content_type", ""),
            "statuses": list(e["statuses"]),
            "params": list(e["params"].values()),
            "forms": e["forms"],
            "seen_count": e["seen_count"],
            "source_tools": ["crawler"],
            "discovered_from": list(e["discovered_from"])[:5],
            "examples": list(e["examples"])[:3]
        })

    with open("inventory.json", "w", encoding="utf-8") as f:
        json.dump(inventory, f, ensure_ascii=False, indent=2)

    has_input_count = sum(1 for e in inventory if e["params"] or e["forms"])
    print(f"\n[Crawler] ✅ Hoàn thành! {len(inventory)} endpoints ({has_input_count} có input) → inventory.json")
    logging.info(f"Crawl xong: {len(inventory)} endpoints, {len(visited)} pages visited")
    return inventory

if __name__ == "__main__":
    crawl()