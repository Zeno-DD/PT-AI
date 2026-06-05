# ═══════════════════════════════════════════════════════════════
# agent_classifier.py — AI phân loại endpoint → SQLi / SSTI
#
# Input : inventory.json  (output trực tiếp từ ReconTool)
# Output: probe_results.json
#
# Vai trò:
#   Đọc inventory.json → lọc endpoint có input → gửi cho LLM
#   LLM quyết định: endpoint nào test sqli, endpoint nào test ssti
#   Dispatch actions sang probe_sqli.py và probe_ssti.py
#   KHÔNG gửi HTTP, KHÔNG probe — chỉ suy luận và phân loại
# ═══════════════════════════════════════════════════════════════

import json
import re
import logging
from collections import defaultdict
import ollama

from config import AI_SERVER, LLM_MODEL, TEMP_CLASSIFY, LOG_FILE

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [agent] %(message)s"
)

SYSTEM_PROMPT = """Bạn là chuyên gia pentest web application.
Nhiệm vụ: Phân tích danh sách endpoint và quyết định cách kiểm thử.

QUY TẮC:
- Chỉ test HAI loại: sqli và ssti
- KHÔNG test xss, csrf, jwt hay bất kỳ loại nào khác
- Mỗi action là 1 cặp (endpoint + param) cụ thể

PHÂN LOẠI sqli khi:
- param type_hint là "int" hoặc "integer_id" → rất likely SQLi
- param tên: id, news_id, category_id, user_id → SQLi
- param tên: q, search, keyword → có thể SQLi
- endpoint trả về JSON (response_type chứa "json") → backend query DB

PHÂN LOẠI ssti khi:
- param tên: content, message, bio, comment, author_name → free text → SSTI
- param là textarea (input_type: free_text) → SSTI
- param tên: name, subject → có thể SSTI nếu có template rendering

BỎ QUA:
- param: password, email (dạng validation)
- param: remember, sort (không liên quan SQL/template)
- endpoint /static/ không có PHP backend

OUTPUT: JSON THUẦN, không markdown, không text thừa:
{
  "actions": [
    {
      "type": "sqli_probe",
      "url": "/đường/dẫn",
      "param": "tên_param",
      "method": "GET",
      "reason": "lý do ngắn gọn"
    },
    {
      "type": "ssti_probe",
      "url": "/đường/dẫn",
      "param": "tên_param",
      "method": "POST",
      "reason": "lý do ngắn gọn"
    }
  ],
  "skipped": ["endpoint bỏ qua + lý do"],
  "reasoning": "tóm tắt chiến lược phân loại"
}"""


def _guess_input_type(name: str) -> str:
    n = name.lower()
    if n in {"id", "news_id", "category_id", "user_id", "post_id"}:
        return "integer_id"
    if n in {"content", "message", "bio", "comment", "description", "author_name"}:
        return "free_text"
    if n in {"q", "query", "keyword", "search"}:
        return "search_input"
    if n in {"name", "subject", "title", "author"}:
        return "text_field"
    return "unknown"


def _prepare_targets(inventory: list) -> list:
    """
    Đọc inventory.json và chuẩn bị data cho LLM.
    1. Lọc bỏ 404
    2. Dedup theo canonical_path + method
    3. Gộp params từ các entry trùng
    4. Build dict gọn, đủ context cho LLM phân loại
    """
    # Lọc 404
    valid = []
    for e in inventory:
        statuses = e.get("statuses", [])
        if not statuses or 200 in statuses:
            valid.append(e)

    # Dedup theo (method, canonical_path)
    groups = defaultdict(list)
    for e in valid:
        key = (
            e.get("method", "GET"),
            e.get("canonical_path", e.get("path", ""))
        )
        groups[key].append(e)

    targets = []
    for (method, path), entries in groups.items():
        params_map = {}
        forms_inputs = set()

        for entry in entries:
            for p in entry.get("params", []):
                name = p["name"]
                loc  = p.get("location", "")
                hint = p.get("type_hint", "unknown")
                samples = [
                    v for v in p.get("sample_values", [])
                    if v and "FUZZ" not in v
                    and "<script>" not in v
                    and "alert(" not in v
                ][:2]
                if name not in params_map:
                    params_map[name] = {
                        "name":       name,
                        "location":   loc,
                        "type_hint":  hint,
                        "samples":    samples,
                        "input_type": _guess_input_type(name)
                    }

            for form in entry.get("forms", []):
                for inp in form.get("inputs", []):
                    iname = inp.get("name", "")
                    itype = inp.get("type", "")
                    if iname:
                        forms_inputs.add((iname, itype))

        if not params_map and not forms_inputs:
            continue

        base = max(entries, key=lambda e: len(e.get("response_content_type", "")))
        resp_type = base.get("response_content_type", "")

        targets.append({
            "method":        method,
            "url":           path,
            "response_type": resp_type,
            "params":        list(params_map.values()),
            "form_inputs": [
                {"name": n, "html_type": t}
                for n, t in forms_inputs
            ]
        })

    logging.info(f"Chuẩn bị targets: {len(inventory)} entries → {len(targets)} endpoints")
    return targets


def _parse_llm_json(raw: str) -> dict:
    match = re.search(r'(\{.*\})', raw, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            pass
    for line in raw.splitlines():
        stripped = line.strip()
        if stripped.startswith("{"):
            try:
                obj = json.loads(stripped)
                if isinstance(obj, dict):
                    return obj
            except json.JSONDecodeError:
                continue
    logging.error(f"Không parse được JSON: {raw[:200]}")
    return {"actions": [], "skipped": [], "reasoning": "parse error"}


def classify_and_dispatch(inventory: list) -> list:
    """
    Main function: LLM phân loại endpoint từ inventory → dispatch probe.

    Args:
        inventory: list entries đọc thẳng từ inventory.json

    Returns:
        List probe results. Lưu vào probe_results.json.
    """
    from probe_sqli import run_sqli_probe
    from probe_ssti import run_ssti_probe

    targets = _prepare_targets(inventory)
    if not targets:
        print("[Agent] ⚠️  Không có endpoint nào có input")
        return []

    print(f"\n[Agent] Phân loại {len(targets)} endpoints...")
    print(f"        Model : {LLM_MODEL} @ {AI_SERVER}")

    client   = ollama.Client(host=AI_SERVER)
    user_msg = json.dumps(targets, ensure_ascii=False, indent=2)

    try:
        response = client.chat(
            model=LLM_MODEL,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user",   "content": user_msg}
            ],
            options={"temperature": TEMP_CLASSIFY}
        )
        raw = response["message"]["content"]
        logging.info(f"LLM output (200 chars): {raw[:200]}")
    except Exception as e:
        logging.error(f"LLM call thất bại: {e}")
        print(f"[Agent] ❌ Lỗi gọi LLM: {e}")
        return []

    result    = _parse_llm_json(raw)
    actions   = result.get("actions",   [])
    skipped   = result.get("skipped",   [])
    reasoning = result.get("reasoning", "")

    print(f"\n[Agent] Reasoning: {reasoning}")
    print(f"[Agent] → {len(actions)} actions:")
    for a in actions:
        print(f"          [{a.get('type','?').upper()[:4]}] "
              f"{a.get('url')} ?{a.get('param')} — {a.get('reason','')}")
    if skipped:
        print(f"[Agent] Bỏ qua: {len(skipped)} endpoints")

    probe_results = []
    for action in actions:
        atype = action.get("type", "")
        if atype == "sqli_probe":
            results = run_sqli_probe(action)
            probe_results.extend(results)
            logging.info(f"sqli {action['url']}: {len(results)} hits")
        elif atype == "ssti_probe":
            results = run_ssti_probe(action)
            probe_results.extend(results)
            logging.info(f"ssti {action['url']}: {len(results)} hits")
        else:
            logging.warning(f"Unknown action type: {atype}")

    with open("probe_results.json", "w", encoding="utf-8") as f:
        json.dump(probe_results, f, ensure_ascii=False, indent=2)

    print(f"\n[Agent] ✅ {len(probe_results)} hits → probe_results.json")
    logging.info(f"classify_and_dispatch: {len(probe_results)} probe results")
    return probe_results
