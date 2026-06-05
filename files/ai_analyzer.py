# ═══════════════════════════════════════════════════════════════
# ai_analyzer.py — RAG + LLM phân tích probe results → findings
#
# Input : probe_results.json  (từ probe_tool.py)
# Output: findings.json
#
# Luồng mỗi probe:
#   probe dict
#     → tạo query từ type + url
#     → similarity_search ChromaDB → top 3 OWASP chunks
#     → build prompt: OWASP context + probe data
#     → LLM (qwen2.5-coder:14b) phân tích
#     → parse JSON output → finding dict
#     → merge probe + analysis → lưu findings.json
# ═══════════════════════════════════════════════════════════════

import json
import re
import logging
import ollama

from config import (
    AI_SERVER, LLM_MODEL,
    TEMP_ANALYZE, RAG_TOP_K,
    LOG_FILE
)
from rag_indexer import get_vectorstore

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [analyzer] %(message)s"
)

# ── Singleton ChromaDB ───────────────────────────────────────
# Load ChromaDB MỘT LẦN duy nhất — tái dùng cho toàn pipeline.
#
# Tại sao singleton?
# analyze_all() gọi analyze_one() N lần (N = số probe hits).
# Nếu mỗi lần tạo Chroma() mới → load index từ disk N lần → chậm.
# Singleton: load 1 lần (~2-3s), N lần sau trả về ngay (<0.1ms).
#
# bypass_loop.py cũng import _get_vs() để tái dùng cùng instance.
_vs = None


def _get_vs():
    """Trả về ChromaDB singleton — load từ disk nếu chưa có."""
    global _vs
    if _vs is None:
        print("[Analyzer] Đang load ChromaDB...")
        _vs = get_vectorstore()
        print("[Analyzer] ✅ ChromaDB loaded")
    return _vs


def _parse_llm_json(raw: str) -> dict:
    """
    Parse JSON từ LLM output.
    Dùng chung strategy với agent_classifier: regex DOTALL → line fallback.
    """
    # Strategy 1: tìm { ... } toàn bộ kể cả multiline
    match = re.search(r'(\{.*\})', raw, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            pass

    # Strategy 2: tìm dòng JSON hợp lệ
    for line in raw.splitlines():
        stripped = line.strip()
        if stripped.startswith("{"):
            try:
                obj = json.loads(stripped)
                if isinstance(obj, dict):
                    return obj
            except json.JSONDecodeError:
                continue

    logging.warning(f"Parse JSON fail: {raw[:200]}")
    return {}


def _build_analysis_prompt(probe: dict, context: str) -> str:
    """
    Xây dựng prompt phân tích từ OWASP context + probe data.

    Cấu trúc prompt:
        [OWASP Context]  ← 3 chunks liên quan nhất từ ChromaDB
        [Probe Result]   ← dữ liệu thực tế từ probe_tool
        [Yêu cầu]        ← output JSON schema

    Args:
        probe  : dict chứa type, url, param, payload, evidence
        context: chuỗi OWASP text từ RAG retrieval
    """
    return f"""OWASP Security Context (từ knowledge base):
{context}

---

Probe Result (bằng chứng thực tế từ target):
{json.dumps(probe, ensure_ascii=False, indent=2)}

---

Dựa trên OWASP context và bằng chứng probe trên, hãy phân tích lỗ hổng bảo mật.

Trả về JSON THUẦN (không markdown, không text thừa):
{{
  "severity": "Critical hoặc High hoặc Medium hoặc Low",
  "confidence": 0.0 đến 1.0,
  "vulnerability_class": "tên lớp lỗ hổng theo OWASP",
  "explanation": "giải thích chi tiết tại sao đây là lỗ hổng, cơ chế exploit",
  "impact": "tác động nếu bị khai thác",
  "exploit_payloads": ["payload1 cụ thể", "payload2 cụ thể"],
  "remediation": "hướng dẫn sửa lỗi cụ thể cho developer"
}}"""


def analyze_one(probe: dict) -> dict:
    """
    Phân tích một probe result bằng RAG + LLM.

    Quy trình:
        1. Tạo search query từ probe (type + url)
        2. Similarity search ChromaDB → top K chunks OWASP
        3. Nối chunks thành context string
        4. Build prompt = context + probe data
        5. Gọi LLM → parse JSON → merge với probe gốc

    Args:
        probe: dict từ probe_tool (type, url, param, payload, evidence, ...)

    Returns:
        probe dict được bổ sung thêm:
            severity, confidence, vulnerability_class,
            explanation, impact, exploit_payloads, remediation
    """
    vuln_type = probe.get("type", "unknown")
    url       = probe.get("url", "")
    param     = probe.get("param", "")

    # ── Bước 1: RAG retrieval ─────────────────────────────────
    # Query được thiết kế để tìm đúng loại vulnerability
    # ví dụ: "sqli /rest/products/search" → tìm chunks SQLi liên quan
    search_query = f"{vuln_type} {url} {param}"

    try:
        vs = _get_vs()
        docs = vs.similarity_search(search_query, k=RAG_TOP_K)
        # Nối các chunk thành một đoạn context
        context = "\n\n---\n\n".join(
            f"[Nguồn: {doc.metadata.get('source', 'OWASP')} "
            f"trang {doc.metadata.get('page', '?')}]\n{doc.page_content}"
            for doc in docs
        )
        logging.info(
            f"RAG search '{search_query}': {len(docs)} chunks retrieved"
        )
    except Exception as e:
        logging.warning(f"RAG search thất bại: {e} — dùng context rỗng")
        context = "Không có context OWASP — phân tích dựa trên probe data."

    # ── Bước 2: Build prompt ──────────────────────────────────
    prompt = _build_analysis_prompt(probe, context)

    # ── Bước 3: Gọi LLM ──────────────────────────────────────
    client = ollama.Client(host=AI_SERVER)

    try:
        response = client.chat(
            model=LLM_MODEL,
            messages=[{"role": "user", "content": prompt}],
            options={"temperature": TEMP_ANALYZE}
            # temperature=0.1: phân tích cần nhất quán
            # Chạy 2 lần với cùng probe phải cho severity giống nhau
        )
        raw_output = response["message"]["content"]
        logging.info(
            f"LLM analyze [{vuln_type}] {url}: "
            f"output {len(raw_output)} chars"
        )
    except Exception as e:
        logging.error(f"LLM analyze thất bại cho {url}: {e}")
        print(f"[Analyzer] ⚠️  LLM lỗi cho {url}: {e}")
        # Trả về probe gốc không có analysis — pipeline tiếp tục
        return {
            **probe,
            "severity":    "Unknown",
            "confidence":  0.0,
            "explanation": f"LLM call thất bại: {e}",
            "verified_by": "ai_error"
        }

    # ── Bước 4: Parse JSON output ─────────────────────────────
    analysis = _parse_llm_json(raw_output)

    if not analysis:
        logging.warning(f"Parse JSON fail cho {url} — dùng placeholder")
        analysis = {
            "severity":   "Unknown",
            "confidence": 0.0,
            "explanation": "Không parse được JSON từ LLM"
        }

    # ── Bước 5: Merge probe + analysis ───────────────────────
    # **probe: giữ tất cả field gốc (type, url, param, evidence...)
    # **analysis: thêm severity, confidence, exploit_payloads...
    finding = {
        **probe,
        **analysis,
        "verified_by": "ai"  # sẽ được verify lại ở verify.py
    }

    sev  = finding.get("severity", "?")
    conf = finding.get("confidence", 0)
    print(f"[Analyzer]   [{sev}] conf={conf:.2f}  {vuln_type} @ {url}")

    return finding


def analyze_all(probe_results: list) -> list:
    """
    Phân tích toàn bộ probe results.

    Args:
        probe_results: List probe dicts từ probe_tool.py

    Returns:
        List finding dicts (probe + analysis).
        Cũng lưu vào findings.json.
    """
    if not probe_results:
        print("[Analyzer] ⚠️  Không có probe result nào để phân tích")
        return []

    print(f"\n[Analyzer] Phân tích {len(probe_results)} probe results...")
    print(f"           Model : {LLM_MODEL} @ {AI_SERVER}")
    print(f"           RAG k : {RAG_TOP_K} chunks mỗi query")

    findings = []
    for i, probe in enumerate(probe_results, 1):
        print(f"\n[Analyzer] [{i}/{len(probe_results)}] "
              f"{probe.get('type','?').upper()} @ {probe.get('url','?')}")
        finding = analyze_one(probe)
        findings.append(finding)

    # ── Lưu findings.json ────────────────────────────────────
    with open("findings.json", "w", encoding="utf-8") as f:
        json.dump(findings, f, ensure_ascii=False, indent=2)

    confirmed_count = sum(
        1 for f in findings
        if f.get("confidence", 0) >= 0.7
    )
    print(f"\n[Analyzer] ✅ {len(findings)} findings → findings.json")
    print(f"           ({confirmed_count} có confidence >= 0.7)")
    logging.info(
        f"analyze_all done: {len(findings)} findings, "
        f"{confirmed_count} high confidence"
    )

    return findings
