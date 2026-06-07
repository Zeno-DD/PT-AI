# ═══════════════════════════════════════════════════════════════
# config.py — Cấu hình trung tâm toàn pipeline
# Chỉ cần sửa file này khi đổi IP / model / target
# ═══════════════════════════════════════════════════════════════

# ── AI Server (Windows 11) ───────────────────────────────────
AI_SERVER   = "http://26.104.46.75:11434"
LLM_MODEL   = "qwen2.5-coder:14b"
EMBED_MODEL = "nomic-embed-text"

# ── LLM Generation Options ───────────────────────────────────
# Mỗi task dùng temperature khác nhau — xem giải thích bên dưới
TEMP_CLASSIFY = 0.1   # Agent phân loại  → deterministic
TEMP_ANALYZE  = 0.1   # RAG phân tích    → nhất quán
TEMP_BYPASS   = 0.7   # Bypass loop      → sáng tạo, đa dạng
TEMP_VERIFY   = 0.0   # Verify           → maximum deterministic

# ── Target (Juice Shop — máy riêng trong LAN) ────────────────
JUICE_SHOP_URL = "http://192.168.0.104/DVWA/login.php"   # ← ĐỔI IP NÀY
TESTER_EMAIL   = "admin"
TESTER_PASS    = "password"

# ── RAG / ChromaDB (lưu local trên Kali) ─────────────────────
CHROMA_DIR      = "./chroma_db"
DOCS_DIR        = "./docs"
RAG_CHUNK_SIZE  = 1000   # ký tự mỗi chunk
RAG_CHUNK_OVERLAP = 150  # overlap giữa 2 chunk kề nhau
RAG_TOP_K       = 3      # số chunk trả về khi similarity search

# ── Bypass Loop ───────────────────────────────────────────────
BYPASS_MAX_ROUNDS = 5    # tối đa N vòng sinh payload bypass

# ── Logging ───────────────────────────────────────────────────
LOG_FILE  = "pipeline.log"
LOG_LEVEL = "INFO"
