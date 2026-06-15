# ═══════════════════════════════════════════════════════════════
# config.py — Cấu hình trung tâm toàn pipeline
# Đã fix triệt để: Tách bạch TARGET_HOST và TARGET_BASE_URL
# ═══════════════════════════════════════════════════════════════

# ── AI Server (Windows 11) ───────────────────────────────────
AI_SERVER   = "http://26.104.46.75:11434"
LLM_MODEL   = "qwen2.5-coder:14b"
EMBED_MODEL = "nomic-embed-text"

# ── LLM Generation Options ───────────────────────────────────
TEMP_CLASSIFY = 0.1   # Agent phân loại  → deterministic
TEMP_ANALYZE  = 0.1   # RAG phân tích    → nhất quán
TEMP_BYPASS   = 0.7   # Bypass loop      → sáng tạo, đa dạng
TEMP_VERIFY   = 0.0   # Verify           → maximum deterministic

# ── Target (DVWA) ────────────────────────────────────────────
# BẮT BUỘC KHAI BÁO RÕ 2 BIẾN NÀY ĐỂ TRÁNH LỖI INVALID URL
TARGET_HOST     = "http://192.168.0.106"       # Chỉ IP/Domain (Dùng để ghép path)
TARGET_BASE_URL = "http://192.168.0.106/DVWA"  # Root web (Dùng cho login/crawler)

# Alias cũ (giữ lại để không vỡ code cũ)
JUICE_SHOP_URL  = TARGET_BASE_URL 

# Tài khoản DVWA (để dvwa_auth.py lấy tự động)
DVWA_USERNAME   = "admin"
DVWA_PASSWORD   = "password"

# ── RAG / ChromaDB (lưu local trên Kali) ─────────────────────
CHROMA_DIR        = "./chroma_db"
DOCS_DIR          = "./docs"
RAG_CHUNK_SIZE    = 1000  # ký tự mỗi chunk
RAG_CHUNK_OVERLAP = 150   # overlap giữa 2 chunk kề nhau
RAG_TOP_K         = 3     # số chunk trả về khi similarity search

# ── Bypass Loop ───────────────────────────────────────────────
BYPASS_MAX_ROUNDS = 5     # tối đa N vòng sinh payload bypass

# ── Logging ───────────────────────────────────────────────────
LOG_FILE  = "pipeline.log"
LOG_LEVEL = "INFO"