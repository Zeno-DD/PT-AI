# ═══════════════════════════════════════════════════════════════
# check_connection.py — Kiểm tra AI Server trước khi chạy pipeline
#
# Chạy file này trước mọi thứ:
#   python check_connection.py
#
# Kiểm tra:
#   1. Kali có reach Windows 11 server không (HTTP)
#   2. Ollama đang chạy và lắng nghe đúng port không
#   3. Các model cần thiết đã pull chưa
# ═══════════════════════════════════════════════════════════════

import sys
import ollama
from config import AI_SERVER, LLM_MODEL, EMBED_MODEL


def check_server() -> bool:
    """
    Kết nối đến Ollama server và kiểm tra models.

    Returns:
        True nếu tất cả OK, False nếu có lỗi.
    """
    print(f"\n{'='*55}")
    print(f"  AI Server Check")
    print(f"  Target: {AI_SERVER}")
    print(f"{'='*55}")

    # ── Bước 1: Thử kết nối HTTP đến Ollama server ───────────
    try:
        client = ollama.Client(host=AI_SERVER)
        response = client.list()
        print(f"\n✅ Kết nối thành công: {AI_SERVER}")
    except Exception as e:
        print(f"\n❌ Không kết nối được đến server")
        print(f"   Lỗi: {e}")
        print(f"\n   Kiểm tra trên Windows 11:")
        print(f"   1. Get-Service Ollama  →  phải Running")
        print(f"   2. netstat -ano | findstr 11434  →  phải thấy 0.0.0.0:11434")
        print(f"   3. OLLAMA_HOST=0.0.0.0:11434 đã set chưa?")
        return False

    # ── Bước 2: Liệt kê models đang có ──────────────────────
    available = [m.model for m in response.get("models", [])]
    print(f"\n   Models trên server ({len(available)} total):")
    for name in available:
        print(f"   · {name}")

    # ── Bước 3: Kiểm tra từng model cần thiết ────────────────
    print()
    all_ok = True
    for model in [LLM_MODEL, EMBED_MODEL]:
        # So sánh tên model (có thể server trả về kèm tag như :latest)
        found = any(model in m for m in available)
        if found:
            print(f"   ✅ {model}")
        else:
            print(f"   ❌ {model}  →  chưa pull")
            print(f"      Chạy trên Windows 11: ollama pull {model}")
            all_ok = False

    # ── Bước 4: Thử inference nhanh với LLM ──────────────────
    if all_ok:
        print(f"\n   Thử inference với {LLM_MODEL}...")
        try:
            client.chat(
                model=LLM_MODEL,
                messages=[{"role": "user", "content": "Reply with: OK"}],
                options={"temperature": 0, "num_predict": 5}
            )
            print(f"   ✅ LLM inference OK")
        except Exception as e:
            print(f"   ⚠️  LLM inference lỗi: {e}")
            all_ok = False

    # ── Kết quả ───────────────────────────────────────────────
    print(f"\n{'='*55}")
    if all_ok:
        print(f"  ✅ Server sẵn sàng — có thể chạy pipeline")
    else:
        print(f"  ❌ Cần fix các lỗi trên trước khi chạy pipeline")
    print(f"{'='*55}\n")

    return all_ok


if __name__ == "__main__":
    ok = check_server()
    # Exit code 1 nếu có lỗi — tiện cho script automation
    sys.exit(0 if ok else 1)
