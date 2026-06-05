# ═══════════════════════════════════════════════════════════════

# setup.py — Chạy MỘT LẦN trước khi dùng pipeline lần đầu
#
# Làm 2 việc:
#   1. Kiểm tra kết nối AI Server (Windows 11)
#   2. Build RAG knowledge base từ docs/ → chroma_db/
#
# Sau khi setup.py chạy xong thành công:
#   → chạy run_all.py bình thường, không cần setup lại
#
# Nếu thêm tài liệu mới vào docs/:
#   → chạy lại: python setup.py --rebuild
# ═══════════════════════════════════════════════════════════════

import sys
sys.stdout.reconfigure(encoding='utf-8')
from check_connection import check_server
from rag_indexer import build_kb


def setup(force_rebuild: bool = False) -> None:
    """
    Quy trình setup một lần:
        1. Verify AI server sẵn sàng
        2. Build ChromaDB từ OWASP docs

    Args:
        force_rebuild: Xóa chroma_db cũ và build lại.
    """
    print("=" * 55)
    print("  SETUP — AI Security Testing Pipeline")
    print("=" * 55)

    # ── Bước 1: Kiểm tra AI Server ───────────────────────────
    print("\n[1/2] Kiểm tra AI Server...")
    ok = check_server()
    if not ok:
        print("\n❌ Setup thất bại — fix lỗi server trước.")
        sys.exit(1)

    # ── Bước 2: Build RAG Knowledge Base ─────────────────────
    print("\n[2/2] Build RAG Knowledge Base...")
    build_kb(force_rebuild=force_rebuild)

    # ── Xong ─────────────────────────────────────────────────
    print("\n" + "=" * 55)
    print("  ✅ Setup hoàn tất — sẵn sàng chạy run_all.py")
    print("=" * 55 + "\n")


if __name__ == "__main__":
    # python setup.py          → setup bình thường (skip nếu chroma_db/ đã có)
    # python setup.py --rebuild → xóa chroma_db cũ và build lại
    rebuild = "--rebuild" in sys.argv
    if rebuild:
        print("⚠️  Chế độ rebuild — ChromaDB cũ sẽ bị xóa")
    setup(force_rebuild=rebuild)
