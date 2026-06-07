# ═══════════════════════════════════════════════════════════════
# rag_indexer.py — Index OWASP docs vào ChromaDB
#
# Chỉ chạy 1 lần (qua setup.py).
# Lần sau pipeline tự skip nếu chroma_db/ đã tồn tại.
#
# Luồng:
#   docs/*.pdf
#     → PyPDFLoader đọc text từng trang
#     → RecursiveCharacterTextSplitter chia thành chunks
#     → OllamaEmbeddings gọi nomic-embed-text tại Windows 11
#     → ChromaDB lưu (text, vector) xuống ./chroma_db/
# ═══════════════════════════════════════════════════════════════

import os
import logging
from langchain_community.document_loaders import PyPDFLoader, TextLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_ollama import OllamaEmbeddings
from langchain_chroma import Chroma

from config import (
    AI_SERVER, EMBED_MODEL,
    CHROMA_DIR, DOCS_DIR,
    RAG_CHUNK_SIZE, RAG_CHUNK_OVERLAP,
    LOG_FILE
)

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [rag_indexer] %(message)s"
)


def _load_documents() -> list:
    """
    Đọc tất cả file trong docs/.
    Hỗ trợ: .pdf, .txt, .md

    Returns:
        List Document objects từ LangChain.
    """
    if not os.path.exists(DOCS_DIR):
        raise FileNotFoundError(
            f"Thư mục '{DOCS_DIR}' không tồn tại.\n"
            f"Tạo thư mục và đặt OWASP PDF vào đó:\n"
            f"  mkdir -p {DOCS_DIR}\n"
            f"  cp owasp-testing-guide.pdf {DOCS_DIR}/"
        )

    docs = []
    files = os.listdir(DOCS_DIR)

    if not files:
        raise ValueError(
            f"Thư mục '{DOCS_DIR}' rỗng.\n"
            f"Cần có ít nhất 1 file PDF/TXT chứa OWASP content."
        )

    for filename in sorted(files):
        filepath = os.path.join(DOCS_DIR, filename)

        # PDF — dùng PyPDFLoader (đọc từng trang)
        if filename.endswith(".pdf"):
            try:
                loader = PyPDFLoader(filepath)
                pages = loader.load()
                docs.extend(pages)
                logging.info(f"Loaded PDF: {filename} ({len(pages)} pages)")
                print(f"   📄 {filename}  ({len(pages)} trang)")
            except Exception as e:
                logging.warning(f"Không đọc được {filename}: {e}")
                print(f"   ⚠️  {filename}: {e}")

        # Text / Markdown — dùng TextLoader
        elif filename.endswith((".txt", ".md")):
            try:
                loader = TextLoader(filepath, encoding="utf-8")
                text_docs = loader.load()
                docs.extend(text_docs)
                logging.info(f"Loaded text: {filename}")
                print(f"   📝 {filename}")
            except Exception as e:
                logging.warning(f"Không đọc được {filename}: {e}")
                print(f"   ⚠️  {filename}: {e}")

    return docs


def _split_documents(docs: list) -> list:
    """
    Chia documents thành chunks nhỏ để embedding.

    Tại sao cần split?
    - Model embedding có giới hạn token đầu vào
    - Chunk nhỏ hơn → similarity search chính xác hơn
    - overlap 150 ký tự → không mất context ở ranh giới chunk

    Returns:
        List chunks (vẫn là Document objects, chỉ nhỏ hơn).
    """
    splitter = RecursiveCharacterTextSplitter(
        chunk_size=RAG_CHUNK_SIZE,       # mỗi chunk tối đa N ký tự
        chunk_overlap=RAG_CHUNK_OVERLAP, # phần overlap giữa 2 chunk liền nhau
        separators=["\n\n", "\n", ". ", " ", ""]
        # Thứ tự ưu tiên split: đoạn văn → dòng → câu → từ → ký tự
    )
    chunks = splitter.split_documents(docs)
    return chunks


def _build_embeddings():
    """
    Tạo embedding function — gọi nomic-embed-text tại Windows 11 server.

    nomic-embed-text biến text thành vector 768 chiều.
    Mỗi lần gọi: POST http://192.168.62.106:11434/api/embeddings
    Response: {"embedding": [0.12, -0.34, ...]}  # 768 floats
    """
    return OllamaEmbeddings(
        model=EMBED_MODEL,
        base_url=AI_SERVER  # http://192.168.62.106:11434
    )


def build_kb(force_rebuild: bool = False) -> None:
    """
    Build knowledge base từ docs/ vào ChromaDB.

    Args:
        force_rebuild: Nếu True → xóa chroma_db cũ và build lại.
                       Dùng khi thêm tài liệu mới vào docs/.

    Quy trình:
        1. Load tất cả file từ docs/
        2. Split thành chunks (1000 ký tự, overlap 150)
        3. Embed từng chunk qua nomic-embed-text (gọi Windows 11)
        4. Lưu (text + vector) vào ChromaDB local
    """
    print("\n[RAG] Build Knowledge Base")
    print(f"      Docs dir : {DOCS_DIR}")
    print(f"      ChromaDB : {CHROMA_DIR}")
    print(f"      Embed via: {AI_SERVER}")

    # ── Kiểm tra đã có ChromaDB chưa ─────────────────────────
    if not force_rebuild:
        if os.path.exists(CHROMA_DIR) and os.listdir(CHROMA_DIR):
            print("      ⚡ ChromaDB đã tồn tại — skip indexing")
            print("         (dùng force_rebuild=True nếu muốn build lại)")
            return

    # force_rebuild → xóa sạch trước
    if force_rebuild and os.path.exists(CHROMA_DIR):
        import shutil
        shutil.rmtree(CHROMA_DIR)
        print("      🗑  ChromaDB cũ đã xóa")

    # ── Bước 1: Load documents ───────────────────────────────
    print("\n   Đang đọc tài liệu...")
    docs = _load_documents()
    print(f"   → {len(docs)} trang/sections đã đọc")

    # ── Bước 2: Split thành chunks ───────────────────────────
    print("\n   Đang chia thành chunks...")
    chunks = _split_documents(docs)
    print(f"   → {len(chunks)} chunks (size={RAG_CHUNK_SIZE}, overlap={RAG_CHUNK_OVERLAP})")

    # ── Bước 3 + 4: Embed và lưu vào ChromaDB ────────────────
    print(f"\n   Đang embed qua {EMBED_MODEL}...")
    print(f"   (Gọi {AI_SERVER} — có thể mất vài phút)")

    embeddings = _build_embeddings()

    # Chroma.from_documents() làm 3 việc:
    # a) Với mỗi chunk → gọi nomic-embed-text → 768-dim vector
    # b) Lưu (text, vector, metadata) vào SQLite + HNSW index
    # c) Persist xuống disk tại CHROMA_DIR
    Chroma.from_documents(
        documents=chunks,
        embedding=embeddings,
        persist_directory=CHROMA_DIR
    )

    print(f"\n   ✅ ChromaDB đã build: {len(chunks)} chunks → {CHROMA_DIR}/")
    logging.info(f"ChromaDB built: {len(chunks)} chunks từ {len(docs)} documents")


def get_vectorstore():
    """
    Load ChromaDB đã có từ disk.
    Dùng trong ai_analyzer.py và bypass_loop.py (qua singleton).

    Returns:
        Chroma vectorstore instance sẵn sàng để similarity_search().
    """
    if not os.path.exists(CHROMA_DIR):
        raise RuntimeError(
            "ChromaDB chưa được build.\n"
            "Chạy: python setup.py"
        )
    embeddings = _build_embeddings()
    return Chroma(
        persist_directory=CHROMA_DIR,
        embedding_function=embeddings
    )


if __name__ == "__main__":
    # Chạy trực tiếp để test: python rag_indexer.py
    build_kb()
