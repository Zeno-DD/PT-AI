import json
import sys
import os

from agent_classifier import classify_and_dispatch
from ai_analyzer      import analyze_all
from bypass_loop      import bypass_all
from verify           import verify_all

def main():
    # 👉 Ép hệ thống dùng chuẩn UTF-8 để không bị lỗi tiếng Việt hay icon
    sys.stdout.reconfigure(encoding='utf-8') 

    print("=" * 55)
    print("  🚀 KHỞI CHẠY AI SECURITY PIPELINE")
    print("=" * 55)

    # 1. Đọc file json truyền vào hoặc mặc định inventory.json
    file_path = sys.argv[1] if len(sys.argv) > 1 else "inventory.json"
    
    if not os.path.exists(file_path):
        print(f"\n❌ Lỗi: Không tìm thấy file '{file_path}'")
        print("Vui lòng kiểm tra lại thư mục hiện tại.\n")
        sys.exit(1)

    print(f"\n[1/5] Đang nạp cấu hình từ: {file_path}")
    with open(file_path, 'r', encoding='utf-8') as f:
        inventory = json.load(f)

    print("[2/5] Đang phân loại và điều phối Agent...")
    probes = classify_and_dispatch(inventory)
    
    print("[3/5] Đang phân tích lỗ hổng AI (RAG/Prompt)...")
    findings = analyze_all(probes)
    
    print("[4/5] Đang thực thi Bypass (Self-injection)...")
    findings = bypass_all(findings)
    
    print("[5/5] Đang xác thực kết quả...")
    verified = verify_all(findings) 
    
    print("\n📝 Đang xuất báo cáo tổng hợp...")
    # Lưu kết quả ra file JSON
    with open("verified_findings.json", "w", encoding="utf-8") as f:
        json.dump(verified, f, ensure_ascii=False, indent=2)

    # Đếm số lỗ hổng đã được xác nhận (đề phòng trường hợp is_confirmed không tồn tại)
    confirmed = sum(1 for f in verified if f.get("is_confirmed", False))
    
    print(f"\n{'='*55}")
    print(f"  ✅ Xong — {confirmed} lỗ hổng confirmed")
    print(f"  📄 Đã lưu vào: verified_findings.json")
    print(f"{'='*55}\n")

# Dòng này để đảm bảo hàm main() thực sự được gọi
if __name__ == "__main__":
    main()