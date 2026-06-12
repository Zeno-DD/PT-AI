# ═══════════════════════════════════════════════════════════════
# dvwa_auth.py — Module tự động Login và Quản lý Session
# Đã cập nhật: Ép Security Level = Low trên Server-side
# ═══════════════════════════════════════════════════════════════

import httpx
from bs4 import BeautifulSoup
from config import TARGET_BASE_URL

def get_dvwa_cookies() -> dict:
    """
    Tự động đăng nhập DVWA, ép Security=Low trên server và trả về Cookies dict.
    Được gọi tự động bởi Crawler, Probe, Bypass và Verify.
    """
    login_url    = f"{TARGET_BASE_URL}/login.php"
    security_url = f"{TARGET_BASE_URL}/security.php"
    
    # Khởi tạo client lưu phiên làm việc
    client = httpx.Client(timeout=10, follow_redirects=True)
    
    try:
        # 1. Truy cập trang login để lấy user_token (CSRF Token)
        r = client.get(login_url)
        soup = BeautifulSoup(r.text, "html.parser")
        token_input = soup.find("input", {"name": "user_token"})
        user_token = token_input["value"] if token_input else ""
        
        # 2. Gửi request POST đăng nhập
        client.post(login_url, data={
            "username": "admin", 
            "password": "password",
            "Login": "Login", 
            "user_token": user_token
        })
        
        # 3. CRITICAL FIX: Gửi POST lên trang security.php để ép Backend PHP
        # lưu biến $_SESSION['security'] = 'low'
        client.post(security_url, data={
            "seclev_submit": "Submit",
            "security": "low"
        })
        
        # 4. Xuất Cookie ra dạng Dictionary để các module httpx khác dùng chung
        cookies = dict(client.cookies)
        cookies["security"] = "low" # Giữ lại key này trong cookie cho chắc chắn
        
        print("[Auth] ✅ Đã lấy Session DVWA + ép Security=Low trên Server thành công!")
        return cookies
        
    except Exception as e:
        print(f"[!] Lỗi Auto-Login DVWA: {e}")
        return {}