# ═══════════════════════════════════════════════════════════════
# dvwa_auth.py — Module tự động Login và Quản lý Session
# Đã cập nhật: Singleton cache — chỉ login 1 lần, tái dùng cookie
# ═══════════════════════════════════════════════════════════════

import httpx
from bs4 import BeautifulSoup
from config import TARGET_BASE_URL

# Singleton cache — tránh login 4 lần khi các module được import đồng thời
_cached_cookies: dict | None = None


def get_dvwa_cookies(force_refresh: bool = False) -> dict:
    """
    Tự động đăng nhập DVWA, ép Security=Low trên server và trả về Cookies dict.
    Kết quả được cache lại — chỉ thực sự login khi:
      - Lần đầu tiên gọi hàm này
      - Hoặc truyền force_refresh=True (khi session hết hạn)

    Được gọi tự động bởi Crawler, Probe, Bypass và Verify.
    """
    global _cached_cookies

    if _cached_cookies and not force_refresh:
        return _cached_cookies

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
            "Login":    "Login",
            "user_token": user_token
        })

        # 3. Gửi POST lên security.php để ép Backend PHP
        # lưu biến $_SESSION['security'] = 'low'
        client.post(security_url, data={
            "seclev_submit": "Submit",
            "security":      "low"
        })

        # 4. Xuất Cookie ra dạng Dictionary và lưu vào cache
        cookies = dict(client.cookies)
        cookies["security"] = "low"  # Giữ lại key này trong cookie cho chắc chắn

        _cached_cookies = cookies
        print("[Auth] ✅ Đã lấy Session DVWA + ép Security=Low trên Server thành công!")
        return _cached_cookies

    except Exception as e:
        print(f"[Auth] ❌ Lỗi Auto-Login DVWA: {e}")
        return {}


def invalidate_session() -> None:
    """
    Xoá cache cookie — dùng khi phát hiện session hết hạn
    (VD: response trả về trang login thay vì nội dung thật).
    Gọi hàm này rồi gọi lại get_dvwa_cookies() để login lại.
    """
    global _cached_cookies
    _cached_cookies = None
    print("[Auth] 🔄 Session cache đã được xoá, sẽ login lại ở lần gọi tiếp theo.")