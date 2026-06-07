# ... (Giữ nguyên các import và hằng số đầu file)

# [THÊM] Khai báo Cookie giống như trong các file probe
DVWA_COOKIES = {
    "PHPSESSID": "5eebef159783c02bbdee94932adc8b4e", 
    "security": "low"
}

def _rule_verify(finding: dict) -> tuple[bool, str]:
    url    = f"{JUICE_SHOP_URL}{finding['url']}" # Lưu ý: Đổi JUICE_SHOP_URL thành base URL của DVWA
    param  = finding["param"]
    method = finding.get("method", "GET")
    vuln   = finding.get("type", "sqli")

    payloads = finding.get("exploit_payloads", [])
    if not payloads and finding.get("payload"):
        payloads = [finding["payload"]]

    for payload in payloads:
        try:
            # Gửi request có kèm Cookie VÀ nút Submit
            params_data = {param: payload, "Submit": "Submit"}
            
            if method == "GET":
                r = httpx.get(url, params=params_data, cookies=DVWA_COOKIES, timeout=10, follow_redirects=True)
            else:
                r = httpx.post(url, data=params_data, cookies=DVWA_COOKIES, timeout=10, follow_redirects=True)

            if _rule_check_response(r.text, vuln):
                return True, "rule_based"
        except Exception as e:
            logging.warning(f"Rule verify lỗi: {e}")

    return False, "rule_based"

# ... (Phần _ai_verify và các hàm còn lại giữ nguyên)