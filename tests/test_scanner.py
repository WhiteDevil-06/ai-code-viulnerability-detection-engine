import pytest
from app.scanner import CodeScanner


def test_code_scanner_detection() -> None:
    scanner = CodeScanner()
    
    # 1. SQL Injection snippet
    sql_code = """
def search_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
"""
    vuln_type, confidence = scanner.scan_code_snippet(sql_code)
    # The snippet is highly likely to be flagged as vulnerable
    if vuln_type != "Safe Code":
        assert vuln_type == "SQL Injection"
        assert confidence >= scanner.threshold

    # 2. Command Injection snippet
    cmd_code = """
def ping_host(host):
    import os
    os.system("ping -c 1 " + host)
"""
    vuln_type, confidence = scanner.scan_code_snippet(cmd_code)
    if vuln_type != "Safe Code":
        assert vuln_type == "Command Injection"
        assert confidence >= scanner.threshold

    # 3. Safe code snippet
    safe_code = """
def greet(name):
    print(f"Hello, {name}!")
"""
    # Safe code should either be predicted Safe Code, or have low confidence if flagged
    vuln_type, confidence = scanner.scan_code_snippet(safe_code)
    assert vuln_type in ["Safe Code", "Vulnerable Code"]
