"""
scanner.py
Simple Web Vulnerability Scanner
Checks 5 vulnerability types
"""

import requests

# Disable SSL warnings
import urllib3
urllib3.disable_warnings()

# ── Risk scores for each severity ─────────────────────────────────────────────
SEVERITY_SCORE = {
    "Critical": 10,
    "High":     7,
    "Medium":   4,
    "Low":      2,
}

def get_response(url):
    """Send HTTP request to URL and return response."""
    try:
        response = requests.get(url, timeout=10, verify=False)
        return response
    except Exception:
        return None


# ── Check 1: Missing Security Headers ────────────────────────────────────────
def check_security_headers(url):
    """Check if important security headers are missing."""
    response = get_response(url)
    if not response:
        return None

    # List of important headers
    important_headers = [
        "x-frame-options",
        "content-security-policy",
        "x-xss-protection",
        "strict-transport-security",
    ]

    # Check which ones are missing
    missing = []
    for header in important_headers:
        if header not in response.headers:
            missing.append(header)

    if missing:
        return {
            "name":        "Missing Security Headers",
            "severity":    "High",
            "score":       SEVERITY_SCORE["High"],
            "description": f"Missing: {', '.join(missing)}",
            "fix":         "Add security headers to your web server configuration"
        }
    return None


# ── Check 2: SQL Injection ────────────────────────────────────────────────────
def check_sql_injection(url):
    """Check if website is vulnerable to SQL injection."""
    # SQL injection payload
    test_url = url + "?id=1'"

    response = get_response(test_url)
    if not response:
        return None

    # SQL error messages to look for
    sql_errors = [
        "sql syntax",
        "mysql_fetch",
        "warning: mysql",
        "unclosed quotation",
        "ora-",
    ]

    # Check if any SQL error appears in response
    body = response.text.lower()
    for error in sql_errors:
        if error in body:
            return {
                "name":        "SQL Injection",
                "severity":    "Critical",
                "score":       SEVERITY_SCORE["Critical"],
                "description": f"SQL error found in response: {error}",
                "fix":         "Use parameterized queries. Never put user input directly in SQL!"
            }
    return None


# ── Check 3: XSS ──────────────────────────────────────────────────────────────
def check_xss(url):
    """Check if website reflects XSS payloads."""
    # XSS test payload
    payload = "<script>alert('xss')</script>"
    test_url = url + "?q=" + payload

    response = get_response(test_url)
    if not response:
        return None

    # Check if payload appears in response without sanitization
    if payload in response.text:
        return {
            "name":        "XSS (Cross-Site Scripting)",
            "severity":    "High",
            "score":       SEVERITY_SCORE["High"],
            "description": "XSS payload reflected in response without sanitization",
            "fix":         "Sanitize all user input. Use Content Security Policy headers."
        }
    return None


# ── Check 4: Sensitive Files ──────────────────────────────────────────────────
def check_sensitive_files(url):
    """Check if sensitive files are publicly accessible."""
    # List of sensitive files to check
    sensitive_files = [
        "/.env",
        "/config.php",
        "/.git/config",
        "/backup.sql",
        "/phpinfo.php",
    ]

    for filepath in sensitive_files:
        test_url = url + filepath
        response = get_response(test_url)

        # If file exists and is accessible
        if response and response.status_code == 200:
            return {
                "name":        "Sensitive File Exposed",
                "severity":    "Critical",
                "score":       SEVERITY_SCORE["Critical"],
                "description": f"Sensitive file accessible: {filepath}",
                "fix":         "Remove or restrict access to sensitive files immediately!"
            }
    return None


# ── Check 5: Server Info ──────────────────────────────────────────────────────
def check_server_info(url):
    """Check if server version is exposed in headers."""
    response = get_response(url)
    if not response:
        return None

    server  = response.headers.get("Server", "")
    powered = response.headers.get("X-Powered-By", "")

    if server or powered:
        exposed = []
        if server:  exposed.append(f"Server: {server}")
        if powered: exposed.append(f"X-Powered-By: {powered}")
        return {
            "name":        "Server Info Exposed",
            "severity":    "Low",
            "score":       SEVERITY_SCORE["Low"],
            "description": f"Exposed: {', '.join(exposed)}",
            "fix":         "Hide server version info in web server configuration"
        }
    return None


# ── Main scan function ────────────────────────────────────────────────────────
def scan_website(url):
    """
    Run all 5 checks on the target URL.
    Returns a list of findings.
    """
    # Make sure URL starts with http
    if not url.startswith("http"):
        url = "https://" + url

    findings = []

    # Run each check
    print(f"Scanning {url}...")

    result = check_security_headers(url)
    if result:
        findings.append(result)
        print(f"  [!] {result['name']} — {result['severity']}")

    result = check_sql_injection(url)
    if result:
        findings.append(result)
        print(f"  [!] {result['name']} — {result['severity']}")

    result = check_xss(url)
    if result:
        findings.append(result)
        print(f"  [!] {result['name']} — {result['severity']}")

    result = check_sensitive_files(url)
    if result:
        findings.append(result)
        print(f"  [!] {result['name']} — {result['severity']}")

    result = check_server_info(url)
    if result:
        findings.append(result)
        print(f"  [!] {result['name']} — {result['severity']}")

    print(f"Scan complete! {len(findings)} issues found.")
    return url, findings