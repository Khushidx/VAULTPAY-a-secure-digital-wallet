"""
Live HTTP Verification Script for Step 2 Authentication.

Performs live HTTP requests against the running Flask server:
1. Tests GET /register and extracts CSRF token.
2. Posts registration for a test student user.
3. Posts login with test credentials and stores session cookie.
4. Accesses protected /dashboard using session cookie.
5. Posts logout and verifies /dashboard is no longer accessible.
"""

import re
import sys
import urllib.request
import urllib.parse
import http.cookiejar

BASE_URL = "http://127.0.0.1:5000"

# Setup cookie jar for session tracking
cookie_jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookie_jar))


def get_csrf_token(html: str) -> str:
    match = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', html)
    if not match:
        raise ValueError("Could not find CSRF token in HTML response.")
    return match.group(1)


def run_verification():
    print("[1] Fetching registration page...")
    req = urllib.request.Request(f"{BASE_URL}/register")
    with opener.open(req) as resp:
        html = resp.read().decode("utf-8")
        assert resp.status == 200
        csrf_token = get_csrf_token(html)
        print("    Found CSRF token:", csrf_token[:16] + "...")

    print("[2] Registering new user 'live_student'...")
    reg_data = urllib.parse.urlencode({
        "csrf_token": csrf_token,
        "username": "live_student",
        "email": "live_student@college.edu",
        "password": "LivePassword123!",
        "confirm_password": "LivePassword123!",
    }).encode("utf-8")
    
    reg_req = urllib.request.Request(f"{BASE_URL}/register", data=reg_data, method="POST")
    with opener.open(reg_req) as resp:
        print("    Registration redirected to:", resp.geturl())
        login_html = resp.read().decode("utf-8")
        assert "Account created successfully" in login_html
        login_csrf = get_csrf_token(login_html)

    print("[3] Logging in as 'live_student'...")
    login_data = urllib.parse.urlencode({
        "csrf_token": login_csrf,
        "username_or_email": "live_student",
        "password": "LivePassword123!",
    }).encode("utf-8")
    
    login_req = urllib.request.Request(f"{BASE_URL}/login", data=login_data, method="POST")
    with opener.open(login_req) as resp:
        print("    Login redirected to:", resp.geturl())
        dash_html = resp.read().decode("utf-8")
        assert "Welcome, live_student!" in dash_html
        assert "Stored Cryptographic Record" in dash_html
        print("    Successfully reached protected Dashboard!")

    print("[4] Accessing protected /dashboard directly with active session...")
    dash_req = urllib.request.Request(f"{BASE_URL}/dashboard")
    with opener.open(dash_req) as resp:
        assert resp.status == 200
        headers = dict(resp.headers)
        assert "no-store" in headers.get("Cache-Control", "")
        print("    Cache-Control verified:", headers.get("Cache-Control"))

    print("[5] Logging out...")
    logout_req = urllib.request.Request(f"{BASE_URL}/logout")
    with opener.open(logout_req) as resp:
        home_html = resp.read().decode("utf-8")
        assert "successfully logged out" in home_html
        print("    Logged out successfully.")

    print("[6] Attempting to access /dashboard after logout...")
    try:
        dash_req2 = urllib.request.Request(f"{BASE_URL}/dashboard")
        with opener.open(dash_req2) as resp:
            # Should have redirected to /login
            assert "/login" in resp.geturl()
            print("    Correctly redirected to /login:", resp.geturl())
    except urllib.error.HTTPError as e:
        if e.code in (302, 401):
            print("    Correctly blocked after logout (code:", e.code, ")")
        else:
            raise

    print("\n[SUCCESS] All live manual verification checks passed!")


if __name__ == "__main__":
    run_verification()
