"""Unit tests for the deterministic parsing logic in avsa.modules.sqli.

These cover the pure helpers only — no live server is required. The live
end-to-end run against DVAI (the three primitives actually firing) is performed
separately by the user.
"""

from avsa.modules.sqli import has_sql_error_signature, is_login_success


# --- is_login_success -------------------------------------------------------

def test_login_success_302_to_chat():
    # DVAI's success signal: 302 with /chat in the Location.
    assert is_login_success(302, "/chat/1") is True


def test_login_failure_200_rerender():
    # Failed login re-renders the page with 200 and no redirect.
    assert is_login_success(200, "") is False


def test_login_redirect_elsewhere_is_not_success():
    # A 302 to /login (e.g. bounced) is not a successful login.
    assert is_login_success(302, "/login") is False


# --- has_sql_error_signature ------------------------------------------------

def test_error_signature_detected():
    body = (
        "<title>OperationalError</title>"
        "sqlite3.OperationalError: unrecognized token: \"'\""
    )
    assert has_sql_error_signature(body) is True


def test_no_error_signature_in_normal_login_page():
    body = (
        "<html><body><h1>Log in</h1>"
        "<form method='post'><input name='username'></form>"
        "<p>Invalid username or password.</p></body></html>"
    )
    assert has_sql_error_signature(body) is False
