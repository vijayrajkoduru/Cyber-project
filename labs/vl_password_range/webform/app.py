"""VL-METHOD Password Range — HTTP form login target.

Deterministic login form designed to exercise all 7 VL-METHOD stages of
the Patator HTTP form scanner:

  Stage 1 pre_flight     -> port 5000 reachable, HTTP 200 on /login
  Stage 2 fingerprint    -> Server: gunicorn header + Flask framework cookie
  Stage 3 quick_probe    -> admin/admin in default list -> HIT
                            (302 redirect + session cookie set)
  Stage 4 deep_scan      -> wordlist credentials tested (only admin/admin works)
  Stage 5 verify         -> second-request with session cookie hits /dashboard
                            -> 200 OK -> CONFIRMED
  Stage 6 privilege      -> /admin/users + /admin/settings return 200 with
                            session cookie -> classified as 'admin'
  Stage 7 chain_handoff  -> CONFIRMED admin -> suggests followup scanners

Single valid credential pair: admin / admin.
Anything else returns 401 with body "Invalid credentials" (fail_string).
"""
from flask import Flask, request, redirect, make_response, jsonify

app = Flask(__name__)

VALID_USER = "admin"
VALID_PASS = "admin"
SESSION_TOKEN = "vlmethod-session-abc123"

LOGIN_HTML = """<!doctype html>
<html><head><title>Login</title></head><body>
<h1>Sign in</h1>
<form method="POST" action="/login">
  <label>Username: <input name="username" type="text"></label><br>
  <label>Password: <input name="password" type="password"></label><br>
  <button type="submit">Login</button>
</form>
</body></html>"""


def _has_session():
    return request.cookies.get("session") == SESSION_TOKEN


@app.route("/")
def root():
    return redirect("/login")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return LOGIN_HTML, 200

    user = request.form.get("username", "")
    pwd = request.form.get("password", "")

    if user == VALID_USER and pwd == VALID_PASS:
        resp = make_response(redirect("/dashboard"))
        resp.set_cookie("session", SESSION_TOKEN, httponly=True)
        return resp

    return "Invalid credentials", 401


@app.route("/dashboard")
def dashboard():
    if not _has_session():
        return "Unauthorized", 401
    return "Welcome admin — you are logged in.", 200


@app.route("/admin/users")
def admin_users():
    if not _has_session():
        return "Unauthorized", 401
    return jsonify([
        {"id": 1, "username": "admin", "role": "admin"},
        {"id": 2, "username": "alice", "role": "user"},
        {"id": 3, "username": "bob", "role": "user"},
    ]), 200


@app.route("/admin/settings")
def admin_settings():
    if not _has_session():
        return "Unauthorized", 401
    return jsonify({
        "site_name": "VL-METHOD Password Range",
        "smtp_host": "smtp.local",
        "feature_flags": {"signup_open": True},
    }), 200


@app.route("/health")
def health():
    return "ok", 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
