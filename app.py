import warnings
warnings.filterwarnings("ignore", category=UserWarning)

from datetime import datetime, timezone
import json
import os
import re
from pathlib import Path
import threading
import webbrowser
from uuid import uuid4

from flask import Flask, jsonify, render_template, request, redirect, url_for, session, flash, g
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.security import generate_password_hash, check_password_hash

from backend.detector import analyze_text, analyze_batch, backend_metadata
from backend.validation import (
    ValidationError,
    validate_payload,
    validate_text,
    validate_input_type,
    MAX_BATCH_ITEMS,
    MAX_TEXT_LENGTH,
)

app = Flask(
    __name__,
    template_folder="frontend/templates",
    static_folder="frontend/static",
    static_url_path="/static",
)
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024
# Local demo account system: users are stored in a JSON file (no SQL database).
# Set SCAMSHIELD_SECRET_KEY in the environment for a stable secret outside demos.
app.config["SECRET_KEY"] = os.environ.get("SCAMSHIELD_SECRET_KEY", "change-this-demo-secret-before-deployment")
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("SCAMSHIELD_HTTPS", "0") == "1"
USER_STORE = Path(__file__).resolve().parent / "data" / "accounts.json"
USER_STORE.parent.mkdir(parents=True, exist_ok=True)


def load_accounts():
    try:
        with USER_STORE.open("r", encoding="utf-8") as handle:
            value = json.load(handle)
        return value if isinstance(value, dict) else {}
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}


def save_accounts(accounts):
    USER_STORE.parent.mkdir(parents=True, exist_ok=True)
    temporary = USER_STORE.with_suffix(".tmp")
    with temporary.open("w", encoding="utf-8") as handle:
        json.dump(accounts, handle, indent=2)
    temporary.replace(USER_STORE)


def safe_user(record):
    return {"name": record.get("name", "User"), "email": record.get("email", "")}


@app.before_request
def load_current_user():
    email = session.get("user_email")
    record = load_accounts().get(email) if email else None
    g.current_user = safe_user(record) if record else None


@app.context_processor
def inject_current_user():
    return {"current_user": getattr(g, "current_user", None)}


@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Cache-Control"] = "no-store" if request.path.startswith("/api/") else "no-cache"
    return response


@app.errorhandler(RequestEntityTooLarge)
def too_large(_):
    return jsonify({
        "error": "Request is too large.",
        "max_request_bytes": app.config["MAX_CONTENT_LENGTH"],
    }), 413


@app.errorhandler(404)
def not_found(_):
    if request.path.startswith("/api/"):
        return jsonify({"error": "Endpoint not found."}), 404
    return render_template("index.html", error="Page not found."), 404


@app.errorhandler(Exception)
def unhandled(exc):
    if request.path.startswith("/api/"):
        return jsonify({
            "error": "Internal server error.",
            "request_id": getattr(request, "request_id", None),
        }), 500
    raise exc


@app.before_request
def attach_request_id():
    request.request_id = uuid4().hex[:12]


@app.after_request
def add_request_id(response):
    response.headers["X-Request-ID"] = request.request_id
    return response



@app.get("/login")
def login_page():
    if g.current_user:
        return redirect(url_for("account"))
    return render_template("auth.html", mode="login", page_name="Log in")


@app.post("/login")
def login_submit():
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    record = load_accounts().get(email)
    if not record or not check_password_hash(record.get("password_hash", ""), password):
        flash("Email or password is incorrect.", "error")
        return render_template("auth.html", mode="login", page_name="Log in", email=email), 401
    session.clear()
    session["user_email"] = email
    flash("You are now logged in.", "success")
    return redirect(url_for("account"))


@app.get("/register")
def register_page():
    if g.current_user:
        return redirect(url_for("account"))
    return render_template("auth.html", mode="register", page_name="Create account")


@app.post("/register")
def register_submit():
    name = request.form.get("name", "").strip()
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    confirm = request.form.get("confirm_password", "")
    if len(name) < 2 or len(name) > 80:
        flash("Name must be between 2 and 80 characters.", "error")
        return render_template("auth.html", mode="register", page_name="Create account", name=name, email=email), 400
    if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email) or len(email) > 254:
        flash("Enter a valid email address.", "error")
        return render_template("auth.html", mode="register", page_name="Create account", name=name, email=email), 400
    if len(password) < 8:
        flash("Password must be at least 8 characters.", "error")
        return render_template("auth.html", mode="register", page_name="Create account", name=name, email=email), 400
    if password != confirm:
        flash("Passwords do not match.", "error")
        return render_template("auth.html", mode="register", page_name="Create account", name=name, email=email), 400
    accounts = load_accounts()
    if email in accounts:
        flash("An account with this email already exists. Please log in.", "error")
        return render_template("auth.html", mode="register", page_name="Create account", name=name, email=email), 409
    accounts[email] = {"name": name, "email": email, "password_hash": generate_password_hash(password), "created_at": datetime.now(timezone.utc).isoformat()}
    save_accounts(accounts)
    session.clear()
    session["user_email"] = email
    flash("Account created successfully.", "success")
    return redirect(url_for("account"))


@app.get("/account")
def account():
    if not g.current_user:
        flash("Please log in to manage your account.", "error")
        return redirect(url_for("login_page"))
    return render_template("account.html", page_name="Manage account")


@app.post("/account")
def account_update():
    if not g.current_user:
        return redirect(url_for("login_page"))
    name = request.form.get("name", "").strip()
    if len(name) < 2 or len(name) > 80:
        flash("Name must be between 2 and 80 characters.", "error")
        return redirect(url_for("account"))
    email = session["user_email"]
    accounts = load_accounts()
    if email not in accounts:
        session.clear()
        return redirect(url_for("login_page"))
    accounts[email]["name"] = name
    save_accounts(accounts)
    flash("Your profile has been updated.", "success")
    return redirect(url_for("account"))


@app.post("/account/password")
def account_password_update():
    if not g.current_user:
        return redirect(url_for("login_page"))
    email = session["user_email"]
    accounts = load_accounts()
    record = accounts.get(email)
    old_password = request.form.get("current_password", "")
    new_password = request.form.get("new_password", "")
    confirm = request.form.get("confirm_password", "")
    if not record or not check_password_hash(record.get("password_hash", ""), old_password):
        flash("Current password is incorrect.", "error")
    elif len(new_password) < 8:
        flash("New password must be at least 8 characters.", "error")
    elif new_password != confirm:
        flash("New passwords do not match.", "error")
    else:
        record["password_hash"] = generate_password_hash(new_password)
        save_accounts(accounts)
        flash("Password changed successfully.", "success")
    return redirect(url_for("account"))


@app.post("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("home"))


@app.get("/")
def home():
    return render_template("index.html")


@app.post("/analyze")
def analyze():
    content = request.form.get("content", "")
    input_type = request.form.get("input_type", "message")
    try:
        result = analyze_text(content, input_type)
        return render_template("result.html", result=result, text=content)
    except ValidationError as exc:
        return render_template(
            "index.html", error=str(exc), previous=content
        ), 400


@app.post("/api/analyze")
def api_analyze():
    payload = request.get_json(silent=True) or {}
    try:
        content, input_type = validate_payload(payload)
        result = analyze_text(content, input_type)
        return jsonify({
            "success": True,
            "request_id": request.request_id,
            "result": result,
        })
    except ValidationError as exc:
        return jsonify({
            "success": False,
            "request_id": request.request_id,
            "error": str(exc),
        }), 400


@app.post("/api/analyze/batch")
def api_analyze_batch():
    payload = request.get_json(silent=True) or {}
    items = payload.get("items") if isinstance(payload, dict) else None

    if not isinstance(items, list):
        return jsonify({
            "success": False,
            "error": "items must be a JSON array.",
        }), 400

    if not items:
        return jsonify({
            "success": False,
            "error": "items cannot be empty.",
        }), 400

    if len(items) > MAX_BATCH_ITEMS:
        return jsonify({
            "success": False,
            "error": f"Maximum batch size is {MAX_BATCH_ITEMS}.",
        }), 400

    try:
        results = analyze_batch(items)
        return jsonify({
            "success": True,
            "request_id": request.request_id,
            "count": len(results),
            "results": results,
        })
    except (ValidationError, ValueError) as exc:
        return jsonify({
            "success": False,
            "request_id": request.request_id,
            "error": str(exc),
        }), 400


@app.get("/api/health")
def api_health():
    return jsonify({
        "status": "ok",
        "service": "ScamShield",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "request_id": request.request_id,
    })


@app.get("/health")
def health():
    return api_health()


@app.get("/api/model")
def api_model():
    return jsonify({
        "success": True,
        "metadata": backend_metadata(),
    })


@app.get("/api/scam-types")
def scam_types():
    meta = backend_metadata()
    return jsonify({"success": True, "scam_types": meta["scam_types"]})


@app.get("/api/stages")
def stages():
    meta = backend_metadata()
    return jsonify({"success": True, "stages": meta["stages"]})


@app.get("/history")
def history():
    return render_template("history.html")


@app.get("/analytics")
def analytics():
    return render_template("analytics.html")


@app.get("/guide")
def guide():
    return render_template("guide.html")


@app.get("/about")
def about():
    return render_template("about.html")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    is_cloud = bool(os.environ.get("PORT"))
    host = "0.0.0.0" if is_cloud else "127.0.0.1"
    url = f"http://127.0.0.1:{port}"

    if not is_cloud:
        try:
            threading.Timer(1.2, lambda: webbrowser.open(url)).start()
        except Exception:
            pass

    print("=" * 60)
    print("ScamShield is starting...")
    print(f"Open: {url}")
    print("Press CTRL+C to stop the server.")
    print("=" * 60)

    app.run(host=host, port=port, debug=False, use_reloader=False)
