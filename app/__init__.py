"""Gatehouse: a small application for practicing security delivery gates."""
import os
import re
import secrets
import sqlite3
import time
from datetime import timedelta
from functools import wraps
from pathlib import Path

import click
from flask import Flask, abort, flash, g, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.exceptions import SecurityError


def create_app(config=None):
    app = Flask(__name__)
    production = os.environ.get("APP_ENV") == "production"
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("SECRET_KEY"),
        DATABASE=os.environ.get("DATABASE", str(Path(app.instance_path) / "gatehouse.db")),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=production,
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
        SESSION_REFRESH_EACH_REQUEST=False,
        MAX_CONTENT_LENGTH=16 * 1024,
        TRUSTED_HOSTS=os.environ.get("TRUSTED_HOSTS", "localhost,127.0.0.1").split(","),
    )
    if config:
        app.config.update(config)
    if not app.config["SECRET_KEY"] or len(app.config["SECRET_KEY"]) < 32:
        raise RuntimeError("Set SECRET_KEY to at least 32 random characters. See README.md.")
    Path(app.config["DATABASE"]).parent.mkdir(parents=True, exist_ok=True)

    def db():
        if "db" not in g:
            g.db = sqlite3.connect(app.config["DATABASE"], timeout=10)
            g.db.row_factory = sqlite3.Row
            g.db.execute("PRAGMA foreign_keys = ON")
        return g.db

    @app.teardown_appcontext
    def close_db(error=None):
        connection = g.pop("db", None)
        if connection:
            connection.close()

    with app.app_context():
        db().executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL, version INTEGER NOT NULL DEFAULT 0,
                failures INTEGER NOT NULL DEFAULT 0, locked_until REAL NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY, owner_id INTEGER NOT NULL REFERENCES users(id),
                title TEXT NOT NULL, severity TEXT NOT NULL CHECK(severity IN ('low','medium','high','critical')),
                status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open','resolved')),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
        """)

    # Equal-cost password checks for unknown users; never a usable account.
    dummy_hash = generate_password_hash(secrets.token_urlsafe(32))

    def csrf_token():
        if "csrf" not in session:
            session["csrf"] = secrets.token_urlsafe(32)
        return session["csrf"]

    app.jinja_env.globals["csrf_token"] = csrf_token

    @app.before_request
    def protect_request():
        g.user = None
        if "user_id" in session:
            user = db().execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
            if user and user["version"] == session.get("version"):
                g.user = user
            else:
                session.clear()
        if request.method == "POST":
            expected = session.get("csrf", "")
            actual = request.form.get("csrf_token", "")
            if not expected or not secrets.compare_digest(expected, actual):
                abort(400, "Invalid or missing CSRF token. Reload the page and try again.")

    @app.after_request
    def security_headers(response):
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; style-src 'self'; img-src 'self'; "
            "form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Cache-Control"] = "no-store"
        if app.config["SESSION_COOKIE_SECURE"]:
            response.headers["Strict-Transport-Security"] = "max-age=31536000"
        return response

    def login_required(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if g.user is None:
                return redirect(url_for("login"))
            return view(*args, **kwargs)
        return wrapped

    @app.get("/healthz")
    def health():
        return {"status": "ok"}

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            username = request.form.get("username", "").strip().lower()
            password = request.form.get("password", "")
            user = db().execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
            valid = check_password_hash(user["password_hash"] if user else dummy_hash, password)
            now = time.time()
            if user and user["locked_until"] > now:
                return render_template("login.html", error="Sign-in unavailable. Try again later."), 429
            if user and valid:
                db().execute("UPDATE users SET failures = 0, locked_until = 0 WHERE id = ?", (user["id"],))
                db().commit()
                session.clear()
                session.permanent = True
                session["user_id"] = user["id"]
                session["version"] = user["version"]
                return redirect(url_for("index"))
            if user:
                # Atomic increment also covers simultaneous failed requests.
                db().execute("UPDATE users SET failures = CASE WHEN locked_until > 0 THEN 1 ELSE failures + 1 END, locked_until = 0 WHERE id = ?", (user["id"],))
                db().execute("UPDATE users SET locked_until = ? WHERE id = ? AND failures >= 5", (now + 300, user["id"]))
                db().commit()
            return render_template("login.html", error="Invalid username or password."), 401
        return render_template("login.html")

    @app.post("/logout")
    @login_required
    def logout():
        # Revoke previously copied cookies as well as clearing this browser.
        db().execute("UPDATE users SET version = version + 1 WHERE id = ?", (g.user["id"],))
        db().commit()
        session.clear()
        return redirect(url_for("login"))

    @app.get("/")
    @login_required
    def index():
        findings = db().execute("SELECT * FROM findings WHERE owner_id = ? ORDER BY id DESC", (g.user["id"],)).fetchall()
        return render_template("index.html", findings=findings,
                               open_count=sum(f["status"] == "open" for f in findings),
                               critical_count=sum(f["severity"] == "critical" and f["status"] == "open" for f in findings))

    @app.post("/findings")
    @login_required
    def add_finding():
        title = request.form.get("title", "").strip()
        severity = request.form.get("severity", "")
        if not 3 <= len(title) <= 120 or any(ord(c) < 32 for c in title):
            abort(400, "Title must contain 3-120 characters without control characters.")
        if severity not in {"low", "medium", "high", "critical"}:
            abort(400, "Choose a valid severity.")
        db().execute("INSERT INTO findings(owner_id, title, severity) VALUES (?, ?, ?)", (g.user["id"], title, severity))
        db().commit()
        flash("Finding added to your queue.")
        return redirect(url_for("index"))

    @app.post("/findings/<int:finding_id>/resolve")
    @login_required
    def resolve(finding_id):
        result = db().execute("UPDATE findings SET status = 'resolved' WHERE id = ? AND owner_id = ?", (finding_id, g.user["id"]))
        if result.rowcount == 0:
            abort(404)
        db().commit()
        flash("Finding resolved.")
        return redirect(url_for("index"))

    @app.errorhandler(400)
    @app.errorhandler(404)
    @app.errorhandler(413)
    def friendly_error(error):
        # Host validation can fail before Flask creates a URL adapter.
        if isinstance(error, SecurityError):
            return "Bad request.", 400
        return render_template("error.html", error=error), error.code

    @app.cli.command("create-user")
    @click.argument("username")
    @click.password_option(confirmation_prompt=True)
    def create_user(username, password):
        """Create a local account without putting a password in shell history."""
        username = username.strip().lower()
        if not re.fullmatch(r"[a-z0-9_-]{3,32}", username):
            raise click.ClickException("Use 3-32 lowercase letters, digits, underscores or hyphens.")
        if not 12 <= len(password) <= 128:
            raise click.ClickException("Use a password of 12-128 characters.")
        try:
            db().execute("INSERT INTO users(username, password_hash) VALUES (?, ?)", (username, generate_password_hash(password)))
            db().commit()
        except sqlite3.IntegrityError:
            raise click.ClickException("Username already exists.") from None
        click.echo(f"Created {username}.")

    return app
