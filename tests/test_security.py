import os
import re
import secrets
import sqlite3
import tempfile
import unittest
from contextlib import closing
from unittest.mock import patch

from app import create_app


class SecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.password = secrets.token_urlsafe(20)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = os.path.join(self.temp.name, "test.db")
        self.app = create_app({"TESTING": True, "SECRET_KEY": secrets.token_hex(32), "DATABASE": self.path, "SESSION_COOKIE_SECURE": False})
        self.client = self.app.test_client()
        for name in ("alice", "bob"):
            result = self.app.test_cli_runner().invoke(args=["create-user", name], input=f"{self.password}\n{self.password}\n")
            self.assertEqual(result.exit_code, 0, result.output)

    def token(self, client=None):
        client = client or self.client
        page = client.get("/login").get_data(as_text=True)
        return re.search(r'name="csrf_token" value="([^"]+)"', page).group(1)

    def login(self, name="alice", client=None, password=None):
        client = client or self.client
        return client.post("/login", data={"csrf_token": self.token(client), "username": name, "password": password or self.password})

    def post(self, url, **data):
        return self.client.post(url, data={"csrf_token": self.token(), **data})

    def test_health(self):
        self.assertEqual(self.client.get("/healthz").json, {"status": "ok"})

    def test_anonymous_redirected(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.location.endswith("/login"))

    def test_login_and_finding_lifecycle(self):
        self.assertEqual(self.login().status_code, 302)
        self.assertEqual(self.post("/findings", title="Review CSP", severity="high").status_code, 302)
        self.assertIn(b"Review CSP", self.client.get("/").data)
        self.assertEqual(self.post("/findings/1/resolve").status_code, 302)
        self.assertIn(b"resolved", self.client.get("/").data)

    def test_password_is_hashed(self):
        with closing(sqlite3.connect(self.path)) as db:
            value = db.execute("SELECT password_hash FROM users LIMIT 1").fetchone()[0]
        self.assertNotEqual(value, self.password)
        self.assertTrue(value.startswith("scrypt:"))

    def test_invalid_credentials(self):
        self.assertEqual(self.login(password="wrong").status_code, 401)
        self.assertEqual(self.login(name="unknown").status_code, 401)

    def test_login_requires_csrf(self):
        self.assertEqual(self.client.post("/login", data={"username": "alice", "password": self.password}).status_code, 400)

    def test_write_requires_csrf(self):
        self.login()
        self.assertEqual(self.client.post("/findings", data={"title": "A finding", "severity": "high"}).status_code, 400)

    def test_invalid_csrf_rejected(self):
        self.login()
        self.assertEqual(self.client.post("/logout", data={"csrf_token": "incorrect"}).status_code, 400)

    def test_csrf_rotated_on_login(self):
        old = self.token()
        self.login()
        self.assertNotEqual(old, self.token())
        self.assertEqual(self.client.post("/logout", data={"csrf_token": old}).status_code, 400)

    def test_logout_revokes_replayed_cookie(self):
        self.login()
        self.token()
        cookie = self.client.get_cookie("session").value
        self.assertEqual(self.post("/logout").status_code, 302)
        thief = self.app.test_client()
        thief.set_cookie("session", cookie)
        self.assertEqual(thief.get("/").status_code, 302)

    def test_cross_user_read_and_write_denied(self):
        self.login()
        self.post("/findings", title="Alice private issue", severity="critical")
        bob = self.app.test_client()
        self.login("bob", bob)
        self.assertNotIn(b"Alice private issue", bob.get("/").data)
        response = bob.post("/findings/1/resolve", data={"csrf_token": self.token(bob)})
        self.assertEqual(response.status_code, 404)
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute("SELECT status FROM findings WHERE id = 1").fetchone()[0], "open")

    def test_sql_injection_does_not_authenticate(self):
        self.assertEqual(self.login(name="alice' OR 1=1 --").status_code, 401)

    def test_html_is_escaped(self):
        self.login()
        self.post("/findings", title='<script>alert("x")</script>', severity="low")
        page = self.client.get("/").data
        self.assertNotIn(b"<script>", page)
        self.assertIn(b"&lt;script&gt;", page)

    def test_invalid_input(self):
        self.login()
        for title, severity in [("ab", "low"), ("x" * 121, "low"), ("Valid title", "urgent"), ("bad\ntitle", "low")]:
            with self.subTest(title=title, severity=severity):
                self.assertEqual(self.post("/findings", title=title, severity=severity).status_code, 400)

    def test_oversized_request(self):
        self.login()
        self.assertEqual(self.post("/findings", title="x" * 17000, severity="low").status_code, 413)

    def test_account_lockout_and_expiry(self):
        for _ in range(5):
            self.assertEqual(self.login(password="wrong").status_code, 401)
        self.assertEqual(self.login().status_code, 429)
        with patch("app.time.time", return_value=__import__("time").time() + 301):
            self.assertEqual(self.login().status_code, 302)

    def test_security_headers_on_success_and_error(self):
        for url in ("/login", "/missing"):
            response = self.client.get(url)
            self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
            self.assertEqual(response.headers["X-Frame-Options"], "DENY")
            self.assertIn("frame-ancestors 'none'", response.headers["Content-Security-Policy"])
            self.assertEqual(response.headers["Cache-Control"], "no-store")

    def test_cookie_flags(self):
        cookie = self.client.get("/login").headers["Set-Cookie"]
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Lax", cookie)
        self.app.config["SESSION_COOKIE_SECURE"] = True
        secure = self.app.test_client().get("/login")
        self.assertIn("Secure", secure.headers["Set-Cookie"])
        self.assertIn("Strict-Transport-Security", secure.headers)

    def test_untrusted_host_rejected(self):
        self.assertEqual(self.client.get("/healthz", headers={"Host": "attacker.invalid"}).status_code, 400)

    def test_mutation_routes_do_not_allow_get(self):
        self.login()
        for url in ("/logout", "/findings", "/findings/1/resolve"):
            self.assertEqual(self.client.get(url).status_code, 405)

    def test_startup_rejects_missing_secret(self):
        with self.assertRaises(RuntimeError):
            create_app({"SECRET_KEY": None, "DATABASE": self.path})

    def test_cli_rejects_weak_password_and_duplicate_user(self):
        runner = self.app.test_cli_runner()
        weak = runner.invoke(args=["create-user", "carol"], input="short\nshort\n")
        self.assertNotEqual(weak.exit_code, 0)
        duplicate = runner.invoke(args=["create-user", "alice"], input=f"{self.password}\n{self.password}\n")
        self.assertNotEqual(duplicate.exit_code, 0)


if __name__ == "__main__":
    unittest.main()
