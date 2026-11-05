"""Tests des gardes — autonomie totale : ni réseau externe, ni secret réel.

Chaque test correspond à une constatation de l'audit. Les cas « refusé » sont
aussi importants que les cas « accepté » : une garde qui refuse tout ne protège
rien, elle casse le service et se fait désactiver.
"""

from __future__ import annotations

import logging
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import security as G


def fake_resolver(mapping: dict[str, list[str]]):
    def resolve(host: str, port: int) -> list[str]:
        if host not in mapping:
            raise OSError(f"nom inconnu: {host}")
        return mapping[host]
    return resolve


PUBLIC = fake_resolver({"safe.example": ["93.184.216.34"],
                        "internal.example": ["10.0.0.7"],
                        "mixed.example": ["93.184.216.34", "127.0.0.1"],
                        "v6.example": ["::1"]})


class SecretTests(unittest.TestCase):
    def test_absent_is_refused(self):
        with self.assertRaises(G.MissingSecret):
            G.require_secret("API_KEY", {})

    def test_empty_is_refused(self):
        with self.assertRaises(G.MissingSecret):
            G.require_secret("API_KEY", {"API_KEY": "   "})

    def test_placeholder_is_refused(self):
        for fake in ("changeme", "dev", "your_key_here", "xxx"):
            with self.subTest(fake=fake), self.assertRaises(G.MissingSecret):
                G.require_secret("API_KEY", {"API_KEY": fake})

    def test_too_short_is_refused(self):
        with self.assertRaises(G.MissingSecret):
            G.require_secret("API_KEY", {"API_KEY": "abc123"})

    def test_real_value_is_returned(self):
        value = "9f4c2b7e1a6d5c8f0b3e"
        self.assertEqual(G.require_secret("API_KEY", {"API_KEY": value}), value)


class AuthTests(unittest.TestCase):
    def test_enabled_by_default(self):
        with self.assertRaises(G.MissingSecret):
            # Auth active par défaut -> la clé devient obligatoire.
            G.auth_config({})

    def test_enabled_with_key(self):
        cfg = G.auth_config({"API_KEY": "k" * 32})
        self.assertTrue(cfg["enabled"])
        self.assertFalse(cfg["exposed"])

    def test_disabled_on_public_interface_is_refused(self):
        with self.assertRaises(G.InsecureConfig):
            G.auth_config({"AUTH_ENABLED": "0", "BIND_HOST": "0.0.0.0"})

    def test_disabled_on_loopback_is_allowed(self):
        cfg = G.auth_config({"AUTH_ENABLED": "0", "BIND_HOST": "127.0.0.1"})
        self.assertFalse(cfg["enabled"])
        self.assertFalse(cfg["exposed"])


class CorsTests(unittest.TestCase):
    def test_absent_means_no_third_party(self):
        self.assertEqual(G.cors_origins({}), [])

    def test_wildcard_is_refused(self):
        with self.assertRaises(G.InsecureConfig):
            G.cors_origins({"CORS_ORIGINS": "*"})

    def test_wildcard_with_credentials_is_refused(self):
        with self.assertRaises(G.InsecureConfig):
            G.cors_origins({"CORS_ORIGINS": "*", "CORS_ALLOW_CREDENTIALS": "1"})

    def test_explicit_list_is_normalised(self):
        origins = G.cors_origins({"CORS_ORIGINS": "https://app.example.fr/, https://admin.example.fr"})
        self.assertEqual(origins, ["https://app.example.fr", "https://admin.example.fr"])

    def test_invalid_origin_is_refused(self):
        with self.assertRaises(G.InsecureConfig):
            G.cors_origins({"CORS_ORIGINS": "app.example.fr"})


class UrlTests(unittest.TestCase):
    def test_scheme_and_userinfo(self):
        for bad in ("file:///etc/passwd", "ftp://example.com/x",
                    "gopher://example.com/", "http://user:pass@example.com/"):
            with self.subTest(url=bad), self.assertRaises(G.UnsafeURL):
                G.validate_url(bad)

    def test_literal_private_addresses_are_refused(self):
        for bad in ("http://127.0.0.1/", "http://10.1.2.3/", "http://172.16.0.9/",
                    "http://192.168.1.10/", "http://169.254.169.254/latest/meta-data/",
                    "http://0.0.0.0/", "http://[::1]/", "http://[fd00:ec2::254]/"):
            with self.subTest(url=bad), self.assertRaises(G.UnsafeURL):
                G.validate_url(bad)

    def test_name_resolving_to_private_is_refused(self):
        with self.assertRaises(G.UnsafeURL):
            G.validate_url("http://internal.example/", resolver=PUBLIC)

    def test_name_resolving_to_mixed_addresses_is_refused(self):
        # Une seule adresse privée suffit : le résolveur peut renvoyer l'autre.
        with self.assertRaises(G.UnsafeURL):
            G.validate_url("http://mixed.example/", resolver=PUBLIC)

    def test_name_resolving_to_ipv6_loopback_is_refused(self):
        with self.assertRaises(G.UnsafeURL):
            G.validate_url("http://v6.example/", resolver=PUBLIC)

    def test_public_name_is_accepted(self):
        url = G.validate_url("https://safe.example/path?q=1", resolver=PUBLIC)
        self.assertEqual(url, "https://safe.example/path?q=1")

    def test_allow_hosts_restricts(self):
        with self.assertRaises(G.UnsafeURL):
            G.validate_url("https://other.example/", resolver=PUBLIC,
                           allow_hosts=["safe.example"])

    def test_metadata_hostname_is_refused(self):
        with self.assertRaises(G.UnsafeURL):
            G.validate_url("http://metadata.google.internal/", resolver=PUBLIC)

    def test_allow_private_opt_in(self):
        self.assertEqual(G.validate_url("http://127.0.0.1:8080/x", allow_private=True),
                         "http://127.0.0.1:8080/x")


class _Redirector(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        if self.path == "/ok":
            body = b"contenu"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/vers-metadata":
            self.send_response(302)
            self.send_header("Location", "http://169.254.169.254/latest/meta-data/")
            self.end_headers()
            return
        if self.path == "/vers-interne":
            self.send_response(302)
            self.send_header("Location", "http://10.0.0.7/admin")
            self.end_headers()
            return
        self.send_response(404)
        self.end_headers()

    def log_message(self, *_args):  # silence
        return


class SafeGetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _Redirector)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_plain_fetch_works_on_loopback_when_allowed(self):
        url, status, body = G.safe_get(f"http://127.0.0.1:{self.port}/ok", allow_private=True)
        self.assertEqual(status, 200)
        self.assertEqual(body, b"contenu")
        self.assertTrue(url.endswith("/ok"))

    def test_loopback_refused_without_opt_in(self):
        with self.assertRaises(G.UnsafeURL):
            G.safe_get(f"http://127.0.0.1:{self.port}/ok")

    def test_redirect_to_metadata_is_refused(self):
        # La première cible est locale (autorisée exprès), la seconde ne l'est pas :
        # c'est exactement le contournement que le filtre doit arrêter.
        with self.assertRaises(G.UnsafeURL) as ctx:
            G.safe_get(f"http://127.0.0.1:{self.port}/vers-metadata", allow_private=True)
        self.assertIn("métadonnées", str(ctx.exception))

    def test_redirect_to_private_ip_is_refused(self):
        with self.assertRaises(G.UnsafeURL) as ctx:
            G.safe_get(f"http://127.0.0.1:{self.port}/vers-interne", allow_private=True)
        self.assertIn("non publique", str(ctx.exception))


class LogTests(unittest.TestCase):
    def test_redact_hides_value(self):
        secret = "sk-live-abcdef123456"
        masked = G.redact(secret)
        self.assertNotIn(secret, masked)
        self.assertIn("fp:", masked)
        self.assertTrue(masked.endswith(f":{len(secret)}"))

    def test_redact_is_stable(self):
        self.assertEqual(G.redact("abc"), G.redact("abc"))
        self.assertNotEqual(G.redact("abc"), G.redact("abd"))

    def test_empty_value(self):
        self.assertEqual(G.redact(None), "fp:empty:0")

    def test_log_safe_masks_secret_and_prompt(self):
        secret = "cle-refusee-tres-longue-123"
        prompt = "trouve le profil de Jean Dupont"
        with self.assertLogs("test", level="WARNING") as captured:
            G.log_safe(logging.getLogger("test"), "auth.refusee",
                       api_key=secret, prompt=prompt, ip="203.0.113.9")
        joined = "\n".join(captured.output)
        self.assertNotIn(secret, joined)
        self.assertNotIn(prompt, joined)
        self.assertIn("203.0.113.9", joined)


class BindTests(unittest.TestCase):
    def test_default_is_loopback(self):
        self.assertEqual(G.bind_host({}), "127.0.0.1")

    def test_public_bind_requires_explicit_flag(self):
        with self.assertRaises(G.InsecureConfig):
            G.bind_host({"BIND_HOST": "0.0.0.0"})

    def test_public_bind_allowed_when_declared(self):
        self.assertEqual(G.bind_host({"BIND_HOST": "0.0.0.0", "EXPOSE_PUBLIC": "1"}),
                         "0.0.0.0")


if __name__ == "__main__":
    unittest.main(verbosity=2)
