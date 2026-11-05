"""Tests de l'API — serveur réel sur la boucle locale, aucune sortie externe.

Les adaptateurs sont remplacés par des doublures : ce qui est testé ici, c'est
la politique du service (jeton, liste blanche, CORS, non-divulgation), pas la
disponibilité de Wikipédia.
"""

from __future__ import annotations

import json
import os
import socket
import sys
import threading
import time
import unittest
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

# L'environnement doit être fixé AVANT l'import : la configuration est lue au
# chargement du module, et un service mal configuré refuse de démarrer.
os.environ.setdefault("API_KEY", "test-" + "k" * 32)
os.environ["BIND_HOST"] = "127.0.0.1"
os.environ["CORS_ORIGINS"] = "https://app.example.fr"
os.environ.pop("AUTH_ENABLED", None)
os.environ.pop("LINKEDIN_TOKEN", None)

import uvicorn  # noqa: E402

import research_agent  # noqa: E402

KEY = os.environ["API_KEY"]


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class ApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Doublures : aucune requête ne sort de la machine.
        research_agent.BACKENDS.update({
            "wikidata": lambda query, limit=5: [
                {"id": "Q42", "title": "Entité test", "description": "doublure",
                 "source": "wikidata", "url": "https://www.wikidata.org/wiki/Q42"}],
            "wikipedia": lambda title, lang="fr": {
                "title": title, "extract": "résumé de test",
                "source": f"wikipedia:{lang}", "url": "https://fr.wikipedia.org/wiki/X"},
            "linkedin": lambda query: {"available": False, "source": "linkedin:official",
                                       "reason": "doublure"},
        })
        cls.port = _free_port()
        config = uvicorn.Config(research_agent.app, host="127.0.0.1",
                                port=cls.port, log_level="warning")
        cls.server = uvicorn.Server(config)
        cls.thread = threading.Thread(target=cls.server.run, daemon=True)
        cls.thread.start()
        deadline = time.time() + 15
        while time.time() < deadline:
            try:
                with urllib.request.urlopen(
                        f"http://127.0.0.1:{cls.port}/health", timeout=1):
                    return
            except Exception:
                time.sleep(0.1)
        raise RuntimeError("le serveur de test n'a pas démarré")

    @classmethod
    def tearDownClass(cls):
        cls.server.should_exit = True
        cls.thread.join(timeout=5)

    # -- utilitaire ------------------------------------------------------
    def call(self, path: str, payload=None, key: str | None = KEY,
             origin: str | None = None):
        url = f"http://127.0.0.1:{self.port}{path}"
        data = json.dumps(payload).encode("utf-8") if payload is not None else None
        request = urllib.request.Request(url, data=data,
                                         method="POST" if data else "GET")
        if data:
            request.add_header("Content-Type", "application/json")
        if key:
            request.add_header("X-API-Key", key)
        if origin:
            request.add_header("Origin", origin)
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                return response.status, response.headers, response.read().decode()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.headers, exc.read().decode()

    # -- santé et capacités ---------------------------------------------
    def test_health_is_open_and_sober(self):
        status, _, body = self.call("/health", key=None)
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertEqual(payload["status"], "ok")
        self.assertEqual(payload["auth"], "required")
        self.assertNotIn(KEY, body)          # la sonde ne divulgue pas la clé

    def test_capabilities_require_key(self):
        self.assertEqual(self.call("/capabilities", key=None)[0], 401)
        self.assertEqual(self.call("/capabilities", key="mauvais-jeton")[0], 401)
        status, _, body = self.call("/capabilities")
        self.assertEqual(status, 200)
        self.assertIn("research", json.loads(body)["capabilities"])

    # -- recherche -------------------------------------------------------
    def test_research_requires_key(self):
        status, _, _ = self.call("/research", {"query": "Airbus"}, key=None)
        self.assertEqual(status, 401)
        status, _, _ = self.call("/research", {"query": "Airbus"}, key="mauvais-jeton")
        self.assertEqual(status, 401)

    def test_research_returns_sources(self):
        status, _, body = self.call("/research", {"query": "Airbus", "kind": "company"})
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertEqual(payload["agent_id"], research_agent.AGENT_ID)
        self.assertEqual(payload["errors"], [])
        self.assertEqual(payload["result_count"], 2)     # wikipedia + wikidata
        sources = {item["source"] for item in payload["results"]}
        self.assertEqual(sources, {"wikidata", "wikipedia:fr"})

    def test_research_does_not_echo_the_query(self):
        secret_query = "Jean Dupont ingénieur"
        _, _, body = self.call("/research", {"query": secret_query})
        # L'agent renvoie une empreinte, pas la question : une requête de
        # recherche sur une personne est une donnée personnelle.
        self.assertNotIn(secret_query, body)
        self.assertIn("query_sha256", body)

    def test_query_length_is_validated(self):
        status, _, _ = self.call("/research", {"query": "x" * 500})
        self.assertEqual(status, 422)

    # -- SSRF ------------------------------------------------------------
    def test_preview_blocks_metadata(self):
        status, _, body = self.call("/preview",
                                    {"url": "http://169.254.169.254/latest/meta-data/"})
        self.assertEqual(status, 403)
        self.assertIn("métadonnées", body)

    def test_preview_blocks_host_outside_allowlist(self):
        status, _, body = self.call("/preview", {"url": "https://example.com/secret"})
        self.assertEqual(status, 403)
        self.assertIn("liste autorisée", body)

    def test_preview_blocks_loopback(self):
        status, _, body = self.call("/preview", {"url": "http://127.0.0.1:22/"})
        self.assertEqual(status, 403)

    # -- CORS ------------------------------------------------------------
    def test_cors_allowed_origin_only(self):
        _, headers, _ = self.call("/health", key=None, origin="https://app.example.fr")
        self.assertEqual(headers.get("access-control-allow-origin"),
                         "https://app.example.fr")
        _, headers, _ = self.call("/health", key=None, origin="https://evil.example")
        self.assertIsNone(headers.get("access-control-allow-origin"))

    # -- débit -----------------------------------------------------------
    def test_rate_limit_window(self):
        identity = "unite-test-jeton"
        allowed = [research_agent._rate_ok(identity)
                   for _ in range(research_agent.RATE_LIMIT_PER_MINUTE)]
        self.assertTrue(all(allowed))
        self.assertFalse(research_agent._rate_ok(identity))


if __name__ == "__main__":
    unittest.main(verbosity=2)
