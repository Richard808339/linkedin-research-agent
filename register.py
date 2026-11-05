"""Enregistrement de l'agent auprès d'un orchestrateur.

Reprend le protocole du lab : POST /register avec l'en-tête
`X-Orchestrator-Key`, puis un battement régulier pour rafraîchir `last_seen`.

Deux règles : aucune clé n'a de valeur par défaut, et rien de sensible n'est
écrit dans le journal — un secret journalisé est un secret publié.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
import urllib.error
import urllib.request

import security

LOG = logging.getLogger("register")
logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"),
                    format="%(asctime)s %(levelname)s %(name)s %(message)s")

AGENT_ID = os.environ.get("AGENT_ID", "linkedin-research-agent")
AGENT_NAME = os.environ.get("AGENT_NAME", "LinkedIn Research Agent")
CAPABILITIES = ["research", "web_search", "documentation", "summarization"]


def build_payload() -> dict:
    """Charge utile d'enregistrement — sans valeur inventée."""
    return {
        "agent_id": AGENT_ID,
        "name": AGENT_NAME,
        "endpoint": os.environ.get("AGENT_ENDPOINT", "http://127.0.0.1:9100"),
        "capabilities": CAPABILITIES,
        "sub_agents": [],
    }


def register_once(base: str, orch_key: str, payload: dict, timeout: float = 10.0) -> tuple[int, dict]:
    """Un enregistrement. L'URL de l'orchestrateur est validée comme les autres.

    `allow_private=True` est assumé : l'orchestrateur vit sur le réseau local.
    Le schéma et l'absence d'identifiants dans l'URL restent contrôlés.
    """
    base = security.validate_url(base, allow_private=True)
    request = urllib.request.Request(
        base.rstrip("/") + "/register",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "X-Orchestrator-Key": orch_key},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        body = response.read() or b"{}"
        try:
            parsed = json.loads(body)
        except ValueError:
            parsed = {}
        return response.status, parsed


def main() -> int:
    base = os.environ.get("ORCHESTRATOR_URL", "http://127.0.0.1:8000")
    try:
        orch_key = security.require_secret("ORCH_KEY", minimum_length=8)
    except security.MissingSecret as exc:
        print(f"[register] {exc}", file=sys.stderr)
        return 2
    heartbeat = float(os.environ.get("HEARTBEAT_SECONDS", "10"))
    payload = build_payload()

    print(f"[register] {AGENT_ID} -> {base} (battement {heartbeat:.0f}s)")
    while True:
        try:
            status, body = register_once(base, orch_key, payload)
            if status >= 300:
                security.log_safe(LOG, "register.refuse", status=status, reponse=body)
            else:
                LOG.info("register accepté (status=%s)", status)
        except security.UnsafeURL as exc:
            security.log_safe(LOG, "register.url_refusee", url=base, raison=str(exc))
            return 2
        except urllib.error.URLError as exc:
            # Orchestrateur éteint : on réessaie, sans crier, sans boucle serrée.
            LOG.info("orchestrateur injoignable (%s), nouvelle tentative", type(exc).__name__)
        except Exception as exc:  # noqa: BLE001
            LOG.info("échec d'enregistrement (%s)", type(exc).__name__)
        time.sleep(heartbeat)


if __name__ == "__main__":
    raise SystemExit(main())
