"""Agent de recherche — sources publiques, jamais de scraping LinkedIn.

Ce service existe pour répondre à une question précise : « que sait-on
publiquement de cette entreprise ou de cette personne ? ». Il interroge
Wikidata et Wikipédia, et l'API officielle LinkedIn **si et seulement si** un
jeton autorisé est fourni par l'exploitant. Il n'extrait pas de pages LinkedIn :
le faire violerait les conditions d'utilisation du site et exposerait le projet
autant que la personne qui l'exécute.

Les protections ne sont pas décoratives : interdiction de démarrer sans jeton
d'API, sorties réseau filtrées, journaux qui ne conservent ni clé ni requête en
clair, écoute en boucle locale par défaut.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import threading
import time
import urllib.parse
from typing import Any, Callable

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

import security

# --------------------------------------------------------------------------
# Identification de l'agent
# --------------------------------------------------------------------------
VERSION = "1.0.0"
AGENT_ID = os.environ.get("AGENT_ID", "linkedin-research-agent")
AGENT_NAME = os.environ.get("AGENT_NAME", "LinkedIn Research Agent")
CAPABILITIES = ["research", "web_search", "documentation", "summarization"]

# Domaines joignables. Toute autre destination est refusée, y compris une IP
# littérale : une liste d'hôtes est plus étroite qu'un filtre d'IP, et c'est
# exactement ce qu'on veut pour un agent qui va chercher des pages.
ALLOWED_SOURCE_HOSTS = [
    host.strip()
    for host in os.environ.get(
        "ALLOWED_SOURCE_HOSTS",
        "www.wikidata.org,fr.wikipedia.org,en.wikipedia.org,api.linkedin.com",
    ).split(",")
    if host.strip()
]

LOG = logging.getLogger("research_agent")
logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)

# La configuration est lue au chargement : si elle est inacceptable, le module
# refuse d'exister et le serveur ne démarre pas. Un service qui démarre puis
# renvoie 500 à la première requête n'est pas « configuré sans auth », il est
# cassé.
CONFIG = security.auth_config()
API_KEY: str = CONFIG["api_key"] or ""
ENFORCE_AUTH: bool = CONFIG["enabled"]
BIND = security.bind_host()
PORT = int(os.environ.get("PORT", "9100"))
CORS_ALLOWED = security.cors_origins()

# Limite de débit : un agent qui interroge des sources externes doit se limiter
# lui-même, sinon une boucle côté appelant devient une boucle côté fournisseur.
RATE_LIMIT_PER_MINUTE = int(os.environ.get("RATE_LIMIT_PER_MINUTE", "30"))
MAX_QUERY_LENGTH = int(os.environ.get("MAX_QUERY_LENGTH", "160"))

app = FastAPI(title=AGENT_NAME, version=VERSION,
              description="Recherche sur sources publiques, sans scraping LinkedIn.")

if CORS_ALLOWED:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=CORS_ALLOWED,
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["content-type", "x-api-key"],
    )

# --------------------------------------------------------------------------
# Authentification et débit
# --------------------------------------------------------------------------
_rate_state: dict[str, list[float]] = {}
_rate_lock = threading.Lock()


def _rate_ok(identity: str) -> bool:
    """Fenêtre glissante d'une minute, par identité (ici l'empreinte du jeton)."""
    now = time.monotonic()
    with _rate_lock:
        stamps = [t for t in _rate_state.get(identity, []) if now - t < 60.0]
        if len(stamps) >= RATE_LIMIT_PER_MINUTE:
            _rate_state[identity] = stamps
            return False
        stamps.append(now)
        _rate_state[identity] = stamps
    return True


def require_key(x_api_key: str | None = Header(default=None, alias="X-API-Key")) -> str:
    """Dépendance d'authentification, appliquée par défaut sur les routes métier."""
    if not ENFORCE_AUTH:                       # seulement possible en boucle locale
        return "loopback"
    if not x_api_key:
        security.log_safe(LOG, "auth.refusee", api_key=None, raison="absent")
        raise HTTPException(status_code=401, detail="jeton d'API requis")
    if not hmac.compare_digest(x_api_key, API_KEY):
        # L'empreinte permet de corréler deux refus sans écrire la clé reçue.
        security.log_safe(LOG, "auth.refusee", api_key=x_api_key, raison="invalide")
        raise HTTPException(status_code=401, detail="jeton d'API invalide")
    if not _rate_ok(security.redact(x_api_key)):
        raise HTTPException(status_code=429, detail="trop de requêtes, réessayez dans une minute")
    return x_api_key


# --------------------------------------------------------------------------
# Adaptateurs de sources
# --------------------------------------------------------------------------
def _get_json(url: str, timeout: float = 10.0) -> dict[str, Any]:
    """GET contrôlé : hôte en liste blanche, redirections revalidées."""
    final_url, status, body = security.safe_get(
        url, allow_hosts=ALLOWED_SOURCE_HOSTS, timeout=timeout, max_bytes=1_000_000
    )
    if status != 200:
        raise HTTPException(status_code=502, detail=f"source {final_url} a répondu {status}")
    try:
        return json.loads(body.decode("utf-8", "replace"))
    except ValueError as exc:
        raise HTTPException(status_code=502, detail="réponse de source illisible") from exc


def wikidata_search(query: str, limit: int = 5) -> list[dict[str, Any]]:
    """Recherche d'entités (entreprises, personnes) dans Wikidata."""
    url = (
        "https://www.wikidata.org/w/api.php?action=wbsearchentities&format=json"
        f"&language=fr&uselang=fr&limit={int(limit)}&search={urllib.parse.quote(query)}"
    )
    data = _get_json(url)
    results = []
    for item in data.get("search", []):
        results.append({
            "id": item.get("id"),
            "title": item.get("label"),
            "description": item.get("description"),
            "source": "wikidata",
            "url": item.get("concepturi") or f"https://www.wikidata.org/wiki/{item.get('id')}",
        })
    return results


def wikipedia_summary(title: str, lang: str = "fr") -> dict[str, Any]:
    """Résumé d'un article Wikipédia (API REST officielle, sans scraping HTML)."""
    if lang not in {"fr", "en"}:
        raise HTTPException(status_code=400, detail="langue non prise en charge")
    url = (
        f"https://{lang}.wikipedia.org/api/rest_v1/page/summary/"
        f"{urllib.parse.quote(title.replace(' ', '_'))}"
    )
    data = _get_json(url)
    return {
        "title": data.get("title"),
        "extract": data.get("extract"),
        "source": f"wikipedia:{lang}",
        "url": (data.get("content_urls") or {}).get("desktop", {}).get("page"),
    }


def linkedin_official(query: str) -> dict[str, Any]:
    """Recherche via l'API LinkedIn officielle — uniquement si un jeton est fourni.

    Le projet ne scrape pas LinkedIn. Sans jeton autorisé, l'adaptateur le dit au
    lieu de contourner la limite.
    """
    token = (os.environ.get("LINKEDIN_TOKEN") or "").strip()
    if not token:
        return {
            "available": False,
            "source": "linkedin:official",
            "reason": "LINKEDIN_TOKEN absent : la recherche LinkedIn n'est pas activée "
                      "(et le scraping n'est pas une option)",
        }
    url = ("https://api.linkedin.com/v2/adLibrarySearch?q=criteria"
           f"&keyword={urllib.parse.quote(query)}")
    try:
        final_url, status, body = security.safe_get(
            url, allow_hosts=ALLOWED_SOURCE_HOSTS, timeout=15, max_bytes=1_000_000,
            headers={"Authorization": f"Bearer {token}", "X-Restli-Protocol-Version": "2.0.0"},
        )
    except Exception as exc:  # noqa: BLE001 — une source qui tombe ne casse pas l'agent
        security.log_safe(LOG, "source.echec", source="linkedin", erreur=type(exc).__name__)
        return {"available": False, "source": "linkedin:official", "reason": type(exc).__name__}
    if status != 200:
        return {"available": False, "source": "linkedin:official",
                "reason": f"HTTP {status}"}
    try:
        data = json.loads(body.decode("utf-8", "replace"))
    except ValueError:
        return {"available": False, "source": "linkedin:official", "reason": "réponse illisible"}
    return {"available": True, "source": "linkedin:official", "url": final_url,
            "elements": data.get("elements", [])}


# Remplaçables en test : le serveur les lit à chaque appel.
BACKENDS: dict[str, Callable[..., Any]] = {
    "wikidata": wikidata_search,
    "wikipedia": wikipedia_summary,
    "linkedin": linkedin_official,
}

# --------------------------------------------------------------------------
# Modèles (validation d'entrée)
# --------------------------------------------------------------------------
from pydantic import BaseModel, Field  # noqa: E402  (import après config, volontaire)


class ResearchRequest(BaseModel):
    query: str = Field(min_length=2, max_length=MAX_QUERY_LENGTH)
    kind: str = Field(default="company", pattern="^(company|person)$")
    lang: str = Field(default="fr", pattern="^(fr|en)$")
    limit: int = Field(default=5, ge=1, le=10)


class PreviewRequest(BaseModel):
    url: str = Field(min_length=8, max_length=2048)


# --------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------
@app.get("/health")
def health() -> dict[str, Any]:
    """Sonde de vie : ne divulgue rien de sensible, pas de jeton requis."""
    return {
        "status": "ok",
        "agent_id": AGENT_ID,
        "version": VERSION,
        "auth": "required" if ENFORCE_AUTH else "disabled-loopback",
        "sources": sorted(BACKENDS),
        "linkedin_api": bool((os.environ.get("LINKEDIN_TOKEN") or "").strip()),
    }


@app.get("/capabilities")
def capabilities(_key: str = Depends(require_key)) -> dict[str, Any]:
    return {"agent_id": AGENT_ID, "name": AGENT_NAME, "capabilities": CAPABILITIES}


@app.post("/research")
def research(body: ResearchRequest, _key: str = Depends(require_key)) -> dict[str, Any]:
    """Recherche sur sources publiques.

    La requête n'est pas journalisée en clair : elle peut contenir un nom de
    personne, c'est-à-dire une donnée personnelle.
    """
    security.log_safe(LOG, "research.demande", prompt=body.query,
                      kind=body.kind, empreinte=hashlib.sha256(body.query.encode()).hexdigest()[:8])
    results: list[dict[str, Any]] = []
    errors: list[str] = []
    try:
        results.extend(BACKENDS["wikidata"](body.query, body.limit))
    except Exception as exc:  # noqa: BLE001
        errors.append(f"wikidata:{type(exc).__name__}")
    if results:
        try:
            summary = BACKENDS["wikipedia"](results[0]["title"] or body.query, body.lang)
            if summary.get("extract"):
                results.insert(0, summary)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"wikipedia:{type(exc).__name__}")
    linkedin = BACKENDS["linkedin"](body.query)
    return {
        "agent_id": AGENT_ID,
        "query_sha256": hashlib.sha256(body.query.encode()).hexdigest()[:16],
        "kind": body.kind,
        "result_count": len(results),
        "results": results,
        "linkedin": linkedin,
        "errors": errors,
        "note": "sources publiques uniquement ; aucun scraping de LinkedIn",
    }


@app.post("/preview")
def preview(body: PreviewRequest, _key: str = Depends(require_key)) -> dict[str, Any]:
    """Récupère une page de la liste blanche : c'est ici que l'SSRF serait possible."""
    try:
        final_url, status, payload = security.safe_get(
            body.url, allow_hosts=ALLOWED_SOURCE_HOSTS, timeout=10, max_bytes=200_000
        )
    except security.UnsafeURL as exc:
        security.log_safe(LOG, "preview.refuse", url=body.url, raison=str(exc))
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"récupération impossible: {type(exc).__name__}") from exc
    return {"url": final_url, "status": status, "bytes": len(payload)}


@app.exception_handler(Exception)
async def unhandled(_request: Request, exc: Exception) -> JSONResponse:
    """Aucune trace technique au client ; le détail reste dans le journal."""
    LOG.exception("erreur non gérée: %s", type(exc).__name__)
    return JSONResponse(status_code=500, content={"error": "erreur interne"})


def main() -> int:
    import uvicorn  # import local : les tests n'ont pas besoin du serveur

    print(f"{AGENT_NAME} v{VERSION} sur http://{BIND}:{PORT} "
          f"· auth={'requise' if ENFORCE_AUTH else 'désactivée (boucle locale)'} "
          f"· sources={','.join(sorted(BACKENDS))}")
    uvicorn.run(app, host=BIND, port=PORT, log_level="info")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
