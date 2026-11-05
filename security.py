"""Gardes de sécurité réutilisables — stdlib uniquement.

Chaque fonction répond à une constatation précise de l'audit de
`linkedin-research-agent` (le fichier n'étant pas sur cette machine, ces gardes
sont écrites pour être *branchées* dans le code, pas devinées pour lui) :

    research_agent.py:51 / register.py:17  secret en dur ou clé de repli
        -> require_secret() : aucune valeur par défaut, échec au démarrage
    research_agent.py:52                   authentification désactivée par défaut
        -> auth_config() : activée par défaut, désactivation = loopback only
    research_agent.py:109                  CORS ouvert à tous
        -> cors_origins() : liste explicite, '*' interdit avec credentials
    research_agent.py:143/178/447          SSRF (adresse fournie par l'appelant)
        -> validate_url() + safe_get() : schéma, résolution DNS, IP bloquées,
           redirections revalidées à chaque saut
    research_agent.py:222/348              secret ou prompt écrit en clair
        -> redact() / log_safe()
    research_agent.py:473                  écoute sur toutes les interfaces
        -> bind_host() : 127.0.0.1 par défaut

Aucune dépendance : ni requests, ni pydantic. Le module s'importe dans un
service existant sans changer sa configuration.
"""

from __future__ import annotations

import hashlib
import ipaddress
import logging
import os
import secrets
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Iterable, Mapping

__all__ = [
    "MissingSecret",
    "InsecureConfig",
    "UnsafeURL",
    "require_secret",
    "auth_config",
    "cors_origins",
    "validate_url",
    "safe_get",
    "redact",
    "log_safe",
    "bind_host",
]

# Valeurs qui traînent dans les dépôts et ne sont pas des secrets.
PLACEHOLDERS = {
    "", "changeme", "change-me", "dev", "test", "testing", "demo", "example",
    "secret", "password", "hunter2", "xxx", "none", "null", "todo", "your-key",
    "your_key_here", "sk-xxx", "dummy",
}

ALLOWED_SCHEMES = {"http", "https"}

# Adresses de métadonnées cloud : jamais joignables, quel que soit le reste.
METADATA_HOSTS = {"169.254.169.254", "fd00:ec2::254", "metadata.google.internal"}

SECRET_HINTS = ("key", "token", "secret", "password", "passwd", "auth", "cookie",
                "session", "credential")


class MissingSecret(RuntimeError):
    """Secret attendu mais absent, vide ou manifestement factice."""


class InsecureConfig(RuntimeError):
    """Configuration qui exposerait le service ; on refuse de démarrer."""


class UnsafeURL(RuntimeError):
    """URL refusée par la politique de sortie réseau."""


# ---------------------------------------------------------------------------
# 1. Secrets : pas de repli, pas de valeur par défaut
# ---------------------------------------------------------------------------
def require_secret(name: str, env: Mapping[str, str] | None = None,
                   minimum_length: int = 12) -> str:
    """Lit un secret obligatoire et échoue franchement s'il est absent.

    Une clé de repli dans le code est une clé publique : elle finit dans le
    dépôt, puis dans l'historique git, où elle reste. Ici il n'existe aucun
    chemin qui produise une valeur quand la variable manque.
    """
    source = os.environ if env is None else env
    value = (source.get(name) or "").strip()
    if not value:
        raise MissingSecret(
            f"{name} est obligatoire et n'a pas de valeur par défaut : "
            f"renseignez-la dans l'environnement (ou .env non versionné)."
        )
    if value.lower() in PLACEHOLDERS:
        raise MissingSecret(
            f"{name} contient une valeur factice ({value!r}) : elle est refusée."
        )
    if len(value) < minimum_length:
        raise MissingSecret(
            f"{name} est trop court ({len(value)} caractères, minimum {minimum_length})."
        )
    return value


# ---------------------------------------------------------------------------
# 2. Authentification : activée par défaut
# ---------------------------------------------------------------------------
TRUE_VALUES = {"1", "true", "yes", "on", "oui"}
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}


def auth_config(env: Mapping[str, str] | None = None) -> dict[str, Any]:
    """Configuration d'authentification, sûre par défaut.

    Le défaut est `enabled=True`. Couper l'authentification n'est possible que
    sur une boucle locale : un service sans auth exposé sur le réseau est une
    erreur de configuration, pas une option.
    """
    source = os.environ if env is None else env
    host = (source.get("BIND_HOST") or "127.0.0.1").strip()
    raw_enabled = source.get("AUTH_ENABLED")
    enabled = True if raw_enabled is None else raw_enabled.strip().lower() in TRUE_VALUES

    if not enabled:
        if host not in LOOPBACK_HOSTS:
            raise InsecureConfig(
                f"AUTH_ENABLED est désactivé alors que le service écoute sur {host!r} : "
                "couper l'authentification n'est permis que sur 127.0.0.1/localhost."
            )
        return {"enabled": False, "api_key": None, "host": host, "exposed": False}

    # Si l'authentification est active, la clé est obligatoire : pas de jeton vide
    # qui laisserait passer n'importe quel appelant.
    api_key = require_secret("API_KEY", source, minimum_length=16)
    return {"enabled": True, "api_key": api_key, "host": host,
            "exposed": host not in LOOPBACK_HOSTS}


# ---------------------------------------------------------------------------
# 3. CORS : liste explicite
# ---------------------------------------------------------------------------
def cors_origins(env: Mapping[str, str] | None = None) -> list[str]:
    """Origines autorisées, sans joker.

    `allow_origins=["*"]` combiné à `allow_credentials=True` est refusé par les
    navigateurs — et quand il passe, il expose l'API à tout site visité par
    l'utilisateur. Ici, l'absence de configuration veut dire « aucune origine
    tierce », pas « toutes ».
    """
    source = os.environ if env is None else env
    raw = (source.get("CORS_ORIGINS") or "").strip()
    allow_credentials = (source.get("CORS_ALLOW_CREDENTIALS") or "0").strip().lower() in TRUE_VALUES
    if not raw:
        return []
    origins = [item.strip().rstrip("/") for item in raw.split(",") if item.strip()]
    if "*" in origins:
        if allow_credentials:
            raise InsecureConfig(
                "CORS_ORIGINS='*' avec credentials : configuration refusée "
                "(le navigateur la rejette, et l'élargir revient à ouvrir l'API)."
            )
        raise InsecureConfig(
            "CORS_ORIGINS='*' : listez les origines réelles, "
            "un joker rend l'API appelable depuis n'importe quel site."
        )
    for origin in origins:
        parsed = urllib.parse.urlsplit(origin)
        if parsed.scheme not in ALLOWED_SCHEMES or not parsed.netloc:
            raise InsecureConfig(f"Origine CORS invalide : {origin!r}")
    return origins


# ---------------------------------------------------------------------------
# 4. SSRF : schéma, résolution DNS, IP, redirections
# ---------------------------------------------------------------------------
class _BlockedIP(ipaddress._BaseAddress):  # pragma: no cover - typage seulement
    pass


def _is_public(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
        return False
    if ip.is_multicast or ip.is_unspecified:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return _is_public(ip.ipv4_mapped)
    return True


def _default_resolver(host: str, port: int) -> list[str]:
    infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    return [info[4][0] for info in infos]


def validate_url(url: str, *, allow_private: bool = False,
                 allow_hosts: Iterable[str] | None = None,
                 resolver: Any = None) -> str:
    """Valide une URL de sortie et renvoie sa forme normalisée.

    Trois contrôles, dans cet ordre : le schéma, l'absence d'identifiants dans
    l'URL, puis **toutes** les adresses que le nom résout. Contrôler seulement
    la chaîne ne suffit pas — `http://127.0.0.1` et `http://localtest.me` sont
    la même cible, et un DNS qui change entre la vérification et l'appel rend
    la vérification inutile.
    """
    if not isinstance(url, str) or not url.strip():
        raise UnsafeURL("URL vide")
    candidate = url.strip()
    parsed = urllib.parse.urlsplit(candidate)

    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        raise UnsafeURL(f"schéma refusé : {parsed.scheme!r} (attendu http ou https)")
    if parsed.username or parsed.password:
        raise UnsafeURL("identifiants dans l'URL refusés")
    host = parsed.hostname or ""
    if not host:
        raise UnsafeURL("URL sans hôte")

    if host.lower() in METADATA_HOSTS:
        # Vérifié avant la liste blanche : la raison affichée doit dire ce qui
        # s'est réellement passé, sinon un opérateur cherche au mauvais endroit.
        raise UnsafeURL("adresse de métadonnées cloud refusée")

    if allow_hosts is not None:
        allowed = {h.strip().lower() for h in allow_hosts}
        if allowed and host.lower() not in allowed:
            raise UnsafeURL(f"hôte hors liste autorisée : {host!r}")

    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None

    if literal is not None:
        if not allow_private and not _is_public(literal):
            raise UnsafeURL(f"adresse non publique refusée : {literal}")
    else:
        port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
        resolve = resolver or _default_resolver
        try:
            addresses = resolve(host, port)
        except OSError as exc:
            raise UnsafeURL(f"résolution impossible pour {host!r} : {exc}") from exc
        if not addresses:
            raise UnsafeURL(f"{host!r} ne résout vers aucune adresse")
        for address in addresses:
            try:
                ip = ipaddress.ip_address(address)
            except ValueError:
                raise UnsafeURL(f"réponse DNS illisible pour {host!r} : {address!r}")
            if not allow_private and not _is_public(ip):
                raise UnsafeURL(
                    f"{host!r} résout vers une adresse non publique ({ip}) : refusé"
                )
    return urllib.parse.urlunsplit(parsed)


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    """Empêche urllib de suivre une redirection sans revalidation."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        return None


def safe_get(url: str, *, timeout: float = 10.0, max_bytes: int = 2_000_000,
             max_redirects: int = 3, allow_private: bool = False,
             allow_hosts: Iterable[str] | None = None,
             resolver: Any = None, headers: Mapping[str, str] | None = None
             ) -> tuple[str, int, bytes]:
    """GET contrôlé : chaque saut de redirection est revalidé.

    Une redirection est le contournement classique d'un filtre d'URL : la
    première cible est publique, la seconde pointe vers l'adresse interne.
    On ne suit donc aucune redirection automatiquement ; on la relit et on la
    repasse dans `validate_url`.
    """
    current = validate_url(url, allow_private=allow_private,
                           allow_hosts=allow_hosts, resolver=resolver)
    opener = urllib.request.build_opener(_NoRedirects)
    request_headers = {"User-Agent": "linkedin-research-agent/1.0"}
    if headers:
        request_headers.update(dict(headers))

    for _ in range(max_redirects + 1):
        request = urllib.request.Request(current, headers=request_headers, method="GET")
        try:
            with opener.open(request, timeout=timeout) as response:
                body = response.read(max_bytes + 1)
                if len(body) > max_bytes:
                    raise UnsafeURL(f"réponse trop volumineuse (> {max_bytes} octets)")
                return current, response.status, body
        except urllib.error.HTTPError as exc:
            if exc.code in (301, 302, 303, 307, 308):
                location = exc.headers.get("Location")
                if not location:
                    raise UnsafeURL(f"redirection {exc.code} sans Location") from exc
                next_url = urllib.parse.urljoin(current, location)
                # Une redirection est toujours revalidée en politique stricte,
                # même si la première cible a été explicitement autorisée :
                # sinon une URL interne légitime sert de tremplin vers une autre.
                current = validate_url(next_url, allow_private=False,
                                       allow_hosts=allow_hosts, resolver=resolver)
                continue
            raise
    raise UnsafeURL(f"plus de {max_redirects} redirections")


# ---------------------------------------------------------------------------
# 5. Journaux : ni secret, ni prompt en clair
# ---------------------------------------------------------------------------
# Clé des empreintes de journal. Vide par défaut : elle est alors tirée au
# démarrage, ce qui suffit pour corréler pendant une exécution et ne laisse
# aucune trace exploitable dans les fichiers de log.
_FINGERPRINT_KEY: bytes = (os.environ.get("FINGERPRINT_KEY") or "").encode("utf-8") or secrets.token_bytes(32)


def redact(value: Any, *, keep: int = 8) -> str:
    """Empreinte stable et non réversible, pour corréler sans divulguer.

    Un journal est lisible par plus de monde que la base : y écrire une clé
    refusée ou le prompt d'un utilisateur, c'est les publier. L'empreinte
    suffit pour répondre à « est-ce la même clé qui a été refusée deux fois ? ».

    HMAC et non SHA-256 nu : huit caractères d'un SHA-256 non salé se
    retrouvent par force brute quand la valeur est un jeton court — un journal
    volé rendrait alors la clé. Avec une clé HMAC éphémère, l'empreinte ne dit
    rien hors du processus. `FINGERPRINT_KEY` rend la corrélation stable entre
    redémarrages, au prix d'un secret de plus à protéger.
    """
    text = "" if value is None else str(value)
    if not text:
        return "fp:empty:0"
    # BLAKE2b à clé : aussi rapide qu'un SHA-256, mais la clé empêche de
    # recalculer l'empreinte sans la connaître. Ce n'est pas un hachage de mot
    # de passe et cela ne prétend pas l'être.
    digest = hashlib.blake2b(text.encode("utf-8", "replace"),
                             key=_FINGERPRINT_KEY, digest_size=16).hexdigest()
    return f"fp:{digest[:keep]}:{len(text)}"


def _is_secret_field(name: str) -> bool:
    lowered = name.lower()
    return any(hint in lowered for hint in SECRET_HINTS)


def log_safe(logger: logging.Logger, event: str, /, **fields: Any) -> None:
    """Journalise un événement en masquant les champs sensibles.

    Les champs dont le nom évoque un secret sont remplacés par leur empreinte ;
    le texte libre (prompt, message) est réduit à sa longueur et son empreinte.
    """
    safe_fields: dict[str, Any] = {}
    for key, value in fields.items():
        if _is_secret_field(key):
            safe_fields[key] = redact(value)
        elif key in {"prompt", "text", "message", "query", "body"}:
            safe_fields[key] = redact(value)
        else:
            safe_fields[key] = value
    logger.warning("%s | %s", event, " ".join(f"{k}={v}" for k, v in safe_fields.items()))


# ---------------------------------------------------------------------------
# 6. Écoute réseau
# ---------------------------------------------------------------------------
def bind_host(env: Mapping[str, str] | None = None) -> str:
    """127.0.0.1 par défaut ; l'exposition demande un choix explicite.

    Écouter sur 0.0.0.0 rend le service joignable depuis le réseau local, y
    compris par un voisin de Wi-Fi. Ce n'est pas un défaut acceptable : il faut
    EXPOSE_PUBLIC=1 pour l'obtenir.
    """
    source = os.environ if env is None else env
    host = (source.get("BIND_HOST") or "127.0.0.1").strip()
    # Comparaison, pas une écoute : ces valeurs sont précisément celles qu'on
    # refuse sans EXPOSE_PUBLIC. D'où le nosec : bandit voit le littéral.
    if host in {"0.0.0.0", "::", "*"}:  # nosec B104
        if (source.get("EXPOSE_PUBLIC") or "").strip().lower() not in TRUE_VALUES:
            raise InsecureConfig(
                f"BIND_HOST={host!r} exposerait le service sur le réseau : "
                "définissez EXPOSE_PUBLIC=1 si c'est vraiment voulu."
            )
    return host


def utc_epoch() -> int:
    """Horodatage entier : comparable sans ambiguïté de fuseau ni de format."""
    return int(time.time())
