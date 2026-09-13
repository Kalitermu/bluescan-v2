cd ~/bluescan-v2

cat > target_policy.py <<'PY'
"""
Política de validação de alvos do BlueScan.

Permite:
- localhost / loopback
- IPs privados e de laboratório
- domínios explicitamente autorizados
- subdomínios de domínios autorizados

Variável opcional:
    BLUESCAN_ALLOWED_HOSTS

Exemplo:
    export BLUESCAN_ALLOWED_HOSTS="example.com,*.example.org"
"""

import ipaddress
import os
from urllib.parse import urlparse


ALLOWED_SCHEMES = {"http", "https"}


def _allowed_hosts():
    value = os.getenv("BLUESCAN_ALLOWED_HOSTS", "")
    return {
        item.strip().lower().rstrip(".")
        for item in value.split(",")
        if item.strip()
    }


def _is_private_or_local(host):
    if host in {
        "localhost",
        "localhost.localdomain",
    }:
        return True

    try:
        ip = ipaddress.ip_address(host)

        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
        )

    except ValueError:
        return False


def _is_explicitly_allowed(host):
    host = host.lower().rstrip(".")

    for allowed in _allowed_hosts():

        # Domínio exato
        if allowed == host:
            return True

        # *.example.com
        if allowed.startswith("*."):
            base = allowed[2:]

            if host == base or host.endswith("." + base):
                return True

    return False


def validate_target(url):
    if not isinstance(url, str):
        return False, "O alvo precisa ser uma string."

    url = url.strip()

    if not url:
        return False, "URL vazia."

    if "://" not in url:
        url = "https://" + url

    try:
        parsed = urlparse(url)
    except Exception:
        return False, "URL inválida."

    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        return False, "Somente HTTP/HTTPS são permitidos."

    if not parsed.hostname:
        return False, "Host ausente."

    host = parsed.hostname.strip().lower().rstrip(".")

    if parsed.username is not None or parsed.password is not None:
        return False, "URLs com usuário/senha embutidos não são permitidas."

    # Laboratório local
    if _is_private_or_local(host):
        return True, "Alvo local/privado permitido."

    # Bug bounty/laboratório explicitamente autorizado
    if _is_explicitly_allowed(host):
        return True, "Alvo explicitamente autorizado."

    return (
        False,
        "Alvo não está na lista de autorizados."
    )


def normalize_target(url):
    if not isinstance(url, str):
        raise ValueError("Alvo inválido.")

    url = url.strip()

    if not url:
        raise ValueError("Alvo vazio.")

    if "://" not in url:
        url = "https://" + url

    parsed = urlparse(url)

    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        raise ValueError("Somente HTTP/HTTPS são permitidos.")

    if not parsed.hostname:
        raise ValueError("Host ausente.")

    return url


def is_authorized_mode():
    return bool(_allowed_hosts())
PY