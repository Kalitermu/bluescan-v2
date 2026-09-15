cd ~/bluescan-v2

cat > target_policy.py <<'PY'
import ipaddress
import os
from urllib.parse import urlparse


ALLOWED_SCHEMES = {"http", "https"}


def _allowed_hosts():
    """
    Retorna os hosts explicitamente autorizados
    pela variável de ambiente BLUESCAN_ALLOWED_HOSTS.

    Exemplo:

        export BLUESCAN_ALLOWED_HOSTS="meusite.com,cliente.com,*.empresa.com"
    """
    value = os.getenv("BLUESCAN_ALLOWED_HOSTS", "")

    hosts = []

    for item in value.split(","):
        item = item.strip().lower().rstrip(".")

        if item:
            hosts.append(item)

    return hosts


def _is_private_or_local(host):
    """
    Permite somente endereços IP privados, locais ou link-local.
    """
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
    """
    Verifica se o domínio foi explicitamente autorizado.

    Aceita:

        exemplo.com

    ou:

        *.exemplo.com
    """
    host = host.lower().rstrip(".")

    for allowed in _allowed_hosts():

        # Domínio exato
        if allowed == host:
            return True

        # Subdomínios explicitamente autorizados
        if allowed.startswith("*."):
            base = allowed[2:]

            if host == base or host.endswith("." + base):
                return True

    return False


def validate_target(url):
    """
    Valida um alvo antes de qualquer análise.

    O BlueScan não libera arbitrariamente a internet:
    o alvo precisa ser local/privado ou estar explicitamente
    autorizado através de BLUESCAN_ALLOWED_HOSTS.
    """

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
        return False, "URLs com usuário ou senha embutidos não são permitidas."

    # Ambiente local/privado
    if _is_private_or_local(host):
        return True, "Alvo local ou privado autorizado."

    # Domínio explicitamente autorizado
    if _is_explicitly_allowed(host):
        return True, "Alvo explicitamente autorizado."

    return (
        False,
        "Alvo não autorizado. Adicione o domínio à lista "
        "BLUESCAN_ALLOWED_HOSTS antes da análise."
    )


def normalize_target(url):
    """
    Normaliza e valida a estrutura básica da URL.
    """

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
    """
    Indica se existe pelo menos um domínio explicitamente
    autorizado na configuração.
    """
    return bool(_allowed_hosts())
PY