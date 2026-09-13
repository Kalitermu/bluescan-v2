cd ~/bluescan-v2

cat > target_policy.py <<'PY'
"""
Política de validação de alvos do BlueScan.

Modo padrão:
    - localhost / IP privado: permitido
    - alvo público: exige BLUESCAN_AUTHORIZED=1

Para usar em um laboratório ou sistema que você está autorizado
a testar:

    export BLUESCAN_AUTHORIZED=1

Depois:
    streamlit run app.py
"""

import ipaddress
import os
from urllib.parse import urlparse


ALLOWED_SCHEMES = {"http", "https"}


def _authorization_enabled():
    """
    Ativa o modo de alvos públicos somente quando explicitamente
    habilitado pelo operador.
    """
    value = os.getenv("BLUESCAN_AUTHORIZED", "").strip().lower()

    return value in {
        "1",
        "true",
        "yes",
        "sim",
        "on",
    }


def _is_private_or_local(host):
    """
    Verifica se o host é localhost ou um endereço IP reservado/
    privado para laboratório.
    """

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


def validate_target(url):
    """
    Valida um alvo HTTP/HTTPS.

    Retorna:
        (True, mensagem)
        ou
        (False, mensagem)

    Exemplos:

        validate_target("http://127.0.0.1:8080")
        validate_target("https://example.com")
    """

    if not isinstance(url, str):
        return False, "O alvo precisa ser uma string."

    url = url.strip()

    if not url:
        return False, "URL vazia."

    # Permite o usuário digitar domínio sem esquema.
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

    host = parsed.hostname.strip().lower()

    if not host:
        return False, "Host vazio."

    # Protege contra URLs com credenciais.
    if parsed.username is not None or parsed.password is not None:
        return False, "URLs com usuário/senha embutidos não são permitidas."

    # Laboratório/local sempre permitido.
    if _is_private_or_local(host):
        return True, "Alvo local/privado permitido."

    # Domínio/IP público somente no modo explicitamente autorizado.
    if _authorization_enabled():
        return True, "Alvo público aceito no modo autorizado."

    return (
        False,
        "Alvo público bloqueado. "
        "Para um laboratório autorizado, defina "
        "BLUESCAN_AUTHORIZED=1."
    )


def normalize_target(url):
    """
    Normaliza uma URL para uso pelo restante do BlueScan.

    Exemplo:
        example.com -> https://example.com
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
    Informa se o modo de alvos públicos está explicitamente ativo.
    """
    return _authorization_enabled()
PY