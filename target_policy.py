from urllib.parse import urlparse
import ipaddress


ALLOWED_HOSTS = {
    "127.0.0.1",
    "localhost",
}


def validate_target(url):
    try:
        parsed = urlparse(url)
    except Exception:
        return False, "URL inválida."

    if parsed.scheme not in ("http", "https"):
        return False, "Somente HTTP/HTTPS."

    if not parsed.hostname:
        return False, "Host ausente."

    host = parsed.hostname.lower()

    if host in ALLOWED_HOSTS:
        return True, "Alvo de laboratório permitido."

    try:
        ip = ipaddress.ip_address(host)

        if ip.is_private or ip.is_loopback or ip.is_link_local:
            return True, "IP privado/de laboratório permitido."

    except ValueError:
        pass

    return False, (
        "Alvo bloqueado. "
        "Esta versão aceita somente alvos de laboratório."
    )
