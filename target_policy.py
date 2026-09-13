cat > target_policy.py <<'PY'
from urllib.parse import urlparse


def validate_target(target):
    """
    Validação básica do alvo.
    Não bloqueia domínio, IP, localhost ou rede pública.
    """

    if not isinstance(target, str):
        return False, "Alvo inválido."

    target = target.strip()

    if not target:
        return False, "Alvo vazio."

    try:
        parsed = urlparse(target)
    except Exception:
        return False, "URL inválida."

    if parsed.scheme.lower() not in ("http", "https"):
        return False, "O alvo precisa usar HTTP ou HTTPS."

    if not parsed.hostname:
        return False, "Host não informado."

    return True, "Alvo aceito."
PY
    