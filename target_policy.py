cd ~/bluescan-v2

cat > target_policy.py <<'PY'
from urllib.parse import urlparse


ALLOWED_SCHEMES = {"http", "https"}


def validate_target(target):
    if not isinstance(target, str):
        return False, "O alvo precisa ser uma URL."

    target = target.strip()

    if not target:
        return False, "Informe uma URL."

    try:
        parsed = urlparse(target)
    except Exception:
        return False, "URL inválida."

    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        return False, "Somente URLs HTTP ou HTTPS são permitidas."

    if not parsed.hostname:
        return False, "A URL não possui um hostname válido."

    return (
        True,
        "Alvo aceito. Confirme que você possui autorização para realizar a análise.",
    )
PY