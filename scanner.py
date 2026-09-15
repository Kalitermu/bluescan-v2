cd ~/bluescan-v2
source .venv/bin/activate

cp scanner.py scanner.before_exposure_fix.py

cat > scanner.py <<'PY'
from datetime import datetime, timezone
from urllib.parse import urlparse, urlunparse
import hashlib
import json
import re
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


ENGINE_NAME = "Motor de exposição rápida BlueScan"
ENGINE_VERSION = "2.0"

TIMEOUT = 8
MAX_BYTES = 200_000


SENSITIVE_PATHS = [
    "/.env",
    "/.env.local",
    "/.env.production",
    "/.git/config",
    "/.git/HEAD",
    "/config.json",
    "/config.yml",
    "/config.yaml",
    "/settings.json",
    "/settings.yml",
    "/settings.yaml",
    "/debug",
    "/phpinfo.php",
    "/server-status",
    "/backup.zip",
    "/backup.tar.gz",
    "/database.sql",
    "/dump.sql",
    "/.htpasswd",
    "/.DS_Store",
]


SECRET_PATTERNS = [
    r"(?i)\bAWS_ACCESS_KEY_ID\s*=",
    r"(?i)\bAWS_SECRET_ACCESS_KEY\s*=",
    r"(?i)\bDATABASE_URL\s*=",
    r"(?i)\bDB_PASSWORD\s*=",
    r"(?i)\bDB_USERNAME\s*=",
    r"(?i)\bSECRET_KEY\s*=",
    r"(?i)\bAPI_KEY\s*=",
    r"(?i)\bAPI_SECRET\s*=",
    r"(?i)\bPRIVATE_KEY\s*=",
    r"(?i)\bPASSWORD\s*=",
    r"(?i)\bJWT_SECRET\s*=",
    r"(?i)\bENCRYPTION_KEY\s*=",
]


HTML_MARKERS = [
    "<html",
    "<!doctype",
    "<head",
    "<body",
    "<title",
    "<script",
]


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def normalize_target(target):
    target = (target or "").strip()

    parsed = urlparse(target)

    if parsed.scheme not in ("http", "https"):
        raise ValueError("O alvo precisa usar HTTP ou HTTPS.")

    if not parsed.hostname:
        raise ValueError("O alvo não possui hostname válido.")

    return target


def get_origin(target):
    parsed = urlparse(target)

    return urlunparse(
        (
            parsed.scheme,
            parsed.netloc,
            "/",
            "",
            "",
            "",
        )
    )


def is_html(content_type, body):
    content_type = (content_type or "").lower()

    if "text/html" in content_type:
        return True

    sample = body[:5000].lower()

    return any(marker.encode() in sample for marker in HTML_MARKERS)


def looks_like_sensitive_content(path, content_type, body):
    """
    Só considera exposição quando há evidência no conteúdo.

    Um HTTP 200 sozinho não é suficiente.
    """

    lower_path = path.lower()
    lower_type = (content_type or "").lower()

    text = body.decode("utf-8", errors="ignore")

    # Arquivos de configuração: procurar indicadores reais.
    if lower_path.endswith((".env", ".json", ".yml", ".yaml")):

        if is_html(content_type, body):
            return False, "HTML retornado no lugar do arquivo esperado."

        matches = []

        for pattern in SECRET_PATTERNS:
            if re.search(pattern, text):
                matches.append(pattern)

        if matches:
            return True, (
                "Conteúdo compatível com configuração potencialmente sensível."
            )

        # JSON/YAML válido ou conteúdo textual estruturado pode merecer revisão,
        # mas não será classificado automaticamente como vulnerabilidade.
        if (
            "application/json" in lower_type
            or "application/yaml" in lower_type
            or "text/yaml" in lower_type
        ):
            return False, (
                "Arquivo estruturado acessível, mas não foram identificados "
                "segredos conhecidos."
            )

        return False, "Conteúdo não confirmou exposição sensível."

    # .git
    if "/.git/" in lower_path:

        if is_html(content_type, body):
            return False, "HTML retornado no lugar do recurso Git."

        text_lower = text.lower()

        if "ref:" in text_lower or "[core]" in text_lower:
            return True, "Conteúdo compatível com metadados de repositório Git."

        return False, "Resposta não confirmou exposição de metadados Git."

    # Outros arquivos sensíveis.
    if lower_path.endswith(
        (
            ".sql",
            ".zip",
            ".tar.gz",
            ".htpasswd",
            ".ds_store",
        )
    ):

        if is_html(content_type, body):
            return False, "HTML retornado no lugar do recurso solicitado."

        return True, "Recurso sensível acessível e não identificado como HTML."

    return False, "Nenhuma evidência suficiente."


def classify_response(status, content_type, body, path):
    """
    Classificação defensiva baseada em evidência.
    """

    if status in (401, 403):
        return {
            "classification": "blocked",
            "severity": "info",
            "title": "Recurso sensível com acesso bloqueado",
            "evidence": (
                f"HTTP {status} para {path}. "
                "O servidor não forneceu o conteúdo solicitado."
            ),
            "impact": (
                "Não há evidência de exposição do conteúdo deste recurso."
            ),
            "recommendation": (
                "Manter o controle de acesso e revisar periodicamente "
                "as regras de exposição."
            ),
        }

    if status == 404:
        return {
            "classification": "not_found",
            "severity": "info",
            "title": "Recurso não encontrado",
            "evidence": f"HTTP 404 para {path}.",
            "impact": "Não há evidência de que o recurso esteja disponível.",
            "recommendation": (
                "Nenhuma ação necessária com base somente nesta resposta."
            ),
        }

    if status != 200:
        return {
            "classification": "other_status",
            "severity": "info",
            "title": "Resposta HTTP não conclusiva",
            "evidence": f"HTTP {status} para {path}.",
            "impact": "A resposta não confirma exposição do recurso.",
            "recommendation": (
                "Revisar manualmente caso o recurso seja relevante para o sistema."
            ),
        }

    exposed, reason = looks_like_sensitive_content(
        path,
        content_type,
        body,
    )

    if exposed:
        return {
            "classification": "potential_exposure",
            "severity": "high",
            "title": "Possível exposição de recurso sensível",
            "evidence": reason,
            "impact": (
                "Um recurso potencialmente sensível está acessível sem "
                "evidência de bloqueio."
            ),
            "recommendation": (
                "Remover o recurso da área pública ou aplicar controle de "
                "acesso apropriado. Confirmar manualmente o conteúdo e "
                "rotacionar credenciais caso existam segredos expostos."
            ),
        }

    if is_html(content_type, body):
        return {
            "classification": "html_fallback",
            "severity": "info",
            "title": "Resposta HTML para caminho sensível",
            "evidence": (
                f"HTTP 200, porém Content-Type={content_type or 'ausente'} "
                "e o conteúdo aparenta ser HTML."
            ),
            "impact": (
                "O HTTP 200 não demonstra que o recurso sensível exista. "
                "A aplicação pode estar retornando uma página de fallback."
            ),
            "recommendation": (
                "Não classificar como exposição sem evidência adicional."
            ),
        }

    return {
        "classification": "review",
        "severity": "info",
        "title": "Caminho sensível respondeu HTTP 200",
        "evidence": reason,
        "impact": (
            "A resposta merece revisão, mas não há evidência suficiente "
            "para confirmar uma exposição."
        ),
        "recommendation": (
            "Validar o conteúdo retornado antes de classificar como "
            "vulnerabilidade."
        ),
    }


def request_url(url):
    started = time.perf_counter()

    request = Request(
        url,
        headers={
            "User-Agent": "BlueScan/2.0 Security Scanner",
            "Accept": "*/*",
        },
        method="GET",
    )

    try:
        with urlopen(request, timeout=TIMEOUT) as response:

            content_type = response.headers.get("Content-Type", "")

            body = response.read(MAX_BYTES + 1)

            truncated = len(body) > MAX_BYTES

            if truncated:
                body = body[:MAX_BYTES]

            elapsed = time.perf_counter() - started

            return {
                "url": url,
                "status": response.status,
                "content_type": content_type,
                "bytes": len(body),
                "truncated": truncated,
                "duration_seconds": round(elapsed, 3),
                "body": body,
                "error": None,
            }

    except HTTPError as error:

        try:
            body = error.read(MAX_BYTES + 1)
        except Exception:
            body = b""

        truncated = len(body) > MAX_BYTES

        if truncated:
            body = body[:MAX_BYTES]

        elapsed = time.perf_counter() - started

        return {
            "url": url,
            "status": error.code,
            "content_type": error.headers.get("Content-Type", ""),
            "bytes": len(body),
            "truncated": truncated,
            "duration_seconds": round(elapsed, 3),
            "body": body,
            "error": None,
        }

    except (URLError, TimeoutError, OSError) as error:

        elapsed = time.perf_counter() - started

        return {
            "url": url,
            "status": None,
            "content_type": "",
            "bytes": 0,
            "truncated": False,
            "duration_seconds": round(elapsed, 3),
            "body": b"",
            "error": str(error),
        }

    except Exception as error:

        elapsed = time.perf_counter() - started

        return {
            "url": url,
            "status": None,
            "content_type": "",
            "bytes": 0,
            "truncated": False,
            "duration_seconds": round(elapsed, 3),
            "body": b"",
            "error": str(error),
        }


def make_result(item, target):
    body = item.get("body", b"")
    path = urlparse(item["url"]).path or "/"

    result = {
        "url": item["url"],
        "source": "Caminho sensível conhecido",
        "status": item["status"],
        "content_type": item["content_type"],
        "bytes": item["bytes"],
        "truncated": item["truncated"],
        "duration_seconds": item["duration_seconds"],
        "error": item["error"],
    }

    if body:
        result["body_sha256"] = hashlib.sha256(body).hexdigest()

    if item["error"]:
        result["classification"] = "error"
        result["severity"] = "info"
        result["title"] = "Erro durante verificação"
        result["evidence"] = item["error"]
        result["impact"] = "O recurso não pôde ser avaliado."
        result["recommendation"] = (
            "Repetir a análise ou verificar conectividade do alvo."
        )
        return result

    classification = classify_response(
        item["status"],
        item["content_type"],
        body,
        path,
    )

    result.update(classification)

    return result


def scan_exposure(target):
    started = now_iso()
    started_perf = time.perf_counter()

    target = normalize_target(target)

    origin = get_origin(target)

    verified = []
    findings = []

    for path in SENSITIVE_PATHS:

        url = origin.rstrip("/") + path

        response = request_url(url)

        result = make_result(response, target)

        verified.append(result)

        if result.get("classification") == "potential_exposure":
            findings.append(result)

    duration = time.perf_counter() - started_perf

    return {
        "motor": ENGINE_NAME,
        "versao": ENGINE_VERSION,
        "iniciado_em": started,
        "terminado_em": now_iso(),

        "alvo_informado": target,

        "host_testado": origin,

        "observacao_escopo": (
            "Os caminhos sensíveis deste módulo são verificados no host raiz. "
            "Isso não significa que os recursos pertençam ao caminho específico "
            "informado pelo usuário."
        ),

        "recursos_verificados": len(verified),
        "caminhos_verificados": len(SENSITIVE_PATHS),

        "recursos_descobertos": len(
            [
                item
                for item in verified
                if item.get("status") == 200
            ]
        ),

        "contagem_resultados": len(findings),

        "duracao_segundos": round(duration, 3),

        "resultados": findings,

        "verificado": verified,
    }


def scan_target(target):
    """
    Compatibilidade com o app.py atual.
    """

    started = time.perf_counter()

    exposure = scan_exposure(target)

    duration = time.perf_counter() - started

    return {
        "target": target,
        "started_at": exposure["iniciado_em"],
        "finished_at": exposure["terminado_em"],
        "duration_seconds": round(duration, 3),

        "exposure": exposure,

        "summary": {
            "total_findings": exposure["contagem_resultados"],
            "high": len(
                [
                    x
                    for x in exposure["resultados"]
                    if x.get("severity") == "high"
                ]
            ),
            "medium": 0,
            "low": 0,
            "info": len(
                [
                    x
                    for x in exposure["verificado"]
                    if x.get("severity") == "info"
                ]
            ),
        },
    }


if __name__ == "__main__":

    import sys

    if len(sys.argv) != 2:
        print(
            "Uso: python scanner.py https://seu-alvo-autorizado.example"
        )
        raise SystemExit(1)

    target = sys.argv[1]

    result = scan_target(target)

    print(
        json.dumps(
            result,
            indent=2,
            ensure_ascii=False,
        )
    )
PY

python -m py_compile scanner.py