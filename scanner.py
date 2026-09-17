cat > scanner.py <<'PY'
import re
import time
from datetime import datetime, timezone
from urllib.parse import urlparse, urljoin

import httpx


USER_AGENT = "BlueScan/2.1"
TIMEOUT = 15.0


def _finding(
    title,
    severity,
    category,
    source,
    evidence="",
    impact="",
    recommendation="",
):
    return {
        "title": title,
        "severity": severity,
        "category": category,
        "source": source,
        "evidence": evidence,
        "impact": impact,
        "recommendation": recommendation,
    }


def _add_finding(
    findings,
    title,
    severity,
    category,
    evidence="",
    impact="",
    recommendation="",
):
    """
    Adiciona um achado evitando duplicações pelo título.
    """

    if any(item.get("title") == title for item in findings):
        return

    findings.append(
        _finding(
            title,
            severity,
            category,
            "BlueScan HTTP",
            evidence,
            impact,
            recommendation,
        )
    )


def _header(headers, name):
    """
    Busca um cabeçalho sem diferenciar maiúsculas/minúsculas.
    """

    wanted = name.lower()

    for key, value in headers.items():
        if str(key).lower() == wanted:
            return str(value)

    return None


def _cookie_has_attribute(cookie_text, attribute):
    """
    Verifica um atributo de cookie de forma case-insensitive.
    """

    pattern = rf"(?:^|;)\s*{re.escape(attribute)}(?:=|;|$)"

    return re.search(
        pattern,
        cookie_text,
        flags=re.IGNORECASE,
    ) is not None


def _extract_set_cookie_headers(response):
    """
    Obtém Set-Cookie quando disponível.
    """

    cookies = []

    try:
        values = response.headers.get_list("set-cookie")
        if values:
            return values
    except Exception:
        pass

    value = _header(response.headers, "Set-Cookie")

    if value:
        cookies.append(value)

    return cookies


def _analyze_security_headers(response, parsed, findings):
    """
    Analisa headers de segurança relevantes.
    """

    headers = response.headers

    # HSTS só faz sentido quando o acesso é HTTPS.
    if parsed.scheme.lower() == "https":
        if not _header(headers, "Strict-Transport-Security"):
            _add_finding(
                findings,
                "HSTS ausente",
                "low",
                "Security Headers",
                "Strict-Transport-Security não foi encontrado.",
                "Pode reduzir a capacidade do navegador de reforçar o uso de HTTPS.",
                "Avaliar a implementação de Strict-Transport-Security.",
            )

    # CSP.
    if not _header(headers, "Content-Security-Policy"):
        _add_finding(
            findings,
            "Content-Security-Policy ausente",
            "info",
            "Security Headers",
            "Content-Security-Policy não foi encontrado.",
            "A ausência de CSP elimina uma camada adicional de controle sobre recursos carregados pelo navegador.",
            "Avaliar uma Content-Security-Policy adequada à aplicação.",
        )

    # MIME sniffing.
    x_content = _header(headers, "X-Content-Type-Options")

    if not x_content:
        _add_finding(
            findings,
            "X-Content-Type-Options ausente",
            "low",
            "Security Headers",
            "X-Content-Type-Options não foi encontrado.",
            "Pode reduzir algumas proteções contra MIME sniffing.",
            "Avaliar o uso de X-Content-Type-Options: nosniff.",
        )
    elif x_content.lower().strip() != "nosniff":
        _add_finding(
            findings,
            "X-Content-Type-Options configurado de forma diferente de nosniff",
            "info",
            "Security Headers",
            f"X-Content-Type-Options: {x_content}",
            "A configuração observada não corresponde ao valor normalmente utilizado para impedir MIME sniffing.",
            "Revisar a configuração do cabeçalho.",
        )

    # Clickjacking:
    # X-Frame-Options OU CSP frame-ancestors.
    x_frame = _header(headers, "X-Frame-Options")
    csp = _header(headers, "Content-Security-Policy") or ""

    has_frame_ancestors = "frame-ancestors" in csp.lower()

    if not x_frame and not has_frame_ancestors:
        _add_finding(
            findings,
            "Proteção contra framing não identificada",
            "low",
            "Security Headers",
            "X-Frame-Options ausente e diretiva frame-ancestors não identificada na CSP.",
            "Pode aumentar a exposição a ataques de clickjacking, dependendo do contexto da aplicação.",
            "Avaliar X-Frame-Options ou CSP com frame-ancestors.",
        )

    # Referrer Policy.
    if not _header(headers, "Referrer-Policy"):
        _add_finding(
            findings,
            "Referrer-Policy ausente",
            "info",
            "Security Headers",
            "Referrer-Policy não foi encontrado.",
            "O navegador pode utilizar uma política de referência diferente da desejada pela aplicação.",
            "Avaliar uma Referrer-Policy apropriada.",
        )

    # Permissions Policy.
    if not _header(headers, "Permissions-Policy"):
        _add_finding(
            findings,
            "Permissions-Policy ausente",
            "info",
            "Security Headers",
            "Permissions-Policy não foi encontrado.",
            "Recursos e APIs do navegador podem não estar explicitamente restringidos por essa política.",
            "Avaliar uma Permissions-Policy adequada ao sistema.",
        )


def _analyze_information_disclosure(response, findings):
    """
    Identifica informações de tecnologia expostas.
    """

    server = _header(response.headers, "Server")

    if server:
        _add_finding(
            findings,
            "Identificação do servidor exposta",
            "info",
            "Information Disclosure",
            f"Server: {server}",
            "Pode fornecer informações utilizadas para fingerprinting da infraestrutura.",
            "Avaliar se a exposição desse detalhe é necessária.",
        )

    powered_by = _header(response.headers, "X-Powered-By")

    if powered_by:
        _add_finding(
            findings,
            "Tecnologia exposta por X-Powered-By",
            "low",
            "Information Disclosure",
            f"X-Powered-By: {powered_by}",
            "Pode revelar a tecnologia utilizada pela aplicação.",
            "Avaliar a remoção desse cabeçalho em produção.",
        )


def _analyze_cors(response, findings):
    """
    Analisa configurações CORS observáveis na resposta.
    """

    allow_origin = _header(
        response.headers,
        "Access-Control-Allow-Origin",
    )

    if allow_origin == "*":
        _add_finding(
            findings,
            "CORS permite qualquer origem",
            "info",
            "CORS",
            "Access-Control-Allow-Origin: *",
            "Recursos podem estar disponíveis para requisições originadas de qualquer domínio, conforme o recurso e demais controles.",
            "Verificar se o uso de '*' é realmente necessário para o recurso.",
        )


def _analyze_cookies(response, parsed, findings):
    """
    Analisa atributos básicos de cookies.
    """

    cookie_headers = _extract_set_cookie_headers(response)

    for raw_cookie in cookie_headers:

        first_part = raw_cookie.split(";", 1)[0].strip()

        if "=" not in first_part:
            continue

        cookie_name = first_part.split("=", 1)[0].strip()

        if not cookie_name:
            continue

        secure = _cookie_has_attribute(
            raw_cookie,
            "Secure",
        )

        httponly = _cookie_has_attribute(
            raw_cookie,
            "HttpOnly",
        )

        samesite = re.search(
            r"(?:^|;)\s*SameSite\s*=\s*([^;]+)",
            raw_cookie,
            flags=re.IGNORECASE,
        )

        samesite_value = (
            samesite.group(1).strip()
            if samesite
            else None
        )

        if parsed.scheme.lower() == "https" and not secure:
            _add_finding(
                findings,
                f"Cookie sem Secure: {cookie_name}",
                "low",
                "Cookies",
                f"Cookie '{cookie_name}' não apresentou o atributo Secure.",
                "Em determinadas situações, o cookie pode ficar mais exposto a transmissão sem a proteção esperada.",
                "Avaliar o uso de Secure para cookies transmitidos por HTTPS.",
            )

        if not httponly:
            _add_finding(
                findings,
                f"Cookie sem HttpOnly: {cookie_name}",
                "info",
                "Cookies",
                f"Cookie '{cookie_name}' não apresentou HttpOnly.",
                "JavaScript do navegador poderá ter acesso ao cookie quando o contexto permitir.",
                "Quando apropriado, avaliar o uso de HttpOnly.",
            )

        if not samesite_value:
            _add_finding(
                findings,
                f"Cookie sem SameSite explícito: {cookie_name}",
                "info",
                "Cookies",
                f"Cookie '{cookie_name}' não apresentou SameSite explícito.",
                "A política de envio do cookie entre origens não está explicitamente definida pelo atributo.",
                "Avaliar uma política SameSite apropriada ao funcionamento da aplicação.",
            )


def _analyze_content(response, parsed, findings):
    """
    Analisa conteúdo HTML de forma não destrutiva.
    """

    content_type = _header(
        response.headers,
        "Content-Type",
    ) or ""

    if not content_type:
        _add_finding(
            findings,
            "Content-Type ausente",
            "low",
            "HTTP Configuration",
            "A resposta não apresentou Content-Type.",
            "Pode dificultar a interpretação correta do conteúdo pelo cliente.",
            "Definir um Content-Type apropriado para a resposta.",
        )

    body = response.text[:200000]

    # Erros detalhados comuns.
    error_patterns = [
        r"traceback\s*\(",
        r"stack\s*trace",
        r"fatal\s+error",
        r"uncaught\s+exception",
        r"sql\s+syntax",
        r"mysql.*error",
        r"postgresql.*error",
        r"oracle.*error",
        r"exception\s+in\s+thread",
    ]

    if any(
        re.search(pattern, body, re.IGNORECASE)
        for pattern in error_patterns
    ):
        _add_finding(
            findings,
            "Possível mensagem de erro detalhada exposta",
            "medium",
            "Information Disclosure",
            "Padrão compatível com mensagem técnica de erro identificado no conteúdo.",
            "Mensagens detalhadas podem revelar informações sobre componentes internos da aplicação.",
            "Revisar o tratamento de erros e evitar mensagens técnicas detalhadas em respostas destinadas ao usuário.",
        )

    # Mixed content: somente para páginas HTTPS.
    if parsed.scheme.lower() == "https":

        insecure_resources = set()

        patterns = [
            r"""(?:src|href)\s*=\s*["'](http://[^"']+)["']""",
            r"""url\(\s*["']?(http://[^"')]+)["']?\s*\)""",
        ]

        for pattern in patterns:
            for match in re.findall(
                pattern,
                body,
                flags=re.IGNORECASE,
            ):
                insecure_resources.add(match)

        if insecure_resources:
            examples = list(insecure_resources)[:5]

            _add_finding(
                findings,
                "Possível conteúdo misto",
                "medium",
                "Transport Security",
                "Recursos HTTP foram identificados em uma página HTTPS: "
                + ", ".join(examples),
                "Recursos carregados por HTTP podem reduzir a proteção oferecida pelo HTTPS.",
                "Avaliar a migração dos recursos para HTTPS.",
            )


def _analyze_redirects(response, target, findings, redirects):
    """
    Registra redirecionamentos observados.
    """

    for item in response.history:

        location = _header(
            item.headers,
            "Location",
        )

        entry = {
            "status": item.status_code,
            "from": str(item.url),
            "location": location,
        }

        redirects.append(entry)

        if location:
            destination = urljoin(
                str(item.url),
                location,
            )

            source_scheme = urlparse(
                str(item.url)
            ).scheme.lower()

            destination_scheme = urlparse(
                destination
            ).scheme.lower()

            if (
                source_scheme == "http"
                and destination_scheme == "https"
            ):
                continue

            if (
                source_scheme == "https"
                and destination_scheme == "http"
            ):
                _add_finding(
                    findings,
                    "Redirecionamento HTTPS para HTTP",
                    "medium",
                    "Transport Security",
                    f"{item.url} -> {destination}",
                    "Pode levar o usuário de uma conexão HTTPS para HTTP.",
                    "Revisar o fluxo de redirecionamento e evitar downgrade para HTTP.",
                )


def _analyze_status(response, findings):
    """
    Registra o status HTTP sem transformar códigos normais em vulnerabilidades.
    """

    status = response.status_code

    if status == 401:
        _add_finding(
            findings,
            "HTTP 401 — Autenticação requerida",
            "info",
            "HTTP",
            "Status HTTP: 401 Unauthorized",
            "O recurso requer autenticação para acesso.",
            "Validar se o comportamento é esperado.",
        )

    elif status == 403:
        _add_finding(
            findings,
            "HTTP 403 — Acesso negado",
            "info",
            "HTTP",
            "Status HTTP: 403 Forbidden",
            "O servidor recusou o acesso ao recurso solicitado.",
            "Validar se o bloqueio é esperado para o recurso e contexto do teste.",
        )

    elif status == 404:
        _add_finding(
            findings,
            "HTTP 404 — Recurso não encontrado",
            "info",
            "HTTP",
            "Status HTTP: 404 Not Found",
            "O recurso solicitado não foi encontrado.",
            "Validar se o comportamento é esperado.",
        )

    elif status >= 500:
        _add_finding(
            findings,
            f"HTTP {status} — Erro no servidor",
            "medium",
            "HTTP",
            f"Status HTTP: {status}",
            "A resposta indica erro no processamento pelo servidor.",
            "Investigar logs da aplicação e verificar se o erro pode ser reproduzido de forma controlada.",
        )

    else:
        _add_finding(
            findings,
            f"HTTP {status}",
            "info",
            "HTTP",
            f"Status HTTP: {status}",
            "O servidor respondeu à requisição.",
            "Manter o serviço monitorado.",
        )


def _calculate_summary(findings):
    """
    Gera contagem por severidade.
    """

    summary = {
        "total": len(findings),
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }

    for finding in findings:

        severity = str(
            finding.get("severity", "info")
        ).lower()

        if severity in summary:
            summary[severity] += 1

    return summary


def scan_target(target):
    """
    Executa análise defensiva HTTP de um alvo autorizado.

    O scanner não executa exploração nem tenta contornar
    mecanismos de autenticação ou controle de acesso.
    """

    started = time.time()
    started_at = datetime.now(
        timezone.utc
    ).isoformat()

    if not isinstance(target, str):
        raise ValueError("Alvo inválido.")

    target = target.strip()

    parsed = urlparse(target)

    if parsed.scheme.lower() not in {
        "http",
        "https",
    }:
        raise ValueError(
            "O alvo deve utilizar HTTP ou HTTPS."
        )

    if not parsed.hostname:
        raise ValueError(
            "A URL precisa conter um hostname válido."
        )

    findings = []
    redirects = []
    cookies = []

    response = None

    try:

        with httpx.Client(
            timeout=TIMEOUT,
            follow_redirects=True,
            headers={
                "User-Agent": USER_AGENT,
                "Accept": (
                    "text/html,application/xhtml+xml,"
                    "application/json;q=0.9,*/*;q=0.8"
                ),
            },
            verify=True,
        ) as client:

            response = client.get(target)

    except httpx.ConnectTimeout as exc:

        finished_at = datetime.now(
            timezone.utc
        ).isoformat()

        _add_finding(
            findings,
            "Timeout de conexão",
            "medium",
            "Connectivity",
            str(exc),
            "O servidor não respondeu dentro do tempo configurado.",
            "Verificar disponibilidade do serviço e conectividade.",
        )

        return {
            "target": target,
            "final_url": target,
            "status_code": None,
            "started_at": started_at,
            "finished_at": finished_at,
            "duration_seconds": round(
                time.time() - started,
                2,
            ),
            "summary": _calculate_summary(findings),
            "findings": findings,
            "redirects": redirects,
            "cookies": cookies,
            "error": "Timeout de conexão.",
        }

    except httpx.ConnectError as exc:

        finished_at = datetime.now(
            timezone.utc
        ).isoformat()

        _add_finding(
            findings,
            "Falha de conexão",
            "medium",
            "Connectivity",
            str(exc),
            "Não foi possível estabelecer conexão com o alvo.",
            "Verificar DNS, conectividade, porta e disponibilidade do serviço.",
        )

        return {
            "target": target,
            "final_url": target,
            "status_code": None,
            "started_at": started_at,
            "finished_at": finished_at,
            "duration_seconds": round(
                time.time() - started,
                2,
            ),
            "summary": _calculate_summary(findings),
            "findings": findings,
            "redirects": redirects,
            "cookies": cookies,
            "error": "Falha de conexão.",
        }

    except httpx.HTTPError as exc:

        finished_at = datetime.now(
            timezone.utc
        ).isoformat()

        _add_finding(
            findings,
            "Erro HTTP durante a análise",
            "medium",
            "HTTP",
            str(exc),
            "A análise HTTP não conseguiu obter uma resposta válida.",
            "Verificar o serviço e a conectividade do alvo autorizado.",
        )

        return {
            "target": target,
            "final_url": target,
            "status_code": None,
            "started_at": started_at,
            "finished_at": finished_at,
            "duration_seconds": round(
                time.time() - started,
                2,
            ),
            "summary": _calculate_summary(findings),
            "findings": findings,
            "redirects": redirects,
            "cookies": cookies,
            "error": str(exc),
        }

    _analyze_status(
        response,
        findings,
    )

    _analyze_security_headers(
        response,
        parsed,
        findings,
    )

    _analyze_information_disclosure(
        response,
        findings,
    )

    _analyze_cors(
        response,
        findings,
    )

    _analyze_cookies(
        response,
        parsed,
        findings,
    )

    _analyze_content(
        response,
        parsed,
        findings,
    )

    _analyze_redirects(
        response,
        target,
        findings,
        redirects,
    )

    for raw_cookie in _extract_set_cookie_headers(
        response
    ):
        cookies.append(
            raw_cookie
        )

    finished_at = datetime.now(
        timezone.utc
    ).isoformat()

    return {
        "target": target,
        "final_url": str(response.url),
        "status_code": response.status_code,
        "started_at": started_at,
        "finished_at": finished_at,
        "duration_seconds": round(
            time.time() - started,
            2,
        ),
        "summary": _calculate_summary(
            findings
        ),
        "findings": findings,
        "redirects": redirects,
        "cookies": cookies,
        "response": {
            "content_type": _header(
                response.headers,
                "Content-Type",
            ),
            "content_length": _header(
                response.headers,
                "Content-Length",
            ),
            "server": _header(
                response.headers,
                "Server",
            ),
        },
    }
PY