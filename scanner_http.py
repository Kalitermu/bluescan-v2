cd ~/bluescan-v2

cp scanner_http.py scanner_http.backup.py

cat > scanner_http.py <<'PY'
import requests
from urllib.parse import urlparse


USER_AGENT = "BlueScan-Lab/2.1"

REQUEST_TIMEOUT = 15
METHOD_TIMEOUT = 10


SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "severity": "INFO",
        "description": (
            "Define quais recursos a página pode carregar e ajuda "
            "a reduzir determinados ataques no navegador."
        ),
        "recommendation": (
            "Avaliar a implementação de uma Content-Security-Policy "
            "adequada à aplicação."
        ),
    },
    "Strict-Transport-Security": {
        "severity": "INFO",
        "description": (
            "Permite que navegadores reforcem o uso de HTTPS."
        ),
        "recommendation": (
            "Em aplicações HTTPS, avaliar a implementação de "
            "Strict-Transport-Security."
        ),
    },
    "X-Content-Type-Options": {
        "severity": "LOW",
        "description": (
            "Ajuda a impedir que navegadores façam MIME sniffing."
        ),
        "recommendation": (
            "Adicionar X-Content-Type-Options: nosniff."
        ),
    },
    "X-Frame-Options": {
        "severity": "LOW",
        "description": (
            "Ajuda a controlar o carregamento da página em frames "
            "e reduzir riscos de clickjacking."
        ),
        "recommendation": (
            "Adicionar X-Frame-Options apropriado ou utilizar "
            "frame-ancestors na Content-Security-Policy."
        ),
    },
    "Referrer-Policy": {
        "severity": "INFO",
        "description": (
            "Controla quais informações de referência podem ser "
            "enviadas pelo navegador."
        ),
        "recommendation": (
            "Avaliar uma política Referrer-Policy adequada."
        ),
    },
    "Permissions-Policy": {
        "severity": "INFO",
        "description": (
            "Controla recursos e APIs disponíveis ao navegador."
        ),
        "recommendation": (
            "Avaliar uma Permissions-Policy adequada à aplicação."
        ),
    },
}


def add_finding(
    result,
    title,
    severity,
    category,
    evidence,
    recommendation,
):
    """
    Adiciona um achado evitando duplicações.
    """

    existing_titles = {
        finding.get("title")
        for finding in result["findings"]
    }

    if title in existing_titles:
        return

    result["findings"].append(
        {
            "title": title,
            "severity": str(severity).upper(),
            "category": category,
            "evidence": evidence,
            "recommendation": recommendation,
        }
    )


def normalized_headers(headers):
    """
    Cria mapa case-insensitive dos headers HTTP.
    """

    return {
        str(key).lower(): {
            "name": str(key),
            "value": value,
        }
        for key, value in headers.items()
    }


def get_header(headers, name):
    """
    Obtém um header sem depender de capitalização.
    """

    normalized = normalized_headers(headers)

    item = normalized.get(name.lower())

    if item:
        return item["value"]

    return None


def analyze_security_headers(result, response):
    """
    Analisa headers de segurança.
    """

    headers = response.headers

    for header, info in SECURITY_HEADERS.items():

        value = get_header(headers, header)

        if value is None:

            add_finding(
                result=result,
                title=f"{header} ausente",
                severity=info["severity"],
                category="Security Headers",
                evidence=(
                    f"O cabeçalho {header} não foi encontrado "
                    "na resposta HTTP."
                ),
                recommendation=info["recommendation"],
            )


def analyze_server_disclosure(result, response):
    """
    Analisa informações de identificação do servidor.
    """

    server = get_header(response.headers, "Server")

    if server:

        add_finding(
            result=result,
            title="Identificação do servidor exposta",
            severity="INFO",
            category="Information Disclosure",
            evidence=f"Server: {server}",
            recommendation=(
                "Avaliar se detalhes desnecessários de software "
                "e infraestrutura podem ser reduzidos em produção."
            ),
        )

    powered = get_header(response.headers, "X-Powered-By")

    if powered:

        add_finding(
            result=result,
            title="Tecnologia exposta por X-Powered-By",
            severity="LOW",
            category="Information Disclosure",
            evidence=f"X-Powered-By: {powered}",
            recommendation=(
                "Avaliar a remoção de X-Powered-By caso essa "
                "informação não seja necessária."
            ),
        )


def analyze_cookies(result, response, parsed):
    """
    Analisa atributos básicos de cookies recebidos.
    """

    for cookie in response.cookies:

        secure = bool(cookie.secure)

        httponly = cookie.has_nonstandard_attr(
            "HttpOnly"
        )

        samesite = cookie.get_nonstandard_attr(
            "SameSite"
        )

        if samesite is not None:
            samesite = str(samesite)

        cookie_info = {
            "name": cookie.name,
            "secure": secure,
            "httponly": httponly,
            "samesite": samesite,
        }

        result["cookies"].append(cookie_info)

        # HTTPS + cookie sem Secure
        if parsed.scheme.lower() == "https" and not secure:

            add_finding(
                result=result,
                title=f"Cookie sem atributo Secure: {cookie.name}",
                severity="LOW",
                category="Cookies",
                evidence=(
                    f"Cookie '{cookie.name}' foi recebido "
                    "sem o atributo Secure."
                ),
                recommendation=(
                    "Avaliar o uso do atributo Secure em cookies "
                    "transmitidos por HTTPS."
                ),
            )

        # Cookie sem HttpOnly
        if not httponly:

            add_finding(
                result=result,
                title=f"Cookie sem atributo HttpOnly: {cookie.name}",
                severity="INFO",
                category="Cookies",
                evidence=(
                    f"Cookie '{cookie.name}' não apresentou "
                    "o atributo HttpOnly."
                ),
                recommendation=(
                    "Quando o cookie não precisar ser acessado "
                    "por JavaScript, avaliar o uso de HttpOnly."
                ),
            )

        # SameSite
        if not samesite:

            add_finding(
                result=result,
                title=f"Cookie sem SameSite explícito: {cookie.name}",
                severity="INFO",
                category="Cookies",
                evidence=(
                    f"Cookie '{cookie.name}' não apresentou "
                    "SameSite explícito."
                ),
                recommendation=(
                    "Avaliar uma política SameSite adequada, "
                    "como Lax ou Strict conforme o funcionamento "
                    "da aplicação."
                ),
            )


def analyze_content(result, response):
    """
    Analisa características básicas da resposta.
    """

    content_type = get_header(
        response.headers,
        "Content-Type",
    )

    content_length = get_header(
        response.headers,
        "Content-Length",
    )

    result["content"] = {
        "content_type": content_type,
        "content_length": content_length,
        "size_bytes": len(response.content),
    }

    if not content_type:

        add_finding(
            result=result,
            title="Content-Type ausente",
            severity="LOW",
            category="HTTP Configuration",
            evidence=(
                "A resposta HTTP não apresentou "
                "o cabeçalho Content-Type."
            ),
            recommendation=(
                "Definir um Content-Type apropriado "
                "para a resposta."
            ),
        )


def analyze_redirects(result, response):
    """
    Registra e analisa redirects observados durante a requisição.
    """

    for redirect in response.history:

        location = get_header(
            redirect.headers,
            "Location",
        )

        result["redirects"].append(
            {
                "status": redirect.status_code,
                "from": redirect.url,
                "location": location,
                "to": location,
            }
        )

        if location:

            source_scheme = urlparse(
                redirect.url
            ).scheme.lower()

            destination = urlparse(
                location
            )

            # URL absoluta
            destination_scheme = (
                destination.scheme.lower()
            )

            if (
                source_scheme == "https"
                and destination_scheme == "http"
            ):

                add_finding(
                    result=result,
                    title="Redirect de HTTPS para HTTP",
                    severity="MEDIUM",
                    category="Redirects",
                    evidence=(
                        f"{redirect.url} redireciona para "
                        f"{location}."
                    ),
                    recommendation=(
                        "Evitar redirecionamentos de HTTPS "
                        "para HTTP e manter o fluxo protegido."
                    ),
                )


def analyze_http_methods(result, url):
    """
    Realiza verificações HTTP não destrutivas de OPTIONS e HEAD.
    """

    headers = {
        "User-Agent": USER_AGENT
    }

    # OPTIONS
    try:

        options = requests.options(
            url,
            timeout=METHOD_TIMEOUT,
            allow_redirects=False,
            headers=headers,
        )

        result["http_methods"]["OPTIONS"] = {
            "status": options.status_code,
            "allow": get_header(
                options.headers,
                "Allow",
            ),
        }

    except Exception as error:

        result["http_methods"]["OPTIONS"] = {
            "error": str(error)
        }

    # HEAD
    try:

        head = requests.head(
            url,
            timeout=METHOD_TIMEOUT,
            allow_redirects=False,
            headers=headers,
        )

        result["http_methods"]["HEAD"] = {
            "status": head.status_code,
        }

    except Exception as error:

        result["http_methods"]["HEAD"] = {
            "error": str(error)
        }


def scan_http(url):

    result = {
        "target": url,
        "status": None,
        "final_url": None,
        "redirects": [],
        "server": None,
        "headers": {},
        "cookies": [],
        "content": {},
        "http_methods": {},
        "findings": [],
    }

    parsed = urlparse(url)

    try:

        response = requests.get(
            url,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
            headers={
                "User-Agent": USER_AGENT
            },
        )

        result["status"] = response.status_code
        result["final_url"] = response.url

        result["server"] = get_header(
            response.headers,
            "Server",
        )

        result["headers"] = dict(
            response.headers
        )

        # -------------------------
        # Redirects
        # -------------------------

        analyze_redirects(
            result,
            response,
        )

        # -------------------------
        # Security Headers
        # -------------------------

        analyze_security_headers(
            result,
            response,
        )

        # -------------------------
        # Server disclosure
        # -------------------------

        analyze_server_disclosure(
            result,
            response,
        )

        # -------------------------
        # Cookies
        # -------------------------

        analyze_cookies(
            result,
            response,
            parsed,
        )

        # -------------------------
        # Content
        # -------------------------

        analyze_content(
            result,
            response,
        )

        # -------------------------
        # Métodos HTTP
        # -------------------------

        analyze_http_methods(
            result,
            url,
        )

    except requests.exceptions.Timeout as error:

        add_finding(
            result=result,
            title="Tempo limite da conexão HTTP",
            severity="INFO",
            category="Scanner",
            evidence=str(error),
            recommendation=(
                "Verifique a conectividade e a disponibilidade "
                "do alvo autorizado."
            ),
        )

        result["error"] = str(error)

    except requests.exceptions.RequestException as error:

        add_finding(
            result=result,
            title="Falha na conexão HTTP",
            severity="INFO",
            category="Scanner",
            evidence=str(error),
            recommendation=(
                "Verifique a conectividade, URL e disponibilidade "
                "do alvo autorizado."
            ),
        )

        result["error"] = str(error)

    except Exception as error:

        add_finding(
            result=result,
            title="Erro inesperado no scanner HTTP",
            severity="INFO",
            category="Scanner",
            evidence=str(error),
            recommendation=(
                "Verifique os logs do BlueScan para identificar "
                "a causa do erro."
            ),
        )

        result["error"] = str(error)

    return result
PY
