import requests
from urllib.parse import urlparse


USER_AGENT = "BlueScan-Lab/2.0"


SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "severity": "HARDENING",
        "description": "Controla quais recursos uma página pode carregar."
    },
    "Strict-Transport-Security": {
        "severity": "HARDENING",
        "description": "Ajuda a forçar conexões HTTPS."
    },
    "X-Content-Type-Options": {
        "severity": "LOW",
        "description": "Ajuda a evitar MIME sniffing."
    },
    "X-Frame-Options": {
        "severity": "LOW",
        "description": "Ajuda a reduzir riscos de clickjacking."
    },
    "Referrer-Policy": {
        "severity": "HARDENING",
        "description": "Controla informações enviadas pelo Referer."
    },
    "Permissions-Policy": {
        "severity": "HARDENING",
        "description": "Controla recursos sensíveis disponíveis ao navegador."
    }
}


def add_finding(
    result,
    title,
    severity,
    category,
    evidence,
    recommendation
):
    result["findings"].append({
        "title": title,
        "severity": severity,
        "category": category,
        "evidence": evidence,
        "recommendation": recommendation
    })


def scan_http(url):

    result = {
        "target": url,
        "status": None,
        "final_url": None,
        "redirects": [],
        "server": None,
        "headers": {},
        "cookies": [],
        "http_methods": {},
        "findings": []
    }

    parsed = urlparse(url)

    try:

        response = requests.get(
            url,
            timeout=15,
            allow_redirects=True,
            headers={
                "User-Agent": USER_AGENT
            }
        )

        result["status"] = response.status_code
        result["final_url"] = response.url
        result["server"] = response.headers.get("Server")
        result["headers"] = dict(response.headers)

        # -------------------------
        # Redirects
        # -------------------------

        for redirect in response.history:

            result["redirects"].append({
                "status": redirect.status_code,
                "from": redirect.url,
                "location": redirect.headers.get("Location")
            })

        # -------------------------
        # Security Headers
        # -------------------------

        for header, info in SECURITY_HEADERS.items():

            if header not in response.headers:

                severity = info["severity"]

                add_finding(
                    result,
                    f"{header} ausente",
                    severity,
                    "Security Headers",
                    f"O cabeçalho {header} não foi encontrado.",
                    info["description"]
                )

        # -------------------------
        # Server disclosure
        # -------------------------

        server = response.headers.get("Server")

        if server:

            add_finding(
                result,
                "Identificação do servidor exposta",
                "INFO",
                "Information Disclosure",
                f"Server: {server}",
                "Avaliar se essa informação pode ser reduzida em produção."
            )

        # -------------------------
        # X-Powered-By
        # -------------------------

        powered = response.headers.get("X-Powered-By")

        if powered:

            add_finding(
                result,
                "Tecnologia exposta por X-Powered-By",
                "LOW",
                "Information Disclosure",
                f"X-Powered-By: {powered}",
                "Avaliar a remoção desse cabeçalho."
            )

        # -------------------------
        # Cookies
        # -------------------------

        for cookie in response.cookies:

            secure = cookie.secure
            httponly = cookie.has_nonstandard_attr("HttpOnly")
            samesite = cookie.get_nonstandard_attr("SameSite")

            cookie_info = {
                "name": cookie.name,
                "secure": secure,
                "httponly": httponly,
                "samesite": samesite
            }

            result["cookies"].append(cookie_info)

            if parsed.scheme == "https" and not secure:

                add_finding(
                    result,
                    f"Cookie sem atributo Secure: {cookie.name}",
                    "LOW",
                    "Cookies",
                    f"Cookie: {cookie.name}",
                    "Avaliar a utilização de Secure em cookies HTTPS."
                )

        # -------------------------
        # Content-Type
        # -------------------------

        content_type = response.headers.get("Content-Type")

        if not content_type:

            add_finding(
                result,
                "Content-Type ausente",
                "LOW",
                "HTTP Configuration",
                "A resposta não possui Content-Type.",
                "Definir Content-Type apropriado para as respostas."
            )

        # -------------------------
        # OPTIONS
        # -------------------------

        try:

            options = requests.options(
                url,
                timeout=10,
                allow_redirects=False,
                headers={
                    "User-Agent": USER_AGENT
                }
            )

            result["http_methods"]["OPTIONS"] = {
                "status": options.status_code,
                "allow": options.headers.get("Allow")
            }

        except Exception as error:

            result["http_methods"]["OPTIONS"] = {
                "error": str(error)
            }

        # -------------------------
        # HEAD
        # -------------------------

        try:

            head = requests.head(
                url,
                timeout=10,
                allow_redirects=False,
                headers={
                    "User-Agent": USER_AGENT
                }
            )

            result["http_methods"]["HEAD"] = {
                "status": head.status_code
            }

        except Exception as error:

            result["http_methods"]["HEAD"] = {
                "error": str(error)
            }

    except Exception as error:

        add_finding(
            result,
            "Falha na conexão HTTP",
            "INFO",
            "Scanner",
            str(error),
            "Verifique a conectividade do laboratório."
        )

    return result
