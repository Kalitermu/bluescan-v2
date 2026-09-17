cd ~/bluescan-v2

cp scanner_http.py scanner_http.backup_antes_qualificacao.py

cat > scanner_http.py <<'PY'
import hashlib
from urllib.parse import urlparse

import requests


USER_AGENT = "BlueScan-Lab/2.2"

REQUEST_TIMEOUT = 15
METHOD_TIMEOUT = 10


SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "severity": "LOW",
        "type": "HARDENING",
        "recommendation": (
            "Avaliar a implementação de uma Content-Security-Policy "
            "adequada à aplicação."
        ),
        "impact": (
            "A ausência de uma CSP reduz uma camada de defesa "
            "contra determinados conteúdos e scripts não autorizados."
        ),
        "consequence": (
            "Dependendo da aplicação e de outras falhas existentes, "
            "a ausência dessa política pode aumentar o impacto de "
            "determinados ataques no navegador."
        ),
    },
    "Strict-Transport-Security": {
        "severity": "LOW",
        "type": "HARDENING",
        "recommendation": (
            "Em aplicações HTTPS, avaliar a implementação de "
            "Strict-Transport-Security."
        ),
        "impact": (
            "Sem HSTS, o navegador não recebe uma política explícita "
            "para exigir HTTPS em acessos futuros."
        ),
        "consequence": (
            "Em determinados cenários de rede, a ausência de HSTS "
            "pode reduzir a proteção contra downgrade ou acesso "
            "inicial sem HTTPS."
        ),
    },
    "X-Content-Type-Options": {
        "severity": "LOW",
        "type": "HARDENING",
        "recommendation": (
            "Adicionar X-Content-Type-Options: nosniff."
        ),
        "impact": (
            "A ausência de nosniff reduz uma proteção do navegador "
            "contra determinadas interpretações incorretas de tipos "
            "de conteúdo."
        ),
        "consequence": (
            "Dependendo do conteúdo servido, interpretações "
            "inesperadas pelo navegador podem aumentar a superfície "
            "de ataque."
        ),
    },
    "X-Frame-Options": {
        "severity": "LOW",
        "type": "HARDENING",
        "recommendation": (
            "Adicionar X-Frame-Options apropriado ou utilizar "
            "frame-ancestors na Content-Security-Policy."
        ),
        "impact": (
            "A ausência dessa proteção pode permitir que a página "
            "seja enquadrada por outro contexto quando a aplicação "
            "não possui outra política equivalente."
        ),
        "consequence": (
            "Dependendo da aplicação, isso pode aumentar a exposição "
            "a ataques baseados em enquadramento da interface."
        ),
    },
    "Referrer-Policy": {
        "severity": "INFO",
        "type": "HARDENING",
        "recommendation": (
            "Avaliar uma política Referrer-Policy adequada."
        ),
        "impact": (
            "Sem uma política explícita, o comportamento de envio "
            "do referenciador depende das regras padrão do navegador."
        ),
        "consequence": (
            "Dependendo das URLs acessadas, informações de contexto "
            "podem ser compartilhadas além do necessário."
        ),
    },
    "Permissions-Policy": {
        "severity": "INFO",
        "type": "HARDENING",
        "recommendation": (
            "Avaliar uma Permissions-Policy adequada à aplicação."
        ),
        "impact": (
            "A ausência de Permissions-Policy reduz o controle "
            "explícito sobre determinados recursos do navegador."
        ),
        "consequence": (
            "Recursos que não são necessários à aplicação podem "
            "permanecer disponíveis conforme o comportamento do "
            "navegador e dos componentes utilizados."
        ),
    },
}


def make_finding_id(prefix, title, evidence=""):
    raw = f"{prefix}|{title}|{evidence}"

    digest = hashlib.sha256(
        raw.encode("utf-8", errors="replace")
    ).hexdigest()[:10].upper()

    return f"BLUESCAN-{prefix}-{digest}"


def add_finding(
    result,
    title,
    severity,
    category,
    evidence,
    recommendation,
    finding_type="VULNERABILITY",
    status="CONFIRMED",
    confidence="HIGH",
    impact="",
    consequence="",
):
    existing_keys = {
        (
            finding.get("title"),
            finding.get("evidence"),
        )
        for finding in result["findings"]
    }

    key = (
        title,
        evidence,
    )

    if key in existing_keys:
        return

    result["findings"].append(
        {
            "id": make_finding_id(
                category.upper().replace(" ", "-"),
                title,
                evidence,
            ),
            "title": title,
            "severity": str(severity).upper(),
            "type": str(finding_type).upper(),
            "status": str(status).upper(),
            "confidence": str(confidence).upper(),
            "category": category,
            "source": "BlueScan HTTP",
            "evidence": evidence,
            "description": (
                f"O BlueScan identificou a condição: {title}."
            ),
            "impact": impact,
            "consequence": consequence,
            "recommendation": recommendation,
        }
    )


def get_header(headers, name):
    value = headers.get(name)

    if value is not None:
        return value

    name_lower = name.lower()

    for key, value in headers.items():
        if str(key).lower() == name_lower:
            return value

    return None


def analyze_security_headers(result, response):
    headers = response.headers

    for header, info in SECURITY_HEADERS.items():
        value = get_header(
            headers,
            header,
        )

        if value is not None:
            continue

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
            finding_type=info["type"],
            status="CONFIRMED",
            confidence="HIGH",
            impact=info["impact"],
            consequence=info["consequence"],
        )


def analyze_server_disclosure(result, response):
    server = get_header(
        response.headers,
        "Server",
    )

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
            finding_type="INFORMATION",
            status="CONFIRMED",
            confidence="HIGH",
            impact=(
                "O cabeçalho fornece uma informação adicional sobre "
                "a infraestrutura utilizada pelo serviço."
            ),
            consequence=(
                "A informação pode contribuir para o reconhecimento "
                "da tecnologia, mas não demonstra comprometimento "
                "por si só."
            ),
        )

    powered = get_header(
        response.headers,
        "X-Powered-By",
    )

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
            finding_type="INFORMATION",
            status="CONFIRMED",
            confidence="HIGH",
            impact=(
                "O cabeçalho pode revelar tecnologia ou componente "
                "utilizado pela aplicação."
            ),
            consequence=(
                "Essa informação pode facilitar o reconhecimento "
                "da tecnologia, mas não constitui vulnerabilidade "
                "explorável isoladamente."
            ),
        )


def analyze_cookies(result, response, parsed):
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

        result["cookies"].append(
            cookie_info
        )

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
                finding_type="HARDENING",
                status="CONFIRMED",
                confidence="HIGH",
                impact=(
                    "O cookie não possui uma restrição explícita "
                    "para transmissão somente por HTTPS."
                ),
                consequence=(
                    "Em determinados cenários, o cookie pode ficar "
                    "mais exposto caso seja enviado por uma conexão "
                    "não protegida."
                ),
            )

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
                finding_type="HARDENING",
                status="CONFIRMED",
                confidence="HIGH",
                impact=(
                    "O cookie pode permanecer acessível a scripts "
                    "executados no contexto da página."
                ),
                consequence=(
                    "Caso exista outra vulnerabilidade que permita "
                    "execução de script, a ausência de HttpOnly "
                    "pode aumentar o impacto sobre o cookie."
                ),
            )

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
                finding_type="HARDENING",
                status="CONFIRMED",
                confidence="HIGH",
                impact=(
                    "Não existe uma política SameSite explicitamente "
                    "declarada para esse cookie."
                ),
                consequence=(
                    "O comportamento entre contextos de navegação "
                    "pode depender das regras padrão do navegador."
                ),
            )


def analyze_content(result, response):
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
            finding_type="HARDENING",
            status="CONFIRMED",
            confidence="HIGH",
            impact=(
                "A ausência do tipo de conteúdo reduz a clareza "
                "sobre como o recurso deve ser interpretado."
            ),
            consequence=(
                "Dependendo do recurso e do navegador, isso pode "
                "contribuir para interpretações inesperadas."
            ),
        )


def analyze_redirects(result, response):
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

        if not location:
            continue

        source_scheme = urlparse(
            redirect.url
        ).scheme.lower()

        destination = urlparse(
            location
        )

        destination_scheme = destination.scheme.lower()

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
                finding_type="VULNERABILITY",
                status="CONFIRMED",
                confidence="HIGH",
                impact=(
                    "O fluxo de navegação deixa HTTPS e direciona "
                    "o cliente para HTTP sem criptografia."
                ),
                consequence=(
                    "Dependendo do contexto, informações transmitidas "
                    "após o redirecionamento podem ficar expostas "
                    "na rede."
                ),
            )


def analyze_http_methods(result, url):
    headers = {
        "User-Agent": USER_AGENT
    }

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

        analyze_redirects(
            result,
            response,
        )

        analyze_security_headers(
            result,
            response,
        )

        analyze_server_disclosure(
            result,
            response,
        )

        analyze_cookies(
            result,
            response,
            parsed,
        )

        analyze_content(
            result,
            response,
        )

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
            finding_type="INFORMATION",
            status="INDICATION",
            confidence="HIGH",
            impact=(
                "O scanner não conseguiu concluir a comunicação "
                "HTTP dentro do tempo configurado."
            ),
            consequence=(
                "Não é possível concluir a avaliação HTTP completa "
                "com essa evidência."
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
            finding_type="INFORMATION",
            status="INDICATION",
            confidence="HIGH",
            impact=(
                "A comunicação HTTP não pôde ser concluída."
            ),
            consequence=(
                "A avaliação HTTP pode estar incompleta."
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
            finding_type="INFORMATION",
            status="INDICATION",
            confidence="HIGH",
            impact=(
                "O módulo HTTP encontrou uma condição inesperada."
            ),
            consequence=(
                "Parte da avaliação HTTP pode não ter sido concluída."
            ),
        )

        result["error"] = str(error)

    return result
PY

echo
echo "===== TESTE DE SINTAXE ====="
python3 -m py_compile scanner_http.py

if [ $? -eq 0 ]; then
    echo "OK - scanner_http.py sem erro de sintaxe"
else
    echo "ERRO - scanner_http.py possui erro de sintaxe"
    exit 1
fi

echo
echo "===== TESTE DE IMPORTAÇÃO ====="
python3 - <<'PY'
from scanner_http import scan_http

print("OK - scanner_http importado")
print("OK - scan_http disponível")
PY