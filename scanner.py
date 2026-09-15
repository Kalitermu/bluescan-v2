cat > scanner.py <<'PY'
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

import httpx


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


def scan_target(target):
    started = time.time()
    started_at = datetime.now(timezone.utc).isoformat()

    findings = []

    parsed = urlparse(target)

    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Alvo inválido.")

    headers = {
        "User-Agent": "BlueScan/2.0 Defensive Security Scanner",
        "Accept": "*/*",
    }

    try:
        with httpx.Client(
            timeout=15.0,
            follow_redirects=True,
            headers=headers,
            verify=True,
        ) as client:

            response = client.get(target)

        final_url = str(response.url)
        status_code = response.status_code
        response_headers = dict(response.headers)

        server = response_headers.get("server", "")
        powered_by = response_headers.get("x-powered-by", "")

        findings.append(
            _finding(
                title=f"HTTP {status_code}",
                severity="info",
                category="HTTP",
                source="BlueScan HTTP",
                evidence=f"Status HTTP: {status_code}",
                impact="O servidor respondeu à requisição HTTP.",
                recommendation="Manter o serviço monitorado e revisar periodicamente a exposição.",
            )
        )

        if server:
            findings.append(
                _finding(
                    title="Cabeçalho Server exposto",
                    severity="low",
                    category="Information Disclosure",
                    source="BlueScan HTTP",
                    evidence=f"Server: {server}",
                    impact="A identificação do servidor pode fornecer informações úteis para reconhecimento.",
                    recommendation="Avaliar a necessidade de expor informações detalhadas sobre o servidor.",
                )
            )

        if powered_by:
            findings.append(
                _finding(
                    title="Tecnologia exposta pelo cabeçalho HTTP",
                    severity="low",
                    category="Information Disclosure",
                    source="BlueScan HTTP",
                    evidence=f"X-Powered-By: {powered_by}",
                    impact="O cabeçalho pode revelar informações sobre a tecnologia utilizada.",
                    recommendation="Remover ou reduzir cabeçalhos que revelem detalhes desnecessários da tecnologia.",
                )
            )

        security_headers = {
            "strict-transport-security": "HSTS",
            "content-security-policy": "CSP",
            "x-content-type-options": "X-Content-Type-Options",
            "x-frame-options": "X-Frame-Options",
            "referrer-policy": "Referrer-Policy",
            "permissions-policy": "Permissions-Policy",
        }

        for header_name, display_name in security_headers.items():

            if header_name not in response_headers:

                findings.append(
                    _finding(
                        title=f"{display_name} ausente",
                        severity="low",
                        category="Security Headers",
                        source="BlueScan HTTP",
                        evidence=f"Cabeçalho ausente: {display_name}",
                        impact="A ausência pode reduzir algumas proteções de segurança do navegador.",
                        recommendation=f"Avaliar a implementação de {display_name} conforme a arquitetura e os requisitos da aplicação.",
                    )
                )

        if parsed.scheme == "https":

            if "strict-transport-security" in response_headers:
                findings.append(
                    _finding(
                        title="HSTS configurado",
                        severity="info",
                        category="Security Headers",
                        source="BlueScan HTTP",
                        evidence="Strict-Transport-Security presente.",
                        impact="O site informa ao navegador uma política de transporte seguro.",
                        recommendation="Manter a configuração revisada e adequada ao domínio.",
                    )
                )

        else:

            findings.append(
                _finding(
                    title="Alvo acessado por HTTP",
                    severity="medium",
                    category="Transport Security",
                    source="BlueScan HTTP",
                    evidence=f"URL utilizada: {target}",
                    impact="O tráfego HTTP não fornece as mesmas garantias de confidencialidade e integridade do HTTPS.",
                    recommendation="Para aplicações que tratam informações sensíveis, avaliar a utilização de HTTPS.",
                )
            )

        content_length = len(response.content)

        findings.append(
            _finding(
                title="Resposta HTTP recebida",
                severity="info",
                category="HTTP",
                source="BlueScan HTTP",
                evidence=f"URL final: {final_url} | Status: {status_code} | Corpo: {content_length} bytes",
                impact="A resposta foi recebida e pode ser utilizada para análise defensiva.",
                recommendation="Correlacionar os resultados HTTP com os demais controles de segurança.",
            )
        )

        finished_at = datetime.now(timezone.utc).isoformat()
        duration = round(time.time() - started, 2)

        return {
            "target": target,
            "final_url": final_url,
            "status_code": status_code,
            "started_at": started_at,
            "finished_at": finished_at,
            "duration_seconds": duration,
            "findings": findings,
        }

    except httpx.TimeoutException as error:

        raise RuntimeError(
            f"Tempo limite excedido ao acessar o alvo: {error}"
        ) from error

    except httpx.HTTPError as error:

        raise RuntimeError(
            f"Erro HTTP durante a análise: {error}"
        ) from error

    except Exception as error:

        raise RuntimeError(
            f"Erro durante a análise: {error}"
        ) from error
PY