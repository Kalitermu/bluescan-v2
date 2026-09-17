import time
from datetime import datetime, timezone
from urllib.parse import urlparse

import httpx


def _finding(title, severity, category, source, evidence="", impact="", recommendation=""):
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

    parsed = urlparse(target)

    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Alvo inválido.")

    findings = []

    with httpx.Client(
        timeout=15.0,
        follow_redirects=True,
        headers={"User-Agent": "BlueScan/2.0"},
        verify=True,
    ) as client:
        response = client.get(target)

    headers = dict(response.headers)

    findings.append(_finding(
        f"HTTP {response.status_code}",
        "info",
        "HTTP",
        "BlueScan HTTP",
        f"Status HTTP: {response.status_code}",
        "O servidor respondeu à requisição.",
        "Manter o serviço monitorado.",
    ))

    if "server" in headers:
        findings.append(_finding(
            "Cabeçalho Server exposto",
            "low",
            "Information Disclosure",
            "BlueScan HTTP",
            f"Server: {headers["server"]}",
            "Pode revelar informações sobre o servidor.",
            "Avaliar a necessidade de expor essa informação.",
        ))

    security_headers = {
        "strict-transport-security": "HSTS",
        "content-security-policy": "CSP",
        "x-content-type-options": "X-Content-Type-Options",
        "x-frame-options": "X-Frame-Options",
        "referrer-policy": "Referrer-Policy",
        "permissions-policy": "Permissions-Policy",
    }

    for header, name in security_headers.items():
        if header not in headers:
            findings.append(_finding(
                f"{name} ausente",
                "low",
                "Security Headers",
                "BlueScan HTTP",
                f"Cabeçalho ausente: {name}",
                "Pode reduzir algumas proteções do navegador.",
                f"Avaliar a implementação de {name}.",
            ))

    if parsed.scheme == "http":
        findings.append(_finding(
            "Alvo acessado por HTTP",
            "medium",
            "Transport Security",
            "BlueScan HTTP",
            f"URL: {target}",
            "HTTP não oferece as mesmas garantias de confidencialidade do HTTPS.",
            "Avaliar HTTPS quando houver informações sensíveis.",
        ))

    finished_at = datetime.now(timezone.utc).isoformat()

    return {
        "target": target,
        "final_url": str(response.url),
        "status_code": response.status_code,
        "started_at": started_at,
        "finished_at": finished_at,
        "duration_seconds": round(time.time() - started, 2),
        "findings": findings,
    }
