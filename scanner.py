cd ~/bluescan-v2
source .venv/bin/activate

cp scanner.py scanner.before_httpx.py

cat > scanner.py <<'PY'
from datetime import datetime, timezone
import json
import re
import subprocess
import time
from urllib.parse import urlparse
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
import ssl
import socket


HTTPX_BIN = "/usr/bin/httpx-toolkit"
WHATWEB_BIN = "whatweb"


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def normalize_target(target):
    target = target.strip()

    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    return target.rstrip("/")


def get_host(target):
    parsed = urlparse(target)
    return parsed.hostname


def run_command(command, timeout=30):
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout
        )

        return {
            "returncode": result.returncode,
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip()
        }

    except subprocess.TimeoutExpired as exc:
        return {
            "returncode": -1,
            "stdout": "",
            "stderr": f"timeout após {timeout}s"
        }

    except FileNotFoundError:
        return {
            "returncode": -2,
            "stdout": "",
            "stderr": f"programa não encontrado: {command[0]}"
        }

    except Exception as exc:
        return {
            "returncode": -3,
            "stdout": "",
            "stderr": str(exc)
        }


def check_security_headers(headers):
    findings = []

    normalized = {
        str(k).lower(): str(v)
        for k, v in headers.items()
    }

    if "content-security-policy" not in normalized:
        findings.append({
            "title": "Content-Security-Policy ausente",
            "severity": "INFO",
            "category": "Security Headers",
            "evidence": "O cabeçalho Content-Security-Policy não foi encontrado.",
            "recommendation": "Controla quais recursos uma página pode carregar."
        })

    if "x-content-type-options" not in normalized:
        findings.append({
            "title": "X-Content-Type-Options ausente",
            "severity": "LOW",
            "category": "Security Headers",
            "evidence": "O cabeçalho X-Content-Type-Options não foi encontrado.",
            "recommendation": "Ajuda a evitar MIME sniffing."
        })

    if "x-frame-options" not in normalized:
        findings.append({
            "title": "X-Frame-Options ausente",
            "severity": "LOW",
            "category": "Security Headers",
            "evidence": "O cabeçalho X-Frame-Options não foi encontrado.",
            "recommendation": "Ajuda a reduzir riscos de clickjacking."
        })

    if "referrer-policy" not in normalized:
        findings.append({
            "title": "Referrer-Policy ausente",
            "severity": "INFO",
            "category": "Security Headers",
            "evidence": "O cabeçalho Referrer-Policy não foi encontrado.",
            "recommendation": "Controla informações enviadas pelo Referer."
        })

    if "permissions-policy" not in normalized:
        findings.append({
            "title": "Permissions-Policy ausente",
            "severity": "INFO",
            "category": "Security Headers",
            "evidence": "O cabeçalho Permissions-Policy não foi encontrado.",
            "recommendation": "Controla recursos sensíveis disponíveis ao navegador."
        })

    server = normalized.get("server")

    if server:
        findings.append({
            "title": "Identificação da plataforma exposta",
            "severity": "INFO",
            "category": "Information Disclosure",
            "evidence": f"Server: {server}",
            "recommendation": "Avaliar se essa informação é necessária em produção."
        })

    return findings


def scan_http(target):
    started = time.time()

    result = {
        "target": target,
        "status": None,
        "final_url": None,
        "redirects": [],
        "server": None,
        "headers": {},
        "cookies": [],
        "http_methods": {},
        "findings": []
    }

    try:
        request = Request(
            target,
            headers={
                "User-Agent": "BlueScan/3.0"
            },
            method="GET"
        )

        with urlopen(request, timeout=15) as response:
            result["status"] = response.status
            result["final_url"] = response.geturl()

            result["headers"] = dict(response.headers.items())

            result["server"] = response.headers.get("Server")

            set_cookie = response.headers.get_all("Set-Cookie")

            if set_cookie:
                result["cookies"] = set_cookie

            result["findings"] = check_security_headers(
                response.headers
            )

    except HTTPError as exc:
        result["status"] = exc.code
        result["final_url"] = target

        try:
            result["headers"] = dict(exc.headers.items())
            result["server"] = exc.headers.get("Server")
            result["findings"] = check_security_headers(exc.headers)
        except Exception:
            pass

    except Exception as exc:
        result["error"] = str(exc)

    elapsed = round(time.time() - started, 2)

    result["duration_seconds"] = elapsed

    return result


def scan_dns(target):
    host = get_host(target)

    result = {
        "target": host,
        "records": {
            "A": [],
            "AAAA": [],
            "CNAME": [],
            "MX": [],
            "NS": [],
            "TXT": []
        },
        "findings": []
    }

    if not host:
        result["error"] = "hostname inválido"
        return result

    for record_type, family in [
        ("A", socket.AF_INET),
        ("AAAA", socket.AF_INET6)
    ]:
        try:
            addresses = socket.getaddrinfo(
                host,
                443,
                family,
                socket.SOCK_STREAM
            )

            values = set()

            for item in addresses:
                values.add(item[4][0])

            result["records"][record_type] = sorted(values)

        except Exception:
            pass

    return result


def scan_tls(target):
    host = get_host(target)

    result = {
        "target": target,
        "host": host,
        "port": 443
    }

    if not host:
        result["status"] = "error"
        result["error"] = "hostname inválido"
        return result

    try:
        context = ssl.create_default_context()

        with socket.create_connection(
            (host, 443),
            timeout=10
        ) as sock:

            with context.wrap_socket(
                sock,
                server_hostname=host
            ) as tls_sock:

                cert = tls_sock.getpeercert()

                result["tls_version"] = tls_sock.version()

                result["cipher"] = list(
                    tls_sock.cipher()
                ) if tls_sock.cipher() else None

                result["certificate"] = {
                    "subject": str(cert.get("subject")),
                    "issuer": str(cert.get("issuer")),
                    "serial_number": cert.get("serialNumber"),
                    "not_before": cert.get("notBefore"),
                    "not_after": cert.get("notAfter"),
                    "san": [
                        value
                        for kind, value in cert.get("subjectAltName", [])
                        if kind == "DNS"
                    ]
                }

                result["findings"] = [{
                    "title": "Versão TLS moderna negociada",
                    "severity": "INFO",
                    "category": "TLS",
                    "evidence": tls_sock.version()
                }]

                result["status"] = "ok"

    except Exception as exc:
        result["status"] = "error"
        result["error"] = str(exc)

    return result


def scan_httpx(target):
    """
    Substituto do módulo Nmap.
    Focado em enumeração HTTP/HTTPS e identificação da superfície web.
    """

    result = {
        "status": "unknown",
        "target": target,
        "tool": "httpx-toolkit",
        "findings": []
    }

    command = [
        HTTPX_BIN,
        "-u",
        target,
        "-status-code",
        "-title",
        "-tech-detect",
        "-server",
        "-location",
        "-silent"
    ]

    execution = run_command(
        command,
        timeout=30
    )

    result["returncode"] = execution["returncode"]

    if execution["returncode"] == -2:
        result["status"] = "unavailable"
        result["message"] = (
            "httpx-toolkit não encontrado no ambiente."
        )
        return result

    if execution["returncode"] == -1:
        result["status"] = "timeout"
        result["message"] = (
            "httpx-toolkit excedeu o tempo limite."
        )
        return result

    if execution["returncode"] != 0:
        result["status"] = "error"
        result["message"] = execution["stderr"] or (
            "httpx-toolkit retornou erro."
        )
        return result

    output = execution["stdout"]

    if not output:
        result["status"] = "no_result"
        result["message"] = (
            "httpx-toolkit executou, mas não retornou dados."
        )
        return result

    result["status"] = "ok"
    result["raw"] = output

    lines = output.splitlines()

    result["results"] = lines

    for line in lines:
        result["findings"].append({
            "title": "Endpoint HTTP identificado",
            "severity": "INFO",
            "category": "Web Surface",
            "evidence": line
        })

    return result


def scan_whatweb(target):
    result = {
        "status": "unknown",
        "url": target,
        "plugins": []
    }

    execution = run_command(
        [
            WHATWEB_BIN,
            "--quiet",
            target
        ],
        timeout=30
    )

    result["returncode"] = execution["returncode"]

    if execution["returncode"] == -2:
        result["status"] = "unavailable"
        result["message"] = "WhatWeb não encontrado."
        return result

    if execution["returncode"] == -1:
        result["status"] = "timeout"
        result["message"] = "WhatWeb excedeu o tempo limite."
        return result

    if execution["returncode"] != 0:
        result["status"] = "error"
        result["message"] = execution["stderr"]
        return result

    result["status"] = "ok"
    result["raw"] = execution["stdout"]

    return result


def build_security_checks(http_result):
    findings = []

    for finding in http_result.get("findings", []):
        item = dict(finding)

        item["status"] = "INDICATION"
        item["source"] = "BlueScan Checks"

        findings.append(item)

    return {
        "status": "ok",
        "target": http_result.get("target"),
        "final_url": http_result.get("final_url"),
        "http_status": http_result.get("status"),
        "findings": findings,
        "count": len(findings),
        "timeout_seconds": 15
    }


def build_correlation(http_result, tls_result, httpx_result):
    findings = []

    for finding in http_result.get("findings", []):
        title = finding.get("title", "")
        severity = finding.get("severity", "INFO")

        if severity == "LOW":
            finding_type = "CONFIGURATION"
        else:
            finding_type = "HARDENING"

        findings.append({
            "id": re.sub(
                r"[^a-z0-9]+",
                "-",
                title.lower()
            ).strip("-"),
            "title": title,
            "severity": severity,
            "type": finding_type,
            "status": "CONFIRMED",
            "confidence": "HIGH",
            "category": finding.get("category"),
            "source": "HTTP",
            "cve": None,
            "cwe": None,
            "evidence": finding.get("evidence"),
            "description": finding.get("evidence"),
            "impact": finding.get("recommendation"),
            "consequence": (
                "Achado de configuração ou hardening; "
                "não representa confirmação de exploração."
            ),
            "recommendation": finding.get("recommendation"),
            "validation": (
                "Executar novamente o BlueScan e verificar "
                "o comportamento esperado."
            )
        })

    if tls_result.get("status") == "ok":
        tls_version = tls_result.get("tls_version")

        findings.append({
            "id": "versao-tls-moderna-negociada",
            "title": "Versão TLS moderna negociada",
            "severity": "INFO",
            "type": "INFORMATION",
            "status": "CONFIRMED",
            "confidence": "HIGH",
            "category": "TLS",
            "source": "TLS",
            "cve": None,
            "cwe": None,
            "evidence": tls_version,
            "description": (
                "A conexão analisada negociou uma "
                "versão moderna do protocolo TLS."
            ),
            "impact": (
                "TLS moderno fornece uma base criptográfica "
                "adequada para HTTPS."
            ),
            "consequence": (
                "Este achado é positivo e não representa "
                "uma vulnerabilidade."
            ),
            "recommendation": (
                "Manter protocolos TLS modernos habilitados."
            ),
            "validation": (
                "Executar novamente o BlueScan e confirmar "
                "a versão TLS negociada."
            )
        })

    low = sum(
        1 for x in findings
        if x["severity"] == "LOW"
    )

    info = sum(
        1 for x in findings
        if x["severity"] == "INFO"
    )

    medium = sum(
        1 for x in findings
        if x["severity"] == "MEDIUM"
    )

    high = sum(
        1 for x in findings
        if x["severity"] == "HIGH"
    )

    critical = sum(
        1 for x in findings
        if x["severity"] == "CRITICAL"
    )

    vulnerabilities = sum(
        1 for x in findings
        if x["severity"] in {
            "CRITICAL",
            "HIGH",
            "MEDIUM"
        }
    )

    risk = "LOW"

    if critical:
        risk = "CRITICAL"
    elif high:
        risk = "HIGH"
    elif medium:
        risk = "MEDIUM"
    elif low:
        risk = "LOW"

    return {
        "risk": risk,
        "summary": {
            "total_findings": len(findings),
            "confirmed_findings": len(findings),
            "confirmed_vulnerabilities": vulnerabilities,
            "indications": 0,
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "info": info,
            "vulnerabilities": vulnerabilities,
            "configuration": sum(
                1 for x in findings
                if x["type"] == "CONFIGURATION"
            ),
            "hardening": sum(
                1 for x in findings
                if x["type"] == "HARDENING"
            ),
            "information": sum(
                1 for x in findings
                if x["type"] == "INFORMATION"
            )
        },
        "findings": findings
    }


def build_agent(target, correlation):
    return {
        "agent": "BlueScan Agent",
        "version": "1.0",
        "target": target,
        "analyzed_at": now_iso(),
        "risk": correlation["risk"],
        "confirmed_vulnerabilities": correlation[
            "summary"
        ]["confirmed_vulnerabilities"],
        "nuclei": {
            "total": 0,
            "confirmed": 0,
            "needs_review": 0,
            "false_positive": 0,
            "likely_false_positive": 0
        },
        "findings": [
            {
                "source": "correlation",
                "title": item["title"],
                "severity": item["severity"],
                "confidence": item["confidence"],
                "status": "review"
            }
            for item in correlation["findings"]
            if item["severity"] != "INFO"
        ],
        "actions": [
            "Foram encontradas configurações que merecem avaliação."
        ],
        "conclusion": (
            "Nenhuma vulnerabilidade foi confirmada "
            "automaticamente pelo BlueScan Agent."
            if correlation["summary"][
                "confirmed_vulnerabilities"
            ] == 0
            else
            "Foram identificados achados que exigem "
            "revisão adicional."
        )
    }


def scan_target(target):
    target = normalize_target(target)

    started = now_iso()
    start_time = time.time()

    http_result = scan_http(target)
    tls_result = scan_tls(target)
    dns_result = scan_dns(target)
    httpx_result = scan_httpx(target)
    whatweb_result = scan_whatweb(target)

    security_checks = build_security_checks(
        http_result
    )

    correlation = build_correlation(
        http_result,
        tls_result,
        httpx_result
    )

    finished = now_iso()

    duration = round(
        time.time() - start_time,
        1
    )

    return {
        "target": target,
        "started_at": started,
        "finished_at": finished,
        "duration_seconds": duration,

        "http": http_result,

        "tls": tls_result,

        "dns": dns_result,

        "httpx": httpx_result,

        "technology": {
            "technologies": [],
            "count": 0
        },

        "whatweb": whatweb_result,

        "security_checks": security_checks,

        "correlation": correlation,

        "agent": build_agent(
            target,
            correlation
        ),

        "nuclei": {
            "status": "disabled",
            "target": target,
            "count": 0,
            "summary": {},
            "findings": [],
            "message": "Nuclei desativado no BlueScan."
        }
    }
PY

    