cat > scanner.py <<'PY'
from datetime import datetime, timezone
import json
import re
import shutil
import socket
import ssl
import subprocess
import time
from urllib.parse import urlparse

import httpx


# ============================================================
# CONFIGURAÇÕES
# ============================================================

DEFAULT_TIMEOUT = 10
COMMAND_TIMEOUT = 15
HTTPX_TIMEOUT = 15
WHATWEB_TIMEOUT = 20


# ============================================================
# UTILITÁRIOS
# ============================================================

def utc_now():
    return datetime.now(timezone.utc).isoformat()


def command_exists(command):
    return shutil.which(command) is not None


def run_command(command, timeout=COMMAND_TIMEOUT):
    """
    Executa comando externo com timeout.
    Nunca deixa o scanner ficar preso indefinidamente.
    """
    try:
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False
        )

        return {
            "returncode": process.returncode,
            "stdout": process.stdout.strip(),
            "stderr": process.stderr.strip(),
            "timeout": False,
        }

    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or ""
        stderr = exc.stderr or ""

        if isinstance(stdout, bytes):
            stdout = stdout.decode(errors="ignore")

        if isinstance(stderr, bytes):
            stderr = stderr.decode(errors="ignore")

        return {
            "returncode": -1,
            "stdout": stdout.strip(),
            "stderr": stderr.strip(),
            "timeout": True,
        }

    except Exception as exc:
        return {
            "returncode": -1,
            "stdout": "",
            "stderr": str(exc),
            "timeout": False,
        }


def normalize_target(target):
    target = str(target or "").strip()

    if not target:
        return ""

    if not re.match(r"^https?://", target, re.I):
        target = "https://" + target

    return target.rstrip("/")


def get_hostname(target):
    try:
        return urlparse(target).hostname or ""
    except Exception:
        return ""


def unique_list(values):
    result = []

    for value in values:
        if value and value not in result:
            result.append(value)

    return result


# ============================================================
# HTTP
# ============================================================

def scan_http(target):
    result = {
        "target": target,
        "status": None,
        "final_url": None,
        "server": None,
        "content_type": None,
        "content_length": None,
        "headers": {},
        "redirects": [],
        "error": None,
    }

    try:
        headers = {
            "User-Agent": "BlueScan/2.0 Security Scanner"
        }

        with httpx.Client(
            timeout=DEFAULT_TIMEOUT,
            follow_redirects=True,
            verify=True,
            headers=headers
        ) as client:

            response = client.get(target)

            result["status"] = response.status_code
            result["final_url"] = str(response.url)

            result["server"] = response.headers.get("server")
            result["content_type"] = response.headers.get("content-type")

            content_length = response.headers.get("content-length")

            if content_length:
                try:
                    result["content_length"] = int(content_length)
                except Exception:
                    result["content_length"] = content_length

            for key, value in response.headers.items():
                result["headers"][key.lower()] = value

            for history_response in response.history:
                result["redirects"].append({
                    "status": history_response.status_code,
                    "url": str(history_response.url),
                    "location": history_response.headers.get("location")
                })

    except Exception as exc:
        result["error"] = str(exc)

    return result


# ============================================================
# TLS
# ============================================================

def scan_tls(target):
    result = {
        "target": target,
        "hostname": None,
        "port": 443,
        "tls": None,
        "cipher": None,
        "certificate": {},
        "error": None,
    }

    try:
        parsed = urlparse(target)
        hostname = parsed.hostname

        result["hostname"] = hostname

        if not hostname:
            result["error"] = "Hostname não identificado."
            return result

        port = parsed.port or 443
        result["port"] = port

        context = ssl.create_default_context()

        with socket.create_connection(
            (hostname, port),
            timeout=DEFAULT_TIMEOUT
        ) as raw_socket:

            with context.wrap_socket(
                raw_socket,
                server_hostname=hostname
            ) as tls_socket:

                result["tls"] = tls_socket.version()

                cipher = tls_socket.cipher()

                if cipher:
                    result["cipher"] = {
                        "name": cipher[0],
                        "protocol": cipher[1],
                        "bits": cipher[2],
                    }

                certificate = tls_socket.getpeercert()

                if certificate:
                    result["certificate"] = {
                        "subject": certificate.get("subject"),
                        "issuer": certificate.get("issuer"),
                        "version": certificate.get("version"),
                        "serialNumber": certificate.get("serialNumber"),
                        "notBefore": certificate.get("notBefore"),
                        "notAfter": certificate.get("notAfter"),
                    }

    except Exception as exc:
        result["error"] = str(exc)

    return result


# ============================================================
# DNS
# ============================================================

def scan_dns(target):
    hostname = get_hostname(target)

    result = {
        "hostname": hostname,
        "addresses": [],
        "ipv4": [],
        "ipv6": [],
        "canonical_name": None,
        "error": None,
    }

    if not hostname:
        result["error"] = "Hostname não identificado."
        return result

    try:
        infos = socket.getaddrinfo(
            hostname,
            None,
            socket.AF_UNSPEC,
            socket.SOCK_STREAM
        )

        addresses = []

        for info in infos:
            family = info[0]
            sockaddr = info[4]

            if not sockaddr:
                continue

            address = sockaddr[0]

            if address not in addresses:
                addresses.append(address)

            if family == socket.AF_INET:
                if address not in result["ipv4"]:
                    result["ipv4"].append(address)

            elif family == socket.AF_INET6:
                if address not in result["ipv6"]:
                    result["ipv6"].append(address)

        result["addresses"] = addresses

        # Tentativa adicional de descobrir o CNAME.
        dig = shutil.which("dig")

        if dig:
            command = [
                dig,
                "+short",
                "CNAME",
                hostname
            ]

            dig_result = run_command(
                command,
                timeout=10
            )

            if dig_result["returncode"] == 0:
                lines = [
                    line.strip().rstrip(".")
                    for line in dig_result["stdout"].splitlines()
                    if line.strip()
                ]

                if lines:
                    result["canonical_name"] = lines[0]

    except Exception as exc:
        result["error"] = str(exc)

    return result


# ============================================================
# HTTPX
# ============================================================

def scan_httpx(target):
    result = {
        "target": target,
        "available": command_exists("httpx"),
        "status": None,
        "url": None,
        "final_url": None,
        "title": None,
        "webserver": None,
        "technologies": [],
        "raw": "",
        "error": None,
    }

    if not result["available"]:
        result["error"] = "httpx não encontrado no PATH."
        return result

    command = [
        "httpx",
        "-u",
        target,
        "-silent",
        "-status-code",
        "-location",
        "-title",
        "-web-server",
        "-tech-detect",
    ]

    command_result = run_command(
        command,
        timeout=HTTPX_TIMEOUT
    )

    raw = command_result["stdout"]

    result["raw"] = raw

    if command_result["timeout"]:
        result["error"] = "HTTPX excedeu o tempo limite."
        return result

    if command_result["returncode"] != 0 and not raw:
        result["error"] = (
            command_result["stderr"]
            or "HTTPX retornou erro."
        )
        return result

    if raw:
        first_line = raw.splitlines()[0].strip()

        result["url"] = first_line

        status_match = re.search(
            r"\[(\d{3})\]",
            first_line
        )

        if status_match:
            try:
                result["status"] = int(
                    status_match.group(1)
                )
            except Exception:
                pass

        location_match = re.search(
            r"\[(https?://[^\]]+)\]",
            first_line,
            re.I
        )

        if location_match:
            result["final_url"] = (
                location_match.group(1)
            )

        tech_match = re.search(
            r"\[([^\]]+)\]",
            first_line
        )

        bracket_values = re.findall(
            r"\[([^\]]+)\]",
            first_line
        )

        if bracket_values:
            for value in bracket_values:
                value = value.strip()

                if (
                    re.match(r"^\d{3}$", value)
                    or value.lower().startswith("http")
                ):
                    continue

                if value not in result["technologies"]:
                    result["technologies"].append(value)

        if "title" in first_line.lower():
            result["title"] = first_line

    return result


# ============================================================
# TECNOLOGIAS
# ============================================================

def scan_technologies(target, http_result):
    result = {
        "technologies": [],
        "source": [],
        "server": http_result.get("server"),
        "error": None,
    }

    technologies = []

    server = (
        http_result.get("server")
        or ""
    ).lower()

    headers = http_result.get("headers") or {}

    powered_by = (
        headers.get("x-powered-by")
        or ""
    )

    if "github" in server:
        technologies.append("GitHub Pages")

    if "cloudflare" in server:
        technologies.append("Cloudflare")

    if "nginx" in server:
        technologies.append("Nginx")

    if "apache" in server:
        technologies.append("Apache")

    if powered_by:
        technologies.append(
            powered_by.strip()
        )

    # Headers comuns que ajudam na identificação.
    if "server" in headers:
        result["source"].append("HTTP Server Header")

    if "x-powered-by" in headers:
        result["source"].append("X-Powered-By")

    result["technologies"] = unique_list(
        technologies
    )

    return result


# ============================================================
# WHATWEB
# ============================================================

def scan_whatweb(target):
    result = {
        "available": command_exists("whatweb"),
        "plugins": [],
        "raw": "",
        "error": None,
    }

    if not result["available"]:
        result["error"] = "WhatWeb não encontrado."
        return result

    command = [
        "whatweb",
        "--quiet",
        "--aggression=1",
        target
    ]

    command_result = run_command(
        command,
        timeout=WHATWEB_TIMEOUT
    )

    result["raw"] = (
        command_result["stdout"]
        or command_result["stderr"]
    )

    if command_result["timeout"]:
        result["error"] = (
            "WhatWeb excedeu o tempo limite."
        )
        return result

    if command_result["returncode"] != 0:
        if not result["raw"]:
            result["error"] = (
                command_result["stderr"]
                or "WhatWeb retornou erro."
            )

    raw = result["raw"]

    if raw:
        # Extração simples dos plugins:
        # Exemplo:
        # [HTTPServer[GitHub.com], ...]
        matches = re.findall(
            r"([A-Za-z][A-Za-z0-9_-]*)\[([^\]]+)\]",
            raw
        )

        for name, value in matches:
            plugin = f"{name}: {value}"

            if plugin not in result["plugins"]:
                result["plugins"].append(plugin)

    return result


# ============================================================
# SECURITY CHECKS
# ============================================================

def add_check(
    checks,
    check_id,
    title,
    category,
    status,
    severity,
    evidence,
    recommendation
):
    checks.append({
        "id": check_id,
        "title": title,
        "category": category,
        "status": status,
        "severity": severity,
        "evidence": evidence,
        "recommendation": recommendation,
    })


def scan_security_checks(
    target,
    http_result,
    tls_result,
    dns_result
):
    checks = []

    headers = (
        http_result.get("headers")
        or {}
    )

    status = http_result.get("status")

    # --------------------------------------------------------
    # HTTPS
    # --------------------------------------------------------

    parsed = urlparse(target)

    if parsed.scheme.lower() == "https":
        add_check(
            checks,
            "HTTPS-001",
            "Comunicação HTTPS",
            "Transporte",
            "PASS",
            "INFO",
            "O alvo utiliza HTTPS.",
            "Manter HTTPS habilitado e evitar conteúdo HTTP."
        )
    else:
        add_check(
            checks,
            "HTTPS-001",
            "Comunicação HTTPS",
            "Transporte",
            "WARN",
            "LOW",
            "O alvo não utiliza HTTPS.",
            "Preferir HTTPS para proteger a comunicação."
        )

    # --------------------------------------------------------
    # HSTS
    # --------------------------------------------------------

    if parsed.scheme.lower() == "https":

        if "strict-transport-security" in headers:
            add_check(
                checks,
                "HDR-001",
                "Strict-Transport-Security",
                "Headers",
                "PASS",
                "INFO",
                "Header HSTS identificado.",
                "Manter HSTS configurado adequadamente."
            )
        else:
            add_check(
                checks,
                "HDR-001",
                "Strict-Transport-Security",
                "Headers",
                "WARN",
                "LOW",
                "Header Strict-Transport-Security não identificado.",
                "Avaliar a ativação do HSTS."
            )

    # --------------------------------------------------------
    # X-CONTENT-TYPE-OPTIONS
    # --------------------------------------------------------

    if (
        "x-content-type-options"
        in headers
    ):
        add_check(
            checks,
            "HDR-002",
            "X-Content-Type-Options",
            "Headers",
            "PASS",
            "INFO",
            "Header X-Content-Type-Options identificado.",
            "Manter configuração."
        )
    else:
        add_check(
            checks,
            "HDR-002",
            "X-Content-Type-Options",
            "Headers",
            "WARN",
            "LOW",
            "Header X-Content-Type-Options não identificado.",
            "Avaliar o uso de X-Content-Type-Options: nosniff."
        )

    # --------------------------------------------------------
    # CONTENT-SECURITY-POLICY
    # --------------------------------------------------------

    if "content-security-policy" in headers:
        add_check(
            checks,
            "HDR-003",
            "Content-Security-Policy",
            "Headers",
            "PASS",
            "INFO",
            "Header CSP identificado.",
            "Manter a política CSP revisada."
        )
    else:
        add_check(
            checks,
            "HDR-003",
            "Content-Security-Policy",
            "Headers",
            "WARN",
            "LOW",
            "Header Content-Security-Policy não identificado.",
            "Avaliar uma política CSP adequada à aplicação."
        )

    # --------------------------------------------------------
    # REFERRER-POLICY
    # --------------------------------------------------------

    if "referrer-policy" in headers:
        add_check(
            checks,
            "HDR-004",
            "Referrer-Policy",
            "Headers",
            "PASS",
            "INFO",
            "Header Referrer-Policy identificado.",
            "Manter configuração."
        )
    else:
        add_check(
            checks,
            "HDR-004",
            "Referrer-Policy",
            "Headers",
            "WARN",
            "LOW",
            "Header Referrer-Policy não identificado.",
            "Avaliar configuração de Referrer-Policy."
        )

    # --------------------------------------------------------
    # X-FRAME-OPTIONS
    # --------------------------------------------------------

    if (
        "x-frame-options" in headers
        or "content-security-policy" in headers
    ):
        add_check(
            checks,
            "HDR-005",
            "Proteção contra enquadramento",
            "Headers",
            "PASS",
            "INFO",
            "X-Frame-Options ou CSP identificado.",
            "Manter proteção contra framing."
        )
    else:
        add_check(
            checks,
            "HDR-005",
            "Proteção contra enquadramento",
            "Headers",
            "WARN",
            "LOW",
            "Não foi identificada proteção explícita contra framing.",
            "Avaliar X-Frame-Options ou CSP frame-ancestors."
        )

    # --------------------------------------------------------
    # SERVER HEADER
    # --------------------------------------------------------

    server = http_result.get("server")

    if server:
        add_check(
            checks,
            "HDR-006",
            "Exposição do cabeçalho Server",
            "Information Disclosure",
            "INFO",
            "INFO",
            f"Servidor informado pelo header: {server}",
            "Avaliar se a exposição detalhada é necessária."
        )

    # --------------------------------------------------------
    # STATUS HTTP
    # --------------------------------------------------------

    if status is not None:

        if 200 <= status < 400:
            add_check(
                checks,
                "HTTP-001",
                "Resposta HTTP válida",
                "HTTP",
                "PASS",
                "INFO",
                f"Servidor respondeu com HTTP {status}.",
                "Nenhuma ação necessária."
            )
        else:
            add_check(
                checks,
                "HTTP-001",
                "Resposta HTTP",
                "HTTP",
                "INFO",
                "INFO",
                f"Servidor respondeu com HTTP {status}.",
                "Investigar caso o comportamento seja inesperado."
            )

    # --------------------------------------------------------
    # TLS
    # --------------------------------------------------------

    tls_version = tls_result.get("tls")

    if tls_version:

        if tls_version in (
            "TLSv1.2",
            "TLSv1.3"
        ):
            add_check(
                checks,
                "TLS-001",
                "Versão TLS moderna",
                "TLS",
                "PASS",
                "INFO",
                f"Versão negociada: {tls_version}.",
                "Manter TLS moderno."
            )
        else:
            add_check(
                checks,
                "TLS-001",
                "Versão TLS",
                "TLS",
                "WARN",
                "MEDIUM",
                f"Versão negociada: {tls_version}.",
                "Avaliar desativação de protocolos antigos."
            )

    # --------------------------------------------------------
    # DNS
    # --------------------------------------------------------

    addresses = (
        dns_result.get("addresses")
        or []
    )

    if addresses:
        add_check(
            checks,
            "DNS-001",
            "Resolução DNS",
            "DNS",
            "PASS",
            "INFO",
            f"{len(addresses)} endereço(s) identificado(s).",
            "Nenhuma ação necessária."
        )
    else:
        add_check(
            checks,
            "DNS-001",
            "Resolução DNS",
            "DNS",
            "INFO",
            "INFO",
            "Nenhum endereço foi retornado pela resolução DNS.",
            "Verificar resolução DNS caso o resultado seja inesperado."
        )

    return {
        "total": len(checks),
        "checks": checks,
    }


# ============================================================
# CORRELAÇÃO
# ============================================================

def correlate_findings(
    http_result,
    tls_result,
    dns_result,
    security_checks
):
    findings = []

    for check in security_checks.get("checks", []):

        if check.get("status") != "WARN":
            continue

        severity = check.get(
            "severity",
            "LOW"
        )

        if severity not in (
            "LOW",
            "MEDIUM",
            "HIGH",
            "CRITICAL"
        ):
            continue

        findings.append({
            "title": check.get("title"),
            "category": check.get("category"),
            "severity": severity,
            "source": "security_checks",
            "evidence": check.get("evidence"),
            "impact": (
                "A ausência ou configuração observada "
                "pode reduzir uma camada de proteção."
            ),
            "recommendation": check.get(
                "recommendation"
            ),
        })

    severity_order = {
        "CRITICAL": 4,
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1,
        "INFO": 0,
    }

    highest = "LOW"

    for finding in findings:
        severity = finding.get(
            "severity",
            "LOW"
        )

        if severity_order.get(
            severity,
            0
        ) > severity_order.get(
            highest,
            0
        ):
            highest = severity

    if not findings:
        highest = "LOW"

    counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
    }

    for finding in findings:
        severity = (
            finding.get("severity")
            or "LOW"
        ).lower()

        if severity in counts:
            counts[severity] += 1

    return {
        "risk": highest,
        "total": len(findings),
        "vulnerabilities": len(findings),
        "critical": counts["critical"],
        "high": counts["high"],
        "medium": counts["medium"],
        "low": counts["low"],
        "findings": findings,
    }


# ============================================================
# BLUE TEAM SUMMARY
# ============================================================

def blue_team_analysis(result):
    findings = result.get("findings") or []
    correlation = result.get("correlation") or {}

    risk = correlation.get(
        "risk",
        "LOW"
    )

    if not findings:
        return {
            "available": True,
            "summary": (
                "Nenhum finding de segurança foi "
                "correlacionado pelos checks atuais."
            ),
            "risk": risk,
            "recommendations": [
                "Manter as configurações de segurança existentes.",
                "Repetir a validação periodicamente.",
                "Monitorar alterações de headers, TLS e DNS."
            ],
        }

    recommendations = []

    for finding in findings:
        recommendation = finding.get(
            "recommendation"
        )

        if (
            recommendation
            and recommendation not in recommendations
        ):
            recommendations.append(
                recommendation
            )

    return {
        "available": True,
        "summary": (
            f"Foram correlacionados {len(findings)} "
            f"finding(s), com risco máximo {risk}."
        ),
        "risk": risk,
        "recommendations": recommendations,
    }


# ============================================================
# SCAN PRINCIPAL
# ============================================================

def scan_target(target):
    started = time.perf_counter()
    started_at = utc_now()

    target = normalize_target(target)

    result = {
        "target": target,
        "started_at": started_at,
        "finished_at": None,
        "duration_seconds": None,

        "http": None,
        "tls": None,
        "dns": None,
        "httpx": None,
        "technologies": None,
        "whatweb": None,
        "security_checks": None,

        "findings": [],
        "correlation": None,
        "blue_team_analysis": None,

        "errors": [],
    }

    if not target:
        result["errors"].append(
            "Alvo vazio."
        )

        result["finished_at"] = utc_now()
        result["duration_seconds"] = round(
            time.perf_counter() - started,
            2
        )

        return result

    # --------------------------------------------------------
    # HTTP
    # --------------------------------------------------------

    result["http"] = scan_http(target)

    # --------------------------------------------------------
    # TLS
    # --------------------------------------------------------

    if target.lower().startswith("https://"):
        result["tls"] = scan_tls(target)
    else:
        result["tls"] = {
            "target": target,
            "hostname": get_hostname(target),
            "port": 443,
            "tls": None,
            "cipher": None,
            "certificate": {},
            "error": "Alvo não utiliza HTTPS."
        }

    # --------------------------------------------------------
    # DNS
    # --------------------------------------------------------

    result["dns"] = scan_dns(target)

    # --------------------------------------------------------
    # HTTPX
    # --------------------------------------------------------

    result["httpx"] = scan_httpx(target)

    # --------------------------------------------------------
    # TECHNOLOGIES
    # --------------------------------------------------------

    result["technologies"] = scan_technologies(
        target,
        result["http"]
    )

    # Adiciona tecnologias descobertas pelo HTTPX.
    httpx_technologies = (
        result["httpx"].get("technologies")
        or []
    )

    current_technologies = (
        result["technologies"].get("technologies")
        or []
    )

    result["technologies"]["technologies"] = (
        unique_list(
            current_technologies
            + httpx_technologies
        )
    )

    # --------------------------------------------------------
    # WHATWEB
    # --------------------------------------------------------

    result["whatweb"] = scan_whatweb(target)

    # --------------------------------------------------------
    # SECURITY CHECKS
    # --------------------------------------------------------

    result["security_checks"] = (
        scan_security_checks(
            target,
            result["http"],
            result["tls"],
            result["dns"]
        )
    )

    # --------------------------------------------------------
    # CORRELATION
    # --------------------------------------------------------

    result["correlation"] = correlate_findings(
        result["http"],
        result["tls"],
        result["dns"],
        result["security_checks"]
    )

    result["findings"] = (
        result["correlation"].get("findings")
        or []
    )

    # --------------------------------------------------------
    # BLUE TEAM
    # --------------------------------------------------------

    result["blue_team_analysis"] = (
        blue_team_analysis(result)
    )

    # --------------------------------------------------------
    # ERRORS
    # --------------------------------------------------------

    modules = [
        ("http", result["http"]),
        ("tls", result["tls"]),
        ("dns", result["dns"]),
        ("httpx", result["httpx"]),
        ("whatweb", result["whatweb"]),
    ]

    for module_name, module_result in modules:

        if not isinstance(module_result, dict):
            continue

        error = module_result.get("error")

        if error:
            result["errors"].append({
                "module": module_name,
                "error": error
            })

    # --------------------------------------------------------
    # FINALIZAÇÃO
    # --------------------------------------------------------

    result["finished_at"] = utc_now()

    result["duration_seconds"] = round(
        time.perf_counter() - started,
        2
    )

    return result


# ============================================================
# EXECUÇÃO DIRETA
# ============================================================

if __name__ == "__main__":

    import sys

    if len(sys.argv) < 2:
        print(
            "Uso: python scanner.py "
            "https://exemplo.com"
        )
        raise SystemExit(1)

    target = sys.argv[1]

    result = scan_target(target)

    print(
        json.dumps(
            result,
            indent=2,
            ensure_ascii=False
        )
    )
PY