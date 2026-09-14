cd ~/bluescan-v2
source .venv/bin/activate

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

HTTP_TIMEOUT = 10
COMMAND_TIMEOUT = 15
HTTPX_TIMEOUT = 15
WHATWEB_TIMEOUT = 20


# ============================================================
# UTILITÁRIOS
# ============================================================

def now_utc():
    return datetime.now(timezone.utc).isoformat()


def command_exists(command):
    return shutil.which(command) is not None


def run_command(command, timeout=COMMAND_TIMEOUT):
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False
        )

        return {
            "returncode": result.returncode,
            "stdout": result.stdout or "",
            "stderr": result.stderr or "",
            "timeout": False
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
            "stdout": stdout,
            "stderr": stderr,
            "timeout": True
        }

    except Exception as exc:
        return {
            "returncode": -1,
            "stdout": "",
            "stderr": str(exc),
            "timeout": False
        }


def normalize_target(target):
    target = str(target or "").strip()

    if not target:
        return ""

    if not re.match(r"^https?://", target, re.I):
        target = "https://" + target

    return target.rstrip("/")


def hostname_from_target(target):
    try:
        return urlparse(target).hostname or ""
    except Exception:
        return ""


def unique(values):
    output = []

    for value in values:
        if value and value not in output:
            output.append(value)

    return output


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
        "error": None
    }

    try:
        headers = {
            "User-Agent": "BlueScan/2.0"
        }

        with httpx.Client(
            timeout=HTTP_TIMEOUT,
            follow_redirects=True,
            verify=True,
            headers=headers
        ) as client:

            response = client.get(target)

            result["status"] = response.status_code
            result["final_url"] = str(response.url)

            result["server"] = response.headers.get("server")
            result["content_type"] = response.headers.get(
                "content-type"
            )

            content_length = response.headers.get(
                "content-length"
            )

            if content_length:
                try:
                    result["content_length"] = int(
                        content_length
                    )
                except Exception:
                    result["content_length"] = content_length

            result["headers"] = {
                key.lower(): value
                for key, value in response.headers.items()
            }

            for item in response.history:
                result["redirects"].append({
                    "status": item.status_code,
                    "url": str(item.url),
                    "location": item.headers.get(
                        "location"
                    )
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
        "hostname": hostname_from_target(target),
        "port": 443,
        "tls": None,
        "cipher": None,
        "certificate": {},
        "error": None
    }

    try:
        parsed = urlparse(target)

        hostname = parsed.hostname

        if not hostname:
            result["error"] = "Hostname não identificado."
            return result

        port = parsed.port or 443
        result["hostname"] = hostname
        result["port"] = port

        context = ssl.create_default_context()

        with socket.create_connection(
            (hostname, port),
            timeout=HTTP_TIMEOUT
        ) as raw:

            with context.wrap_socket(
                raw,
                server_hostname=hostname
            ) as tls:

                result["tls"] = tls.version()

                cipher = tls.cipher()

                if cipher:
                    result["cipher"] = {
                        "name": cipher[0],
                        "protocol": cipher[1],
                        "bits": cipher[2]
                    }

                certificate = tls.getpeercert()

                if certificate:
                    result["certificate"] = {
                        "subject": certificate.get("subject"),
                        "issuer": certificate.get("issuer"),
                        "version": certificate.get("version"),
                        "serialNumber": certificate.get(
                            "serialNumber"
                        ),
                        "notBefore": certificate.get(
                            "notBefore"
                        ),
                        "notAfter": certificate.get(
                            "notAfter"
                        )
                    }

    except Exception as exc:
        result["error"] = str(exc)

    return result


# ============================================================
# DNS
# ============================================================

def scan_dns(target):
    hostname = hostname_from_target(target)

    result = {
        "hostname": hostname,
        "addresses": [],
        "ipv4": [],
        "ipv6": [],
        "canonical_name": None,
        "error": None
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

        for info in infos:
            family = info[0]
            sockaddr = info[4]

            if not sockaddr:
                continue

            address = sockaddr[0]

            if address not in result["addresses"]:
                result["addresses"].append(address)

            if family == socket.AF_INET:
                if address not in result["ipv4"]:
                    result["ipv4"].append(address)

            elif family == socket.AF_INET6:
                if address not in result["ipv6"]:
                    result["ipv6"].append(address)

    except Exception as exc:
        result["error"] = str(exc)

    # --------------------------------------------------------
    # CNAME via dig
    # --------------------------------------------------------

    if command_exists("dig"):

        command = [
            "dig",
            "+short",
            "CNAME",
            hostname
        ]

        dig = run_command(
            command,
            timeout=10
        )

        if dig["returncode"] == 0:

            lines = [
                line.strip().rstrip(".")
                for line in dig["stdout"].splitlines()
                if line.strip()
            ]

            if lines:
                result["canonical_name"] = lines[0]

    return result


# ============================================================
# HTTPX
# ============================================================

def scan_httpx(target):
    result = {
        "available": command_exists("httpx"),
        "target": target,
        "status": None,
        "url": None,
        "final_url": None,
        "title": None,
        "webserver": None,
        "technologies": [],
        "raw": "",
        "error": None
    }

    if not result["available"]:
        result["error"] = (
            "httpx não encontrado no PATH."
        )
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
        "-tech-detect"
    ]

    output = run_command(
        command,
        timeout=HTTPX_TIMEOUT
    )

    raw = output["stdout"].strip()

    result["raw"] = raw

    if output["timeout"]:
        result["error"] = (
            "HTTPX excedeu o tempo limite."
        )
        return result

    if output["returncode"] != 0 and not raw:
        result["error"] = (
            output["stderr"]
            or "HTTPX retornou erro."
        )
        return result

    if raw:

        line = raw.splitlines()[0].strip()

        result["url"] = line

        status = re.search(
            r"\[(\d{3})\]",
            line
        )

        if status:
            result["status"] = int(
                status.group(1)
            )

        locations = re.findall(
            r"\[(https?://[^\]]+)\]",
            line,
            re.I
        )

        if locations:
            result["final_url"] = locations[-1]

        brackets = re.findall(
            r"\[([^\]]+)\]",
            line
        )

        for value in brackets:

            value = value.strip()

            if re.fullmatch(
                r"\d{3}",
                value
            ):
                continue

            if value.lower().startswith(
                "http://"
            ) or value.lower().startswith(
                "https://"
            ):
                continue

            if value not in result["technologies"]:
                result["technologies"].append(
                    value
                )

    return result


# ============================================================
# TECNOLOGIAS
# ============================================================

def scan_technologies(http_result, httpx_result):
    technologies = []
    sources = []

    server = (
        http_result.get("server")
        or ""
    )

    headers = (
        http_result.get("headers")
        or {}
    )

    if server:
        sources.append(
            "HTTP Server Header"
        )

    server_lower = server.lower()

    if "github" in server_lower:
        technologies.append(
            "GitHub Pages"
        )

    if "cloudflare" in server_lower:
        technologies.append(
            "Cloudflare"
        )

    if "nginx" in server_lower:
        technologies.append(
            "Nginx"
        )

    if "apache" in server_lower:
        technologies.append(
            "Apache"
        )

    powered = headers.get(
        "x-powered-by"
    )

    if powered:
        technologies.append(
            powered
        )
        sources.append(
            "X-Powered-By"
        )

    for technology in (
        httpx_result.get("technologies")
        or []
    ):
        technologies.append(
            technology
        )

    return {
        "technologies": unique(
            technologies
        ),
        "source": unique(
            sources
        ),
        "server": server or None
    }


# ============================================================
# WHATWEB
# ============================================================

def scan_whatweb(target):
    result = {
        "available": command_exists("whatweb"),
        "plugins": [],
        "raw": "",
        "error": None
    }

    if not result["available"]:
        result["error"] = (
            "WhatWeb não encontrado."
        )
        return result

    command = [
        "whatweb",
        "--quiet",
        "--aggression=1",
        target
    ]

    output = run_command(
        command,
        timeout=WHATWEB_TIMEOUT
    )

    result["raw"] = (
        output["stdout"]
        or output["stderr"]
    )

    if output["timeout"]:
        result["error"] = (
            "WhatWeb excedeu o tempo limite."
        )
        return result

    if output["returncode"] != 0:
        if not result["raw"]:
            result["error"] = (
                output["stderr"]
                or "WhatWeb retornou erro."
            )

    matches = re.findall(
        r"([A-Za-z][A-Za-z0-9_-]*)\[([^\]]+)\]",
        result["raw"]
    )

    for name, value in matches:

        plugin = f"{name}: {value}"

        if plugin not in result["plugins"]:
            result["plugins"].append(
                plugin
            )

    return result


# ============================================================
# SECURITY CHECKS
# ============================================================

def build_security_checks(http_result, tls_result):
    headers = (
        http_result.get("headers")
        or {}
    )

    checks = []

    def add(
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
            "recommendation": recommendation
        })

    # --------------------------------------------------------
    # HTTPS
    # --------------------------------------------------------

    if tls_result.get("tls"):

        add(
            "TLS-001",
            "HTTPS habilitado",
            "Transporte",
            "PASS",
            "INFO",
            "O alvo negociou uma conexão TLS.",
            "Manter HTTPS habilitado."
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
            add(
                "TLS-002",
                "Versão TLS moderna",
                "TLS",
                "PASS",
                "INFO",
                f"Versão negociada: {tls_version}.",
                "Manter protocolos TLS modernos."
            )
        else:
            add(
                "TLS-002",
                "Versão TLS",
                "TLS",
                "WARN",
                "MEDIUM",
                f"Versão negociada: {tls_version}.",
                "Desativar protocolos TLS antigos."
            )

    # --------------------------------------------------------
    # HSTS
    # --------------------------------------------------------

    if "strict-transport-security" in headers:

        add(
            "HDR-001",
            "Strict-Transport-Security",
            "Headers",
            "PASS",
            "INFO",
            "Header HSTS identificado.",
            "Manter HSTS configurado."
        )

    else:

        add(
            "HDR-001",
            "Strict-Transport-Security",
            "Headers",
            "WARN",
            "LOW",
            "Header HSTS não identificado.",
            "Avaliar a utilização de Strict-Transport-Security."
        )

    # --------------------------------------------------------
    # X CONTENT TYPE OPTIONS
    # --------------------------------------------------------

    if "x-content-type-options" in headers:

        add(
            "HDR-002",
            "X-Content-Type-Options",
            "Headers",
            "PASS",
            "INFO",
            "Header X-Content-Type-Options identificado.",
            "Manter nosniff configurado."
        )

    else:

        add(
            "HDR-002",
            "X-Content-Type-Options",
            "Headers",
            "WARN",
            "LOW",
            "Header X-Content-Type-Options não identificado.",
            "Avaliar X-Content-Type-Options: nosniff."
        )

    # --------------------------------------------------------
    # CSP
    # --------------------------------------------------------

    if "content-security-policy" in headers:

        add(
            "HDR-003",
            "Content-Security-Policy",
            "Headers",
            "PASS",
            "INFO",
            "Header CSP identificado.",
            "Manter a política CSP revisada."
        )

    else:

        add(
            "HDR-003",
            "Content-Security-Policy",
            "Headers",
            "WARN",
            "LOW",
            "Header CSP não identificado.",
            "Avaliar uma política Content-Security-Policy."
        )

    # --------------------------------------------------------
    # REFERRER POLICY
    # --------------------------------------------------------

    if "referrer-policy" in headers:

        add(
            "HDR-004",
            "Referrer-Policy",
            "Headers",
            "PASS",
            "INFO",
            "Header Referrer-Policy identificado.",
            "Manter a política configurada."
        )

    else:

        add(
            "HDR-004",
            "Referrer-Policy",
            "Headers",
            "WARN",
            "LOW",
            "Header Referrer-Policy não identificado.",
            "Avaliar a configuração de Referrer-Policy."
        )

    # --------------------------------------------------------
    # CLICKJACKING
    # --------------------------------------------------------

    if (
        "x-frame-options" in headers
        or "content-security-policy" in headers
    ):

        add(
            "HDR-005",
            "Proteção contra Clickjacking",
            "Headers",
            "PASS",
            "INFO",
            "Foi identificada proteção via X-Frame-Options ou CSP.",
            "Manter a proteção contra framing."
        )

    else:

        add(
            "HDR-005",
            "Proteção contra Clickjacking",
            "Headers",
            "WARN",
            "LOW",
            "Não foi identificada proteção explícita contra framing.",
            "Avaliar X-Frame-Options ou CSP frame-ancestors."
        )

    # --------------------------------------------------------
    # SERVER DISCLOSURE
    # --------------------------------------------------------

    server = http_result.get("server")

    if server:

        add(
            "HDR-006",
            "Exposição do Server Header",
            "Information Disclosure",
            "INFO",
            "INFO",
            f"Servidor informado: {server}.",
            "Avaliar se a exposição é necessária."
        )

    # --------------------------------------------------------
    # STATUS HTTP
    # --------------------------------------------------------

    status = http_result.get("status")

    if status:

        if 200 <= status < 400:

            add(
                "HTTP-001",
                "Resposta HTTP",
                "HTTP",
                "PASS",
                "INFO",
                f"Servidor respondeu HTTP {status}.",
                "Nenhuma ação necessária."
            )

        else:

            add(
                "HTTP-001",
                "Resposta HTTP",
                "HTTP",
                "INFO",
                "INFO",
                f"Servidor respondeu HTTP {status}.",
                "Investigar se o comportamento for inesperado."
            )

    return {
        "total": len(checks),
        "checks": checks
    }


# ============================================================
# CORRELAÇÃO
# ============================================================

def correlate_findings(security_checks):
    findings = []

    for check in security_checks.get(
        "checks",
        []
    ):

        if check.get("status") != "WARN":
            continue

        severity = check.get(
            "severity",
            "LOW"
        )

        findings.append({
            "title": check.get("title"),
            "category": check.get("category"),
            "severity": severity,
            "source": "security_checks",
            "evidence": check.get("evidence"),
            "impact": (
                "A ausência dessa configuração "
                "pode reduzir uma camada de "
                "proteção da aplicação."
            ),
            "recommendation": check.get(
                "recommendation"
            )
        })

    order = {
        "CRITICAL": 4,
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1,
        "INFO": 0
    }

    risk = "LOW"

    for finding in findings:

        severity = finding.get(
            "severity",
            "LOW"
        )

        if order.get(
            severity,
            0
        ) > order.get(
            risk,
            0
        ):
            risk = severity

    counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0
    }

    for finding in findings:

        key = (
            finding.get("severity")
            or "LOW"
        ).lower()

        if key in counts:
            counts[key] += 1

    return {
        "risk": risk,
        "total": len(findings),
        "vulnerabilities": len(findings),
        "critical": counts["critical"],
        "high": counts["high"],
        "medium": counts["medium"],
        "low": counts["low"],
        "findings": findings
    }


# ============================================================
# BLUE TEAM
# ============================================================

def blue_team_analysis(correlation):
    findings = correlation.get(
        "findings",
        []
    )

    if not findings:

        return {
            "available": True,
            "summary": (
                "Nenhum finding foi "
                "correlacionado."
            ),
            "risk": correlation.get(
                "risk",
                "LOW"
            ),
            "recommendations": []
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
            f"{len(findings)} finding(s) "
            "de hardening foram identificados."
        ),
        "risk": correlation.get(
            "risk",
            "LOW"
        ),
        "recommendations": recommendations
    }


# ============================================================
# SCAN PRINCIPAL
# ============================================================

def scan_target(target):

    started = time.perf_counter()
    started_at = now_utc()

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

        "errors": []
    }

    if not target:

        result["errors"].append(
            "Alvo vazio."
        )

        result["finished_at"] = now_utc()
        result["duration_seconds"] = round(
            time.perf_counter() - started,
            2
        )

        return result

    # --------------------------------------------------------
    # MÓDULOS
    # --------------------------------------------------------

    result["http"] = scan_http(target)

    if target.lower().startswith("https://"):
        result["tls"] = scan_tls(target)
    else:
        result["tls"] = {
            "target": target,
            "hostname": hostname_from_target(target),
            "port": 443,
            "tls": None,
            "cipher": None,
            "certificate": {},
            "error": "Alvo não utiliza HTTPS."
        }

    result["dns"] = scan_dns(target)

    result["httpx"] = scan_httpx(target)

    result["technologies"] = scan_technologies(
        result["http"],
        result["httpx"]
    )

    result["whatweb"] = scan_whatweb(target)

    result["security_checks"] = (
        build_security_checks(
            result["http"],
            result["tls"]
        )
    )

    result["correlation"] = (
        correlate_findings(
            result["security_checks"]
        )
    )

    result["findings"] = (
        result["correlation"]["findings"]
    )

    result["blue_team_analysis"] = (
        blue_team_analysis(
            result["correlation"]
        )
    )

    # --------------------------------------------------------
    # ERROS
    # --------------------------------------------------------

    for module_name in (
        "http",
        "tls",
        "dns",
        "httpx",
        "whatweb"
    ):

        module = result.get(
            module_name
        )

        if isinstance(module, dict):

            error = module.get(
                "error"
            )

            if error:

                result["errors"].append({
                    "module": module_name,
                    "error": error
                })

    # --------------------------------------------------------
    # FINALIZAÇÃO
    # --------------------------------------------------------

    result["finished_at"] = now_utc()

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
            json.dumps(
                {
                    "error": (
                        "Uso: python scanner.py "
                        "https://exemplo.com"
                    )
                },
                ensure_ascii=False
            )
        )

        raise SystemExit(1)

    target = sys.argv[1]

    try:

        result = scan_target(
            target
        )

        print(
            json.dumps(
                result,
                indent=2,
                ensure_ascii=False
            )
        )

    except Exception as exc:

        print(
            json.dumps(
                {
                    "error": str(exc)
                },
                indent=2,
                ensure_ascii=False
            )
        )

        raise SystemExit(1)
PY