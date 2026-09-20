import json
import shutil
import socket
import ssl
import subprocess
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

import httpx

from scanner_checks import run_security_checks
from correlator import correlate_results


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
        "severity": str(severity).upper(),
        "category": category,
        "source": source,
        "evidence": evidence,
        "impact": impact,
        "recommendation": recommendation,
    }


def _tool_result(
    name,
    status="not_run",
    findings=None,
    output="",
    error=None,
):
    return {
        "tool": name,
        "status": status,
        "findings": findings or [],
        "output": output,
        "error": error,
    }


def _run_command(command, timeout=30):
    """
    Executa somente ferramentas locais já instaladas.
    Nunca usa shell=True.
    """

    executable = command[0]

    if shutil.which(executable) is None:
        return {
            "ok": False,
            "status": "not_installed",
            "output": "",
            "error": f"Ferramenta não encontrada: {executable}",
        }

    try:
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )

        output = (process.stdout or "") + (process.stderr or "")

        return {
            "ok": process.returncode == 0,
            "status": (
                "completed"
                if process.returncode == 0
                else "error"
            ),
            "output": output[:20000],
            "error": (
                None
                if process.returncode == 0
                else f"Exit code: {process.returncode}"
            ),
        }

    except subprocess.TimeoutExpired:
        return {
            "ok": False,
            "status": "timeout",
            "output": "",
            "error": f"Tempo limite de {timeout}s atingido.",
        }

    except Exception as exc:
        return {
            "ok": False,
            "status": "error",
            "output": "",
            "error": str(exc),
        }


def _scan_tls(hostname, port):
    findings = []
    technical = {}

    try:
        context = ssl.create_default_context()

        started = time.time()

        with socket.create_connection(
            (hostname, port),
            timeout=8,
        ) as raw_socket:

            with context.wrap_socket(
                raw_socket,
                server_hostname=hostname,
            ) as tls_socket:

                certificate = tls_socket.getpeercert()
                cipher = tls_socket.cipher()
                version = tls_socket.version()

                technical["tls_version"] = version
                technical["cipher"] = (
                    cipher[0] if cipher else None
                )
                technical["certificate_subject"] = str(
                    certificate.get("subject", "")
                )
                technical["duration_seconds"] = round(
                    time.time() - started,
                    2,
                )

                if version in {"TLSv1", "TLSv1.1"}:
                    findings.append(
                        _finding(
                            "Versão TLS antiga observada",
                            "medium",
                            "TLS",
                            "BlueScan TLS",
                            f"Versão observada: {version}",
                            "Protocolos antigos podem oferecer proteções inferiores.",
                            "Avaliar a desativação de versões TLS antigas.",
                        )
                    )
                else:
                    findings.append(
                        _finding(
                            f"TLS {version} ativo",
                            "info",
                            "TLS",
                            "BlueScan TLS",
                            f"Versão TLS negociada: {version}",
                            "Conexão TLS estabelecida.",
                            "Manter configurações TLS atualizadas.",
                        )
                    )

                return {
                    "status": "completed",
                    "findings": findings,
                    "technical": technical,
                    "error": None,
                }

    except Exception as exc:
        return {
            "status": "error",
            "findings": [],
            "technical": technical,
            "error": str(exc),
        }


def _scan_dns(hostname):
    findings = []
    addresses = []

    try:
        infos = socket.getaddrinfo(
            hostname,
            None,
            type=socket.SOCK_STREAM,
        )

        for item in infos:
            address = item[4][0]

            if address not in addresses:
                addresses.append(address)

        findings.append(
            _finding(
                "Resolução DNS concluída",
                "info",
                "DNS",
                "BlueScan DNS",
                f"Endereços encontrados: {', '.join(addresses[:20])}",
                "O hostname foi resolvido.",
                "Manter o DNS monitorado.",
            )
        )

        return {
            "status": "completed",
            "findings": findings,
            "addresses": addresses,
            "error": None,
        }

    except Exception as exc:
        return {
            "status": "error",
            "findings": [],
            "addresses": [],
            "error": str(exc),
        }


def _scan_technology(response):
    findings = []
    technologies = []

    headers = response.headers

    server = headers.get("server")

    if server:
        technologies.append(server)

    powered_by = headers.get("x-powered-by")

    if powered_by:
        technologies.append(powered_by)

    if "github.com" in str(server).lower():
        technologies.append("GitHub")

    if "cloudflare" in str(server).lower():
        technologies.append("Cloudflare")

    if technologies:
        findings.append(
            _finding(
                "Tecnologia identificada por headers",
                "info",
                "Technology Detection",
                "BlueScan Technology",
                ", ".join(
                    dict.fromkeys(technologies)
                ),
                "Informações de tecnologia podem auxiliar inventário e fingerprinting.",
                "Avaliar se os headers expõem mais informações do que o necessário.",
            )
        )

    return {
        "status": "completed",
        "findings": findings,
        "technologies": list(
            dict.fromkeys(technologies)
        ),
    }


def _run_whatweb(target):
    command = [
        "whatweb",
        "--color=never",
        "--quiet",
        target,
    ]

    result = _run_command(
        command,
        timeout=30,
    )

    findings = []

    if result["ok"] and result["output"].strip():
        findings.append(
            _finding(
                "Tecnologias detectadas pelo WhatWeb",
                "info",
                "Technology Detection",
                "WhatWeb",
                result["output"].strip()[:8000],
                "Fornece informações de fingerprinting tecnológico.",
                "Usar os dados como inventário e validação, não como vulnerabilidade confirmada.",
            )
        )

    return _tool_result(
        "WhatWeb",
        result["status"],
        findings,
        result["output"],
        result["error"],
    )


def _run_wapiti(target):
    wapiti = shutil.which("wapiti")

    if wapiti is None:
        local_wapiti = ".venv/bin/wapiti"

        if shutil.which(local_wapiti):
            wapiti = local_wapiti

    if not wapiti:
        return _tool_result(
            "Wapiti",
            "not_installed",
            error="Wapiti não encontrado.",
        )

    command = [
        wapiti,
        "-u",
        target,
        "--scope",
        "page",
        "--flush-session",
        "--max-scan-time",
        "30",
        "-f",
        "json",
    ]

    result = _run_command(
        command,
        timeout=40,
    )

    findings = []

    if result["output"].strip():
        try:
            data = json.loads(
                result["output"]
            )

            vulnerabilities = data.get(
                "vulnerabilities",
                [],
            )

            if isinstance(
                vulnerabilities,
                dict,
            ):
                vulnerabilities = list(
                    vulnerabilities.values()
                )

            if isinstance(
                vulnerabilities,
                list,
            ):
                for vulnerability in vulnerabilities[:50]:

                    if not isinstance(
                        vulnerability,
                        dict,
                    ):
                        continue

                    name = (
                        vulnerability.get("name")
                        or vulnerability.get("info")
                        or vulnerability.get("module")
                        or "Achado Wapiti"
                    )

                    findings.append(
                        _finding(
                            str(name),
                            "low",
                            "Web Security",
                            "Wapiti",
                            json.dumps(
                                vulnerability,
                                ensure_ascii=False,
                            )[:4000],
                            "Resultado reportado pelo scanner Wapiti; requer validação contextual.",
                            "Validar manualmente antes de classificar como vulnerabilidade confirmada.",
                        )
                    )

        except Exception:
            if result["output"].strip():
                findings.append(
                    _finding(
                        "Wapiti executado",
                        "info",
                        "Web Security",
                        "Wapiti",
                        result["output"][:4000],
                        "O scanner produziu saída que não pôde ser convertida automaticamente.",
                        "Consultar o resultado bruto para validação.",
                    )
                )

    return _tool_result(
        "Wapiti",
        result["status"],
        findings,
        result["output"],
        result["error"],
    )


def _run_subfinder(hostname):
    command = [
        "subfinder",
        "-silent",
        "-d",
        hostname,
        "-timeout",
        "15",
        "-max-time",
        "20",
    ]

    result = _run_command(
        command,
        timeout=30,
    )

    findings = []

    lines = [
        line.strip()
        for line in result["output"].splitlines()
        if line.strip()
    ]

    lines = list(
        dict.fromkeys(lines)
    )[:50]

    if lines:
        findings.append(
            _finding(
                "Subdomínios identificados",
                "info",
                "DNS Discovery",
                "subfinder",
                "\n".join(lines),
                "Pode ampliar o inventário de superfície exposta.",
                "Validar os ativos identificados e incorporá-los ao inventário autorizado.",
            )
        )

    return _tool_result(
        "subfinder",
        result["status"],
        findings,
        result["output"],
        result["error"],
    )


def _run_dnsx(hostname):
    command = [
        "dnsx",
        "-silent",
        "-d",
        hostname,
    ]

    result = _run_command(
        command,
        timeout=30,
    )

    findings = []

    if result["ok"] and result["output"].strip():
        findings.append(
            _finding(
                "Registros DNS identificados pelo dnsx",
                "info",
                "DNS Discovery",
                "dnsx",
                result["output"].strip()[:8000],
                "Pode complementar o inventário DNS.",
                "Validar os registros encontrados dentro do escopo autorizado.",
            )
        )

    return _tool_result(
        "dnsx",
        result["status"],
        findings,
        result["output"],
        result["error"],
    )


def scan_target(target):
    started = time.time()
    started_at = datetime.now(
        timezone.utc
    ).isoformat()

    target = target.strip()

    parsed = urlparse(target)

    if parsed.scheme.lower() not in {
        "http",
        "https",
    }:
        raise ValueError(
            "Somente URLs HTTP ou HTTPS são permitidas."
        )

    if not parsed.hostname:
        raise ValueError(
            "A URL não possui hostname válido."
        )

    hostname = parsed.hostname

    port = parsed.port or (
        443
        if parsed.scheme.lower() == "https"
        else 80
    )

    results = {}

    # ============================================================
    # HTTP
    # ============================================================

    http_findings = []

    try:
        with httpx.Client(
            timeout=15.0,
            follow_redirects=True,
            headers={
                "User-Agent":
                    "BlueScan/3.0 Defensive Security Scanner"
            },
            verify=True,
        ) as client:

            response = client.get(target)

        headers = dict(
            response.headers
        )

        http_findings.append(
            _finding(
                f"HTTP {response.status_code}",
                "info",
                "HTTP",
                "BlueScan HTTP",
                f"Status HTTP: {response.status_code}",
                "O servidor respondeu à requisição.",
                "Manter o serviço monitorado.",
            )
        )

        results["HTTP"] = {
            "status": "completed",
            "findings": http_findings,
            "headers": headers,
            "response": response,
            "final_url": str(
                response.url
            ),
            "status_code": response.status_code,
        }

    except Exception as exc:
        results["HTTP"] = {
            "status": "error",
            "findings": [],
            "headers": {},
            "error": str(exc),
        }

    # ============================================================
    # SECURITY CHECKS
    # ============================================================

    headers = results["HTTP"].get(
        "headers",
        {},
    )

    security_data = {
        "target": target,
        "status_code": results["HTTP"].get(
            "status_code"
        ),
        "headers": headers,
    }

    try:
        security_checks = run_security_checks(
            security_data
        )

        results["Security Checks"] = {
            "status": "completed",
            "findings": security_checks.get(
                "findings",
                [],
            ),
            "checks": security_checks.get(
                "checks",
                {},
            ),
            "meta": security_checks.get(
                "meta",
                {},
            ),
        }

    except Exception as exc:
        results["Security Checks"] = {
            "status": "error",
            "findings": [],
            "checks": {},
            "meta": {},
            "error": str(exc),
        }

    # ============================================================
    # TLS
    # ============================================================

    if parsed.scheme.lower() == "https":

        tls_result = _scan_tls(
            hostname,
            port,
        )

        results["TLS"] = tls_result

    else:

        results["TLS"] = {
            "status": "not_applicable",
            "findings": [],
            "technical": {},
            "error": None,
        }

        http_findings.append(
            _finding(
                "Alvo acessado por HTTP",
                "medium",
                "Transport Security",
                "BlueScan HTTP",
                f"URL: {target}",
                "HTTP não oferece as mesmas garantias de confidencialidade do HTTPS.",
                "Avaliar HTTPS quando houver informações sensíveis.",
            )
        )

    # ============================================================
    # DNS
    # ============================================================

    results["DNS"] = _scan_dns(
        hostname
    )

    # ============================================================
    # TECHNOLOGY
    # ============================================================

    if results["HTTP"].get(
        "status"
    ) == "completed":

        results["Technology"] = _scan_technology(
            results["HTTP"]["response"]
        )

    else:

        results["Technology"] = {
            "status": "not_run",
            "findings": [],
            "technologies": [],
        }

    # ============================================================
    # WHATWEB
    # ============================================================

    results["WhatWeb"] = _run_whatweb(
        target
    )

    # ============================================================
    # WAPITI
    # ============================================================

    results["Wapiti"] = _run_wapiti(
        target
    )

    # ============================================================
    # SUBFINDER
    # ============================================================

    results["subfinder"] = _run_subfinder(
        hostname
    )

    # ============================================================
    # DNSX
    # ============================================================

    results["dnsx"] = _run_dnsx(
        hostname
    )

    # ============================================================
    # CORRELAÇÃO
    # ============================================================

    correlation_input = {}

    for source, data in results.items():

        if not isinstance(
            data,
            dict,
        ):
            continue

        correlation_input[source] = data.get(
            "findings",
            [],
        )

    correlated = correlate_results(
        correlation_input
    )

    finished_at = datetime.now(
        timezone.utc
    ).isoformat()

    # ============================================================
    # STATUS DAS FERRAMENTAS
    # ============================================================

    tool_status = {}

    for source, data in results.items():

        if not isinstance(
            data,
            dict,
        ):
            continue

        tool_status[source] = {
            "status": data.get(
                "status",
                "unknown",
            ),
            "error": data.get(
                "error"
            ),
        }

    # ============================================================
    # RESULTADO FINAL
    # ============================================================

    return {
        "target": target,
        "final_url": results["HTTP"].get(
            "final_url",
            target,
        ),
        "status_code": results["HTTP"].get(
            "status_code"
        ),
        "started_at": started_at,
        "finished_at": finished_at,
        "duration_seconds": round(
            time.time() - started,
            2,
        ),
        "findings": correlated["findings"],
        "summary": {
            "total": correlated["total"],
            "counts": correlated["counts"],
            "confirmed": correlated.get(
                "confirmed",
                0,
            ),
            "review": correlated.get(
                "review",
                0,
            ),
            "informational": correlated.get(
                "informational",
                0,
            ),
            "severity": correlated.get(
                "severity",
                "NONE",
            ),
        },
        "tool_status": tool_status,
        "technical": {
            "dns": results["DNS"].get(
                "addresses",
                [],
            ),
            "tls": results["TLS"].get(
                "technical",
                {},
            ),
            "technologies": results["Technology"].get(
                "technologies",
                [],
            ),
        },
        "modules": results,
    }

2. Agora NÃO abra o Streamlit ainda

Primeiro vamos verificar sintaxe e integração:

cd ~/bluescan-v2
source .venv/bin/activate

echo "===== PY_COMPILE ====="

python3 -m py_compile \
scanner.py \
scanner_checks.py \
correlator.py

echo
echo "===== IMPORT ====="

python3 - <<'PY'
import scanner
import scanner_checks
import correlator

print("scanner:", scanner.__file__)
print("scanner_checks:", scanner_checks.__file__)
print("correlator:", correlator.__file__)

print()
print("run_security_checks:", hasattr(scanner_checks, "run_security_checks"))
print("scan_target:", hasattr(scanner, "scan_target"))
print("correlate_results:", hasattr(correlator, "correlate_results"))
PY

Se aparecer:

===== PY_COMPILE =====

===== IMPORT =====
...
run_security_checks: True
scan_target: True
correlate_results: True

a integração estrutural está correta.

3. Depois faça um teste real no seu laboratório local

Não vamos usar site de terceiros nesta etapa:

cd ~/bluescan-v2
source .venv/bin/activate

python3 - <<'PY'
from scanner import scan_target

target = "http://127.0.0.1:8080"

print("===== INICIANDO BLUE SCAN =====")
print("target:", target)
print()

result = scan_target(target)

print("===== RESUMO =====")
print(result.get("summary"))

print()
print("===== FINDINGS =====")

for finding in result.get("findings", []):
    print(
        "[{}] {} - {} - {}".format(
            finding.get("severity"),
            finding.get("status"),
            finding.get("source"),
            finding.get("title"),
        )
    )

print()
print("===== SECURITY CHECKS =====")

security = result.get(
    "modules",
    {},
).get(
    "Security Checks",
    {},
)

print("status:", security.get("status"))
print("checks:", security.get("checks"))
print("findings:", len(security.get("findings", [])))

print()
print("===== MODULE STATUS =====")

for name, data in result.get(
    "tool_status",
    {},
).items():
    print(
        name,
        "=>",
        data.get("status"),
    )
PY

Esse teste é importante: ele vai mostrar se os novos checks realmente chegam ao "correlator.py" através do "scan_target()", em vez de funcionar apenas naquele teste sintético anterior.

Não precisamos aumentar o scanner ainda. Primeiro vamos confirmar esse caminho:

HTTP → checks → correlator → resultado → Streamlit.