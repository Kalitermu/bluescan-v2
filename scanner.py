cd ~/bluescan-v2
source .venv/bin/activate

cp scanner.py scanner.before_nuclei_validator.py

cat > scanner.py <<'PY'
from datetime import datetime
import json
import re
import subprocess
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from scanner_http import scan_http
from scanner_tls import scan_tls
from scanner_dns import scan_dns
from scanner_tech import scan_technology
from correlator import correlate


ANSI_ESCAPE = re.compile(
    r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])"
)


# ============================================================
# WHATWEB
# ============================================================

def run_whatweb(url: str) -> dict:
    """
    Executa WhatWeb em modo Stealthy (-a 1).
    """

    try:
        cmd = [
            "whatweb",
            "--aggression=1",
            url,
        ]

        process = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=45,
        )

        stdout = ANSI_ESCAPE.sub(
            "",
            process.stdout,
        ).strip()

        stderr = ANSI_ESCAPE.sub(
            "",
            process.stderr,
        ).strip()

        plugins = []

        for line in stdout.splitlines():

            line = line.strip()

            if not line:
                continue

            if not line.startswith(url):
                continue

            match = re.search(
                r"\[[0-9]{3}(?: [^\]]+)?\]\s*(.*)$",
                line,
                re.DOTALL,
            )

            if not match:
                continue

            plugin_text = match.group(1).strip()

            parts = re.findall(
                r"[A-Za-z0-9_.+-]+(?:\[[^\]]*\])*",
                plugin_text,
            )

            for part in parts:

                part = part.strip().rstrip(",")

                if not part:
                    continue

                name_match = re.match(
                    r"^([A-Za-z0-9_.+-]+)",
                    part,
                )

                if not name_match:
                    continue

                name = name_match.group(1)

                values = re.findall(
                    r"\[([^\]]*)\]",
                    part,
                )

                plugins.append(
                    {
                        "name": name,
                        "details": values,
                        "raw": part,
                    }
                )

            break

        if stdout.startswith(url):

            return {
                "status": "ok",
                "url": url,
                "returncode": process.returncode,
                "plugins": plugins,
                "plugin_count": len(plugins),
                "raw": stdout,
                "warning": None,
            }

        return {
            "status": "error",
            "url": url,
            "returncode": process.returncode,
            "error": (
                stderr
                or stdout
                or "WhatWeb não retornou dados."
            ),
            "plugins": [],
        }

    except FileNotFoundError:

        return {
            "status": "error",
            "url": url,
            "error": "WhatWeb não encontrado no sistema.",
            "plugins": [],
        }

    except subprocess.TimeoutExpired:

        return {
            "status": "error",
            "url": url,
            "error": (
                "WhatWeb excedeu o tempo limite "
                "de 45 segundos."
            ),
            "plugins": [],
        }

    except Exception as exc:

        return {
            "status": "error",
            "url": url,
            "error": str(exc),
            "plugins": [],
        }


# ============================================================
# HTTP VALIDATOR DO NUCLEI
# ============================================================

def _is_error_page(body: str, content_type: str) -> bool:
    """
    Identifica respostas que parecem páginas genéricas de erro.
    Não tenta explorar o alvo.
    """

    if "text/html" not in content_type.lower():
        return False

    sample = body[:12000].lower()

    indicators = [
        "<title>404",
        "404 not found",
        "page not found",
        "file not found",
        "not found",
        "error 404",
        "github pages",
    ]

    return any(
        indicator in sample
        for indicator in indicators
    )


def validate_nuclei_match(url: str) -> dict:
    """
    Revalida um matched-at do Nuclei usando uma requisição GET
    simples e não destrutiva.

    A função NÃO tenta explorar o recurso.
    """

    result = {
        "url": url,
        "status": "unknown",
        "http_status": None,
        "content_type": None,
        "content_length": None,
        "error_page": False,
        "reason": None,
        "confidence": "low",
    }

    try:

        request = Request(
            url,
            headers={
                "User-Agent": "BlueScan-Validator/1.0",
                "Accept": "*/*",
            },
            method="GET",
        )

        with urlopen(
            request,
            timeout=8,
        ) as response:

            body = response.read(
                20000
            )

            status_code = response.getcode()

            content_type = (
                response.headers.get(
                    "Content-Type",
                    "",
                )
            )

            content_length = response.headers.get(
                "Content-Length"
            )

        body_text = body.decode(
            "utf-8",
            errors="replace",
        )

        result["http_status"] = status_code
        result["content_type"] = content_type
        result["content_length"] = (
            int(content_length)
            if content_length
            and content_length.isdigit()
            else len(body)
        )

        result["error_page"] = _is_error_page(
            body_text,
            content_type,
        )

        # ----------------------------------------------------
        # Recurso claramente inexistente
        # ----------------------------------------------------

        if status_code in (404, 410):

            result["status"] = "false_positive"
            result["confidence"] = "high"
            result["reason"] = (
                "O matched-at retornou "
                f"HTTP {status_code}; recurso "
                "não foi encontrado."
            )

            return result

        # ----------------------------------------------------
        # Página de erro genérica
        # ----------------------------------------------------

        if result["error_page"]:

            result["status"] = "likely_false_positive"
            result["confidence"] = "high"
            result["reason"] = (
                "A resposta parece ser uma "
                "página genérica de erro/fallback."
            )

            return result

        # ----------------------------------------------------
        # Recurso existente
        # ----------------------------------------------------

        if 200 <= status_code < 300:

            result["status"] = "needs_review"
            result["confidence"] = "medium"
            result["reason"] = (
                "O recurso respondeu com sucesso. "
                "Isso não confirma vulnerabilidade; "
                "é necessária análise adicional."
            )

            return result

        # ----------------------------------------------------
        # Outros códigos
        # ----------------------------------------------------

        result["status"] = "needs_review"
        result["confidence"] = "low"
        result["reason"] = (
            f"Resposta HTTP {status_code}; "
            "não foi possível confirmar ou "
            "descartar o achado automaticamente."
        )

        return result

    except HTTPError as exc:

        result["http_status"] = exc.code

        if exc.code in (404, 410):

            result["status"] = "false_positive"
            result["confidence"] = "high"
            result["reason"] = (
                f"HTTP {exc.code}: recurso inexistente."
            )

        else:

            result["status"] = "needs_review"
            result["confidence"] = "low"
            result["reason"] = (
                f"HTTP {exc.code}: resposta "
                "não conclusiva."
            )

        return result

    except (URLError, TimeoutError) as exc:

        result["status"] = "validation_error"
        result["confidence"] = "low"
        result["reason"] = (
            f"Falha na revalidação: {exc}"
        )

        return result

    except Exception as exc:

        result["status"] = "validation_error"
        result["confidence"] = "low"
        result["reason"] = str(exc)

        return result


# ============================================================
# NUCLEI
# ============================================================

def run_nuclei(url: str) -> dict:
    """
    Executa Nuclei de forma limitada e salva JSONL temporário.

    Depois revalida automaticamente cada matched-at.
    """

    result = {
        "status": "not_run",
        "url": url,
        "returncode": None,
        "findings": [],
        "summary": {
            "total": 0,
            "confirmed": 0,
            "needs_review": 0,
            "false_positive": 0,
            "likely_false_positive": 0,
            "validation_error": 0,
        },
        "error": None,
    }

    try:

        cmd = [
            "nuclei",
            "-u",
            url,
            "-severity",
            "info,low,medium,high,critical",
            "-rl",
            "5",
            "-c",
            "5",
            "-timeout",
            "10",
            "-retries",
            "1",
            "-jsonl",
            "-silent",
        ]

        process = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
        )

        result["returncode"] = (
            process.returncode
        )

        stdout = process.stdout.strip()

        if not stdout:

            result["status"] = "ok"

            return result

        findings = []

        for line in stdout.splitlines():

            line = line.strip()

            if not line:
                continue

            try:
                finding = json.loads(line)
            except json.JSONDecodeError:
                continue

            matched_at = finding.get(
                "matched-at"
            )

            if not matched_at:

                finding["blueScan_validation"] = {
                    "status": "not_validated",
                    "reason": (
                        "Nuclei não forneceu "
                        "matched-at."
                    ),
                }

                findings.append(finding)
                continue

            validation = validate_nuclei_match(
                matched_at
            )

            finding[
                "blueScan_validation"
            ] = validation

            findings.append(finding)

        # ----------------------------------------------------
        # Resumo
        # ----------------------------------------------------

        for finding in findings:

            validation = finding.get(
                "blueScan_validation",
                {},
            )

            status = validation.get(
                "status"
            )

            if status == "false_positive":

                result["summary"][
                    "false_positive"
                ] += 1

            elif status == "likely_false_positive":

                result["summary"][
                    "likely_false_positive"
                ] += 1

            elif status == "needs_review":

                result["summary"][
                    "needs_review"
                ] += 1

            elif status == "validation_error":

                result["summary"][
                    "validation_error"
                ] += 1

            else:

                result["summary"][
                    "confirmed"
                ] += 1

        result["summary"]["total"] = len(
            findings
        )

        result["findings"] = findings
        result["status"] = "ok"

        return result

    except FileNotFoundError:

        result["status"] = "error"
        result["error"] = (
            "Nuclei não encontrado no sistema."
        )

        return result

    except subprocess.TimeoutExpired:

        result["status"] = "timeout"
        result["error"] = (
            "Nuclei excedeu o limite de "
            "300 segundos."
        )

        return result

    except Exception as exc:

        result["status"] = "error"
        result["error"] = str(exc)

        return result


# ============================================================
# SCAN PRINCIPAL
# ============================================================

def scan_target(url):
    """
    Executa todos os módulos do BlueScan.
    """

    started_at = datetime.now().astimezone()
    started_perf = time.perf_counter()

    result = {
        "target": url,
        "started_at": started_at.isoformat(),
        "finished_at": None,
        "duration_seconds": None,

        "http": None,
        "tls": None,
        "dns": None,
        "technology": None,
        "whatweb": None,
        "nuclei": None,
        "correlation": None,
    }

    # =========================================================
    # HTTP
    # =========================================================

    http_result = scan_http(url)

    result["http"] = http_result

    # =========================================================
    # TECNOLOGIA
    # =========================================================

    result["technology"] = scan_technology(
        http_result
    )

    # =========================================================
    # WHATWEB
    # =========================================================

    result["whatweb"] = run_whatweb(url)

    # =========================================================
    # TLS
    # =========================================================

    if url.startswith("https://"):

        tls_result = scan_tls(url)

        result["tls"] = tls_result

    else:

        tls_result = None

    # =========================================================
    # DNS
    # =========================================================

    host = url.split(
        "://",
        1,
    )[-1]

    host = host.split(
        "/",
        1,
    )[0]

    host = host.split(
        ":",
        1,
    )[0]

    result["dns"] = scan_dns(host)

    # =========================================================
    # NUCLEI + PÓS-VALIDAÇÃO
    # =========================================================

    result["nuclei"] = run_nuclei(url)

    # =========================================================
    # CORRELAÇÃO
    # =========================================================

    result["correlation"] = correlate(
        http_result=http_result,
        tls_result=tls_result,
    )

    # =========================================================
    # TEMPO
    # =========================================================

    finished_at = datetime.now().astimezone()

    result["finished_at"] = (
        finished_at.isoformat()
    )

    result["duration_seconds"] = round(
        time.perf_counter() - started_perf,
        2,
    )

    return result
PY
