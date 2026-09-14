cd ~/bluescan-v2
source .venv/bin/activate

cp scanner.py scanner.before_dashboard_v2.py

cat > scanner.py <<'PY'
from datetime import datetime
import re
import subprocess
import time

from scanner_http import scan_http
from scanner_tls import scan_tls
from scanner_dns import scan_dns
from scanner_tech import scan_technology
from correlator import correlate


ANSI_ESCAPE = re.compile(
    r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])"
)


def run_whatweb(url: str) -> dict:
    """
    Executa WhatWeb em modo Stealthy (-a 1).

    O resultado textual do WhatWeb é convertido para uma
    estrutura simples de plugins para o BlueScan.
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


def scan_target(url):
    """
    Executa todos os módulos do BlueScan.

    Além dos resultados dos módulos, registra:
    - horário de início;
    - horário de término;
    - duração total da análise.
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
    # CORRELAÇÃO
    # =========================================================

    result["correlation"] = correlate(
        http_result=http_result,
        tls_result=tls_result,
    )

    # =========================================================
    # TEMPO DA ANÁLISE
    # =========================================================

    finished_at = datetime.now().astimezone()

    result["finished_at"] = finished_at.isoformat()

    result["duration_seconds"] = round(
        time.perf_counter() - started_perf,
        2,
    )

    return result
PY
