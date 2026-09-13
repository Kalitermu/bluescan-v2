cd ~/bluescan-v2
source .venv/bin/activate

cp scanner.py scanner.before_whatweb_fix.py

cat > scanner.py <<'PY'
from scanner_http import scan_http
from scanner_tls import scan_tls
from scanner_dns import scan_dns
from scanner_tech import scan_technology
from correlator import correlate

import subprocess
import re


def run_whatweb(url: str) -> dict:
    """
    Executa WhatWeb em modo Stealthy (-a 1).
    Uso destinado a alvos autorizados/laboratório.
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

        stdout = process.stdout.strip()
        stderr = process.stderr.strip()

        if process.returncode != 0:
            return {
                "status": "error",
                "url": url,
                "returncode": process.returncode,
                "error": stderr or stdout or "WhatWeb retornou erro.",
                "plugins": [],
            }

        plugins = []

        # WhatWeb normalmente retorna:
        #
        # https://example.com [200 OK] Allow[GET, HEAD],
        # Country[UNITED STATES][US], HTML5,
        # HTTPServer[cloudflare], IP[...],
        # Title[Example Domain]
        #
        # Extraímos cada plugin sem inventar informações.

        match = re.search(
            r"\[.*?\]\s*(.*)$",
            stdout,
            re.DOTALL,
        )

        if match:
            plugin_text = match.group(1).strip()

            # Divide pelos plugins separados por vírgula,
            # preservando valores entre colchetes.
            parts = re.findall(
                r"(?:[A-Za-z0-9_.+-]+)"
                r"(?:\[[^\]]*\])*",
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

                plugins.append({
                    "name": name,
                    "details": values,
                    "raw": part,
                })

        return {
            "status": "ok",
            "url": url,
            "returncode": process.returncode,
            "raw": stdout,
            "plugins": plugins,
            "plugin_count": len(plugins),
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
            "error": "WhatWeb excedeu o tempo limite de 45 segundos.",
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
    result = {
        "target": url,
        "http": None,
        "tls": None,
        "dns": None,
        "technology": None,
        "whatweb": None,
        "correlation": None,
    }

    # HTTP
    http_result = scan_http(url)
    result["http"] = http_result

    # Tecnologia detectada pelo scanner Python
    result["technology"] = scan_technology(
        http_result
    )

    # WhatWeb
    result["whatweb"] = run_whatweb(url)

    # TLS
    if url.startswith("https://"):
        tls_result = scan_tls(url)
        result["tls"] = tls_result
    else:
        tls_result = None

    # DNS
    host = url.split("://", 1)[-1]
    host = host.split("/", 1)[0]
    host = host.split(":", 1)[0]

    result["dns"] = scan_dns(host)

    # Correlação
    result["correlation"] = correlate(
        http_result=http_result,
        tls_result=tls_result,
    )

    return result
PY
