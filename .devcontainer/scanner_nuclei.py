(
          cd ~/bluescan-v2
source .venv/bin/activate

cat > scanner_nuclei.py <<'PY'
import json
import subprocess


SAFE_TAGS = "ssl,misconfig"

NUCLEI_TIMEOUT = 15


def scan_nuclei(url: str) -> dict:
    """
    Executa Nuclei de forma controlada.

    O Nuclei é opcional no BlueScan.
    Se não terminar dentro do limite, o módulo retorna
    TIMEOUT e o restante do scanner continua normalmente.

    Resultados do Nuclei são tratados como INDICATION.
    Eles não são classificados automaticamente como
    vulnerabilidades confirmadas.
    """

    if not isinstance(url, str) or not url.strip():
        return {
            "status": "error",
            "target": url,
            "findings": [],
            "count": 0,
            "error": "Alvo inválido.",
        }

    url = url.strip()

    cmd = [
        "nuclei",
        "-u",
        url,
        "-tags",
        SAFE_TAGS,
        "-rl",
        "1",
        "-c",
        "1",
        "-timeout",
        "3",
        "-retries",
        "0",
        "-silent",
    ]

    try:
        process = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=NUCLEI_TIMEOUT,
        )

        stdout = process.stdout or ""
        stderr = process.stderr or ""

        findings = []

        for line in stdout.splitlines():

            line = line.strip()

            if not line:
                continue

            # Nuclei pode retornar JSONL quando configurado
            # para JSON. Se a linha não for JSON, ignoramos.
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue

            if not isinstance(item, dict):
                continue

            info = item.get("info", {})

            if not isinstance(info, dict):
                info = {}

            classification = info.get(
                "classification",
                {},
            )

            if not isinstance(classification, dict):
                classification = {}

            severity = str(
                info.get(
                    "severity",
                    "info",
                )
            ).upper()

            findings.append({
                "template_id": item.get(
                    "template-id",
                    item.get("template_id", ""),
                ),
                "name": info.get(
                    "name",
                    "Achado Nuclei",
                ),
                "severity": severity,
                "status": "INDICATION",
                "source": "Nuclei",
                "category": "SECURITY_SCAN",
                "matched_at": item.get(
                    "matched-at",
                    url,
                ),
                "type": info.get(
                    "type",
                    "",
                ),
                "description": info.get(
                    "description",
                    "",
                ),
                "reference": info.get(
                    "reference",
                    [],
                ),
                "cve": classification.get(
                    "cve-id",
                    [],
                ),
                "cwe": classification.get(
                    "cwe-id",
                    [],
                ),
                "evidence": item.get(
                    "extracted-results",
                    [],
                ),
                "validation": (
                    "Indicação automatizada. "
                    "Validar manualmente antes de "
                    "classificar como vulnerabilidade confirmada."
                ),
            })

        return {
            "status": "ok",
            "target": url,
            "tags": SAFE_TAGS.split(","),
            "findings": findings,
            "count": len(findings),
            "returncode": process.returncode,
            "warning": stderr.strip() or None,
            "timeout_seconds": NUCLEI_TIMEOUT,
        }

    except FileNotFoundError:

        return {
            "status": "error",
            "target": url,
            "findings": [],
            "count": 0,
            "error": "Nuclei não encontrado no sistema.",
            "timeout_seconds": NUCLEI_TIMEOUT,
        }

    except subprocess.TimeoutExpired:

        return {
            "status": "timeout",
            "target": url,
            "findings": [],
            "count": 0,
            "error": (
                "Nuclei não concluiu dentro de "
                f"{NUCLEI_TIMEOUT} segundos. "
                "O restante do BlueScan pode continuar."
            ),
            "timeout_seconds": NUCLEI_TIMEOUT,
        }

    except Exception as exc:

        return {
            "status": "error",
            "target": url,
            "findings": [],
            "count": 0,
            "error": str(exc),
            "timeout_seconds": NUCLEI_TIMEOUT,
        }
PY                  
