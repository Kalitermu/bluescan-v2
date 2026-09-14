cd ~/bluescan-v2
source .venv/bin/activate

cat > scanner_nuclei.py <<'PY'
import json
import os
import subprocess
import tempfile


SAFE_TAGS = "misconfig,exposure,ssl,tech"
NUCLEI_TIMEOUT = 120


def _read_findings(temp_path: str, url: str) -> list:
    findings = []

    if not temp_path or not os.path.exists(temp_path):
        return findings

    try:
        with open(
            temp_path,
            "r",
            encoding="utf-8",
            errors="replace",
        ) as file:

            for line in file:
                line = line.strip()

                if not line:
                    continue

                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
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

                findings.append({
                    "template_id": item.get(
                        "template-id",
                        item.get("template_id", ""),
                    ),
                    "name": info.get(
                        "name",
                        "Achado Nuclei",
                    ),
                    "severity": str(
                        info.get(
                            "severity",
                            "info",
                        )
                    ).upper(),
                    "status": "INDICATION",
                    "source": "Nuclei",
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
                })

    except OSError:
        pass

    return findings


def scan_nuclei(url: str) -> dict:
    """
    Executa Nuclei em modo controlado.

    Categorias utilizadas:
    - misconfiguração
    - exposição
    - SSL/TLS
    - identificação tecnológica

    Os resultados são tratados como INDICAÇÃO
    e precisam de validação antes de serem
    considerados vulnerabilidades confirmadas.
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
    temp_path = None

    try:
        fd, temp_path = tempfile.mkstemp(
            prefix="bluescan-nuclei-",
            suffix=".jsonl",
        )

        os.close(fd)

        cmd = [
            "nuclei",
            "-u",
            url,
            "-tags",
            SAFE_TAGS,
            "-rl",
            "3",
            "-c",
            "2",
            "-timeout",
            "10",
            "-retries",
            "0",
            "-jsonl-export",
            temp_path,
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

        except subprocess.TimeoutExpired as exc:
            findings = _read_findings(
                temp_path,
                url,
            )

            stderr = ""

            if exc.stderr:
                stderr = str(exc.stderr).strip()

            return {
                "status": "timeout",
                "target": url,
                "tags": SAFE_TAGS.split(","),
                "findings": findings,
                "count": len(findings),
                "returncode": None,
                "timeout_seconds": NUCLEI_TIMEOUT,
                "partial": bool(findings),
                "error": (
                    "Nuclei não concluiu dentro "
                    f"de {NUCLEI_TIMEOUT} segundos."
                ),
                "warning": stderr or None,
            }

        findings = _read_findings(
            temp_path,
            url,
        )

        stderr = (
            process.stderr.strip()
            if process.stderr
            else ""
        )

        if process.returncode != 0:
            return {
                "status": "error",
                "target": url,
                "tags": SAFE_TAGS.split(","),
                "findings": findings,
                "count": len(findings),
                "returncode": process.returncode,
                "error": (
                    "Nuclei terminou com código "
                    f"{process.returncode}."
                ),
                "warning": stderr or None,
            }

        return {
            "status": "ok",
            "target": url,
            "tags": SAFE_TAGS.split(","),
            "findings": findings,
            "count": len(findings),
            "returncode": process.returncode,
            "warning": stderr or None,
        }

    except FileNotFoundError:
        return {
            "status": "error",
            "target": url,
            "findings": [],
            "count": 0,
            "error": (
                "Nuclei não encontrado no sistema."
            ),
        }

    except Exception as exc:
        return {
            "status": "error",
            "target": url,
            "findings": [],
            "count": 0,
            "error": str(exc),
        }

    finally:
        if temp_path:
            try:
                if os.path.exists(temp_path):
                    os.remove(temp_path)
            except Exception:
                pass
PY
