cd ~/bluescan-v2
source .venv/bin/activate

cat > scanner_nuclei.py <<'PY'
import json
import os
import subprocess
import tempfile


SAFE_TAGS = "misconfig,exposure,ssl,tech"


def scan_nuclei(url: str) -> dict:
    """
    Executa Nuclei em modo controlado.

    Esta versão utiliza somente categorias voltadas a:
    - misconfiguração
    - exposição
    - SSL/TLS
    - identificação tecnológica

    Os resultados são tratados como INDICAÇÃO e precisam
    de validação manual antes de serem considerados
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

        process = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=120,
        )

        findings = []

        if os.path.exists(temp_path):

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

                    info = item.get(
                        "info",
                        {},
                    )

                    if not isinstance(info, dict):
                        info = {}

                    classification = info.get(
                        "classification",
                        {},
                    )

                    if not isinstance(
                        classification,
                        dict,
                    ):
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

        stderr = (
            process.stderr.strip()
            if process.stderr
            else ""
        )

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

    except subprocess.TimeoutExpired:

        return {
            "status": "error",
            "target": url,
            "findings": [],
            "count": 0,
            "error": (
                "Nuclei excedeu o limite "
                "de 120 segundos."
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
