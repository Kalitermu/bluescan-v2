 cd ~/bluescan-v2

cp correlator.py correlator.backup.py

cat > correlator.py <<'PY'
SEVERITY_ORDER = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


def normalize_finding(finding, source):
    severity = str(
        finding.get("severity", "INFO")
    ).upper()

    if severity not in SEVERITY_ORDER:
        severity = "INFO"

    title = finding.get(
        "title",
        "Achado sem título"
    )

    category = finding.get(
        "category",
        source.upper()
    )

    evidence = finding.get(
        "evidence",
        ""
    )

    # Classificação profissional
    if severity == "INFO":
        finding_type = finding.get(
            "type",
            "INFORMATION"
        )
    elif "header" in title.lower() or \
         "política" in title.lower() or \
         "policy" in title.lower():
        finding_type = "CONFIGURATION"
    else:
        finding_type = finding.get(
            "type",
            "VULNERABILITY"
        )

    # Status
    status = finding.get(
        "status",
        "CONFIRMED"
    )

    if status not in {
        "CONFIRMED",
        "INDICATION"
    }:
        status = "CONFIRMED"

    # Confiança
    confidence = finding.get(
        "confidence",
        "HIGH"
    )

    if confidence not in {
        "HIGH",
        "MEDIUM",
        "LOW"
    }:
        confidence = "HIGH"

    return {
        "id": finding.get(
            "id",
            title.lower()
            .replace(" ", "-")
            .replace("/", "-")
        ),

        "title": title,

        "severity": severity,

        "type": finding_type,

        "status": status,

        "confidence": confidence,

        "category": category,

        "source": source,

        "cve": finding.get(
            "cve"
        ),

        "cwe": finding.get(
            "cwe"
        ),

        "evidence": evidence,

        "description": finding.get(
            "description",
            "O scanner identificou esta condição no alvo analisado."
        ),

        "impact": finding.get(
            "impact",
            "A condição pode reduzir a segurança da aplicação ou aumentar a superfície de ataque."
        ),

        "consequence": finding.get(
            "consequence",
            "Se explorada por um agente malicioso, esta condição pode facilitar ataques contra a aplicação ou seus usuários."
        ),

        "recommendation": finding.get(
            "recommendation",
            "Revisar a configuração e aplicar as boas práticas de segurança recomendadas."
        ),

        "validation": finding.get(
            "validation",
            "Executar uma nova varredura após a correção e confirmar que o achado não aparece mais."
        ),
    }


def correlate(
    http_result=None,
    tls_result=None,
    dns_result=None,
    technology_result=None,
    nuclei_result=None,
    whatweb_result=None,
    subdomains_result=None,
):
    findings = []

    sources = [
        ("HTTP", http_result),
        ("TLS", tls_result),
        ("DNS", dns_result),
        ("TECHNOLOGY", technology_result),
        ("NUCLEI", nuclei_result),
        ("WHATWEB", whatweb_result),
        ("SUBFINDER", subdomains_result),
    ]

    for source, result in sources:

        if not isinstance(result, dict):
            continue

        result_findings = result.get(
            "findings",
            []
        )

        if not isinstance(
            result_findings,
            list
        ):
            continue

        for finding in result_findings:

            if not isinstance(
                finding,
                dict
            ):
                continue

            findings.append(
                normalize_finding(
                    finding,
                    source
                )
            )

    # Remove duplicados
    unique = {}

    for finding in findings:

        key = (
            finding["title"],
            finding["category"],
            finding["source"],
            finding["evidence"],
        )

        unique[key] = finding

    findings = list(
        unique.values()
    )

    # Mais graves primeiro
    findings.sort(
        key=lambda item:
            SEVERITY_ORDER.get(
                item["severity"],
                0
            ),
        reverse=True
    )

    counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0,
    }

    types = {
        "VULNERABILITY": 0,
        "CONFIGURATION": 0,
        "HARDENING": 0,
        "INFORMATION": 0,
    }

    confirmed = 0
    indications = 0

    for finding in findings:

        severity = finding["severity"]

        if severity in counts:
            counts[severity] += 1

        finding_type = finding["type"]

        if finding_type in types:
            types[finding_type] += 1

        if finding["status"] == "CONFIRMED":
            confirmed += 1
        else:
            indications += 1

    # Risco geral
    if counts["CRITICAL"] > 0:
        overall_risk = "CRITICAL"
    elif counts["HIGH"] > 0:
        overall_risk = "HIGH"
    elif counts["MEDIUM"] > 0:
        overall_risk = "MEDIUM"
    elif counts["LOW"] > 0:
        overall_risk = "LOW"
    else:
        overall_risk = "INFO"

    return {
        "risk": overall_risk,

        "summary": {
            "total_findings": len(findings),

            "confirmed": confirmed,

            "indications": indications,

            "critical": counts["CRITICAL"],

            "high": counts["HIGH"],

            "medium": counts["MEDIUM"],

            "low": counts["LOW"],

            "info": counts["INFO"],

            "vulnerabilities":
                types["VULNERABILITY"],

            "configuration":
                types["CONFIGURATION"],

            "hardening":
                types["HARDENING"],

            "information":
                types["INFORMATION"],
        },

        "findings": findings,
    }
PY
