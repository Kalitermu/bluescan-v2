
cd ~/bluescan-v2

cp correlator.py correlator.backup_antes_profissional.py

cat > correlator.py <<'PY'
SEVERITY_ORDER = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


def make_id(title):
    return (
        str(title)
        .lower()
        .replace(" ", "-")
        .replace("/", "-")
        .replace(":", "")
    )


def normalize_finding(finding, source):
    title = str(finding.get(
        "title",
        "Achado sem título"
    ))

    severity = str(finding.get(
        "severity",
        "INFO"
    )).upper()

    if severity not in SEVERITY_ORDER:
        severity = "INFO"

    evidence = str(finding.get(
        "evidence",
        ""
    ))

    title_lower = title.lower()

    if severity == "INFO":
        finding_type = "INFORMATION"
    elif any(word in title_lower for word in [
        "header",
        "cabeçalho",
        "política",
        "policy",
        "cookie",
        "configuração",
    ]):
        finding_type = "CONFIGURATION"
    else:
        finding_type = "VULNERABILITY"

    status = str(finding.get(
        "status",
        "CONFIRMED"
    )).upper()

    if status not in {"CONFIRMED", "INDICATION"}:
        status = "CONFIRMED"

    confidence = str(finding.get(
        "confidence",
        "HIGH"
    )).upper()

    if confidence not in {"HIGH", "MEDIUM", "LOW"}:
        confidence = "HIGH"

    if finding_type == "CONFIGURATION":
        description = (
            "Foi identificada uma configuração de "
            "segurança ausente ou inadequada."
        )

        impact = (
            "A ausência dessa proteção pode reduzir "
            "as defesas da aplicação contra determinados "
            "cenários de ataque."
        )

        consequence = (
            "Um atacante poderá se beneficiar da "
            "proteção ausente, dependendo das demais "
            "condições da aplicação."
        )

    elif finding_type == "VULNERABILITY":
        description = (
            "Foi identificada uma condição que pode "
            "representar uma vulnerabilidade de segurança."
        )

        impact = (
            "A condição pode aumentar o risco de "
            "comprometimento da aplicação ou de seus dados."
        )

        consequence = (
            "Se explorável, poderá afetar a confidencialidade, "
            "integridade ou disponibilidade."
        )

    else:
        description = (
            "Foi identificada uma informação relevante "
            "para a avaliação de segurança."
        )

        impact = (
            "A informação ajuda a compreender a superfície "
            "de ataque do alvo."
        )

        consequence = (
            "A informação isoladamente não significa "
            "que o sistema esteja comprometido."
        )

    return {
        "id": finding.get(
            "id",
            make_id(title)
        ),

        "title": title,

        "severity": severity,

        "type": finding.get(
            "type",
            finding_type
        ),

        "status": status,

        "confidence": confidence,

        "category": finding.get(
            "category",
            source.upper()
        ),

        "source": source,

        "cve": finding.get("cve"),

        "cwe": finding.get("cwe"),

        "evidence": evidence,

        "description": finding.get(
            "description",
            description
        ),

        "impact": finding.get(
            "impact",
            impact
        ),

        "consequence": finding.get(
            "consequence",
            consequence
        ),

        "recommendation": finding.get(
            "recommendation",
            "Revisar a configuração e aplicar "
            "as boas práticas de segurança."
        ),

        "validation": finding.get(
            "validation",
            "Executar novamente o BlueScan após "
            "a correção e confirmar que o achado "
            "não aparece mais."
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

    modules = [
        ("HTTP", http_result),
        ("TLS", tls_result),
        ("DNS", dns_result),
        ("TECHNOLOGY", technology_result),
        ("NUCLEI", nuclei_result),
        ("WHATWEB", whatweb_result),
        ("SUBFINDER", subdomains_result),
    ]

    for source, result in modules:
        if not isinstance(result, dict):
            continue

        raw_findings = result.get(
            "findings",
            []
        )

        if not isinstance(raw_findings, list):
            continue

        for finding in raw_findings:
            if isinstance(finding, dict):
                findings.append(
                    normalize_finding(
                        finding,
                        source
                    )
                )

    unique = {}

    for finding in findings:
        key = (
            finding["title"],
            finding["source"],
            finding["evidence"],
        )

        unique[key] = finding

    findings = list(unique.values())

    findings.sort(
        key=lambda item: SEVERITY_ORDER.get(
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

    if counts["CRITICAL"] > 0:
        risk = "CRITICAL"
    elif counts["HIGH"] > 0:
        risk = "HIGH"
    elif counts["MEDIUM"] > 0:
        risk = "MEDIUM"
    elif counts["LOW"] > 0:
        risk = "LOW"
    else:
        risk = "INFO"

    return {
        "risk": risk,

        "summary": {
            "total_findings": len(findings),
            "confirmed": confirmed,
            "indications": indications,
            "critical": counts["CRITICAL"],
            "high": counts["HIGH"],
            "medium": counts["MEDIUM"],
            "low": counts["LOW"],
            "info": counts["INFO"],
            "vulnerabilities": types["VULNERABILITY"],
            "configuration": types["CONFIGURATION"],
            "hardening": types["HARDENING"],
            "information": types["INFORMATION"],
        },

        "findings": findings,
    }
PY
     
