
cd ~/bluescan-v2

cat > correlator.py <<'PY'
SEVERITY_WEIGHT = {
    "CRITICAL": 25,
    "HIGH": 15,
    "MEDIUM": 8,
    "LOW": 3,
    "INFO": 0,
}


def normalize_severity(value):
    """
    Normaliza a severidade para os níveis utilizados pelo BlueScan.
    """

    if value is None:
        return "INFO"

    severity = str(value).strip().upper()

    aliases = {
        "CRIT": "CRITICAL",
        "CRÍTICO": "CRITICAL",
        "CRITICO": "CRITICAL",

        "ALTO": "HIGH",

        "MÉDIO": "MEDIUM",
        "MEDIO": "MEDIUM",

        "BAIXO": "LOW",

        "INFORMATION": "INFO",
        "INFORMATIONAL": "INFO",
        "HARDENING": "INFO",
    }

    return aliases.get(
        severity,
        severity if severity in SEVERITY_WEIGHT else "INFO",
    )


def collect_findings(http_result, tls_result):
    """
    Coleta achados dos módulos do BlueScan.
    """

    findings = []

    if isinstance(http_result, dict):

        http_findings = http_result.get(
            "findings",
            [],
        )

        if isinstance(http_findings, list):
            findings.extend(http_findings)

    if isinstance(tls_result, dict):

        tls_findings = tls_result.get(
            "findings",
            [],
        )

        if isinstance(tls_findings, list):
            findings.extend(tls_findings)

    return findings


def normalize_finding(finding):
    """
    Normaliza um achado individual.
    """

    if not isinstance(finding, dict):
        return None

    severity = normalize_severity(
        finding.get(
            "severity",
            "INFO",
        )
    )

    return {
        "title": str(
            finding.get(
                "title",
                "Achado",
            )
        ),
        "severity": severity,
        "category": str(
            finding.get(
                "category",
                "General",
            )
        ),
        "evidence": str(
            finding.get(
                "evidence",
                "",
            )
        ),
        "recommendation": str(
            finding.get(
                "recommendation",
                "",
            )
        ),
    }


def deduplicate_findings(findings):
    """
    Remove achados duplicados mantendo a primeira ocorrência.
    """

    unique = []
    seen = set()

    for finding in findings:

        key = (
            finding.get("severity"),
            finding.get("title"),
            finding.get("category"),
        )

        if key in seen:
            continue

        seen.add(key)
        unique.append(finding)

    return unique


def calculate_summary(findings):
    """
    Conta achados por severidade.
    """

    summary = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }

    for finding in findings:

        severity = normalize_severity(
            finding.get("severity")
        )

        key = severity.lower()

        if key in summary:
            summary[key] += 1

    return summary


def calculate_score(findings):
    """
    Calcula score de segurança de 0 a 100.

    Quanto maior o número de achados relevantes,
    menor o score.
    """

    penalty = 0

    for finding in findings:

        severity = normalize_severity(
            finding.get("severity")
        )

        penalty += SEVERITY_WEIGHT.get(
            severity,
            0,
        )

    score = max(
        0,
        100 - penalty,
    )

    return score


def calculate_risk(summary):
    """
    Determina o risco geral.
    """

    if summary["critical"] > 0:
        return "CRITICAL"

    if summary["high"] > 0:
        return "HIGH"

    if summary["medium"] > 0:
        return "MEDIUM"

    if summary["low"] > 0:
        return "LOW"

    return "INFO"


def risk_label(risk):
    """
    Retorna descrição amigável do risco.
    """

    labels = {
        "CRITICAL": "CRÍTICO",
        "HIGH": "ALTO",
        "MEDIUM": "MÉDIO",
        "LOW": "BAIXO",
        "INFO": "INFORMAÇÕES",
    }

    return labels.get(
        risk,
        "INFORMAÇÕES",
    )


def correlate(
    http_result=None,
    tls_result=None,
):
    """
    Correlaciona os resultados dos módulos HTTP e TLS.
    """

    raw_findings = collect_findings(
        http_result,
        tls_result,
    )

    normalized = []

    for finding in raw_findings:

        normalized_finding = normalize_finding(
            finding
        )

        if normalized_finding:
            normalized.append(
                normalized_finding
            )

    findings = deduplicate_findings(
        normalized
    )

    summary = calculate_summary(
        findings
    )

    score = calculate_score(
        findings
    )

    risk = calculate_risk(
        summary
    )

    return {
        "risk": risk,
        "risk_label": risk_label(risk),
        "score": score,
        "summary": summary,
        "findings": findings,
    }
PY
