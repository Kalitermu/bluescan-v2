SEVERITY_ORDER = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


def normalize_finding(finding, source):
    return {
        "title": finding.get("title", "Achado sem título"),
        "severity": finding.get("severity", "INFO").upper(),
        "category": finding.get("category", source.upper()),
        "source": source,
        "evidence": finding.get("evidence", ""),
    }


def correlate(http_result=None, tls_result=None):
    findings = []

    if http_result:
        for finding in http_result.get("findings", []):
            findings.append(
                normalize_finding(finding, "HTTP")
            )

    if tls_result:
        for finding in tls_result.get("findings", []):
            findings.append(
                normalize_finding(finding, "TLS")
            )

    # Remove duplicidades
    unique = {}

    for finding in findings:
        key = (
            finding["title"],
            finding["category"],
            finding["evidence"],
        )

        unique[key] = finding

    findings = list(unique.values())

    # Ordena do maior risco para o menor
    findings.sort(
        key=lambda item: SEVERITY_ORDER.get(
            item["severity"], 0
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

    for finding in findings:
        severity = finding["severity"]

        if severity not in counts:
            severity = "INFO"

        counts[severity] += 1

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
            "critical": counts["CRITICAL"],
            "high": counts["HIGH"],
            "medium": counts["MEDIUM"],
            "low": counts["LOW"],
            "info": counts["INFO"],
        },
        "findings": findings,
    }
