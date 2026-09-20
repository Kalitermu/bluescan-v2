from typing import Any, Dict, List


SEVERITY_ORDER = {
    "NONE": 0,
    "INFO": 1,
    "LOW": 2,
    "MEDIUM": 3,
    "HIGH": 4,
    "CRITICAL": 5,
}

VALID_STATUS = {
    "confirmed",
    "review",
    "informational",
    "scanner_error",
}


def _text(value: Any) -> str:
    if value is None:
        return ""

    return str(value).strip()


def _normalize_severity(value: Any) -> str:
    severity = _text(value).upper()

    if severity not in {
        "INFO",
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL",
    }:
        return "INFO"

    return severity


def _normalize_status(value: Any) -> str:
    status = _text(value).lower()

    aliases = {
        "informative": "informational",
        "info": "informational",
        "informational": "informational",
        "review_required": "review",
        "needs_review": "review",
        "manual_review": "review",
        "confirmed": "confirmed",
        "review": "review",
        "scanner_error": "scanner_error",
        "error": "scanner_error",
    }

    return aliases.get(
        status,
        "review",
    )


def _status_from_finding(
    finding: Dict[str, Any],
    severity: str,
) -> str:
    """
    Define um status consistente quando o scanner
    ainda não forneceu um explicitamente.

    Regras conservadoras:
    - INFO -> informational
    - erro explícito -> scanner_error
    - demais achados -> review

    Vulnerabilidade confirmada nunca é inferida
    somente pela severidade.
    """

    explicit_status = finding.get("status")

    if explicit_status:
        return _normalize_status(
            explicit_status
        )

    if severity == "INFO":
        return "informational"

    return "review"


def normalize_finding(
    finding: Any,
    source: str = "",
) -> Dict[str, Any]:

    if not isinstance(finding, dict):
        finding = {
            "title": _text(finding),
        }

    severity = _normalize_severity(
        finding.get(
            "severity",
            "INFO",
        )
    )

    status = _status_from_finding(
        finding,
        severity,
    )

    normalized = {
        "title": _text(
            finding.get(
                "title",
                "Achado sem título",
            )
        ),
        "severity": severity,
        "status": status,
        "category": _text(
            finding.get(
                "category",
                "Uncategorized",
            )
        ),
        "source": _text(
            finding.get(
                "source",
                source,
            )
        ),
        "evidence": _text(
            finding.get(
                "evidence",
                "",
            )
        ),
        "impact": _text(
            finding.get(
                "impact",
                "",
            )
        ),
        "consequence": _text(
            finding.get(
                "consequence",
                "",
            )
        ),
        "recommendation": _text(
            finding.get(
                "recommendation",
                "",
            )
        ),
    }

    return normalized


def deduplicate_findings(
    findings: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:

    unique = []
    seen = set()

    for finding in findings:

        key = (
            finding.get("title", ""),
            finding.get("source", ""),
            finding.get("severity", ""),
            finding.get("status", ""),
            finding.get("evidence", ""),
        )

        if key in seen:
            continue

        seen.add(key)
        unique.append(finding)

    return unique


def _reclassify_status(
    finding: Dict[str, Any],
) -> Dict[str, Any]:

    status = _normalize_status(
        finding.get("status")
    )

    severity = _normalize_severity(
        finding.get("severity")
    )

    # Nunca transforma INFO em vulnerabilidade.
    if severity == "INFO":
        status = "informational"

    # Confirmado somente permanece confirmado
    # quando o próprio finding explicitamente
    # trouxe esse status.
    elif status == "confirmed":
        status = "confirmed"

    # Erro de scanner permanece erro.
    elif status == "scanner_error":
        status = "scanner_error"

    # Todo achado sem confirmação explícita
    # permanece para revisão.
    else:
        status = "review"

    finding["severity"] = severity
    finding["status"] = status

    return finding


def build_summary(
    findings: List[Dict[str, Any]],
) -> Dict[str, Any]:

    counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0,
    }

    confirmed = 0
    review = 0
    informational = 0
    scanner_error = 0

    highest_confirmed = "NONE"

    for finding in findings:

        severity = _normalize_severity(
            finding.get(
                "severity"
            )
        )

        status = _normalize_status(
            finding.get(
                "status"
            )
        )

        counts[severity] += 1

        if status == "confirmed":
            confirmed += 1

            if (
                SEVERITY_ORDER[severity]
                > SEVERITY_ORDER[
                    highest_confirmed
                ]
            ):
                highest_confirmed = severity

        elif status == "review":
            review += 1

        elif status == "informational":
            informational += 1

        elif status == "scanner_error":
            scanner_error += 1

    return {
        "total": len(findings),
        "counts": counts,
        "confirmed": confirmed,
        "review": review,
        "informational": informational,
        "scanner_error": scanner_error,
        "severity": highest_confirmed,
    }


def correlate_results(
    results: Dict[str, Any],
) -> Dict[str, Any]:

    all_findings = []

    if not isinstance(results, dict):
        results = {}

    for source, data in results.items():

        if isinstance(data, dict):
            source_findings = data.get(
                "findings",
                [],
            )
        elif isinstance(data, list):
            source_findings = data
        else:
            continue

        if not isinstance(
            source_findings,
            list,
        ):
            continue

        for finding in source_findings:

            normalized = normalize_finding(
                finding,
                source=str(source),
            )

            normalized = _reclassify_status(
                normalized
            )

            all_findings.append(
                normalized
            )

    all_findings = deduplicate_findings(
        all_findings
    )

    summary = build_summary(
        all_findings
    )

    sources = sorted(
        {
            finding.get(
                "source",
                "",
            )
            for finding in all_findings
            if finding.get(
                "source",
                "",
            )
        }
    )

    return {
        "findings": all_findings,
        "sources": sources,
        "total": summary["total"],
        "counts": summary["counts"],
        "confirmed": summary["confirmed"],
        "review": summary["review"],
        "informational": summary["informational"],
        "scanner_error": summary[
            "scanner_error"
        ],
        "severity": summary["severity"],
    }


def correlate(
    findings: List[Dict[str, Any]],
    checks: Any = None,
    technical: Any = None,
    target: str = "",
) -> Dict[str, Any]:

    result = correlate_results(
        {
            "scanner": findings or [],
        }
    )

    result["target"] = target
    result["checks"] = (
        checks
        if isinstance(checks, dict)
        else {}
    )
    result["technical"] = (
        technical
        if isinstance(technical, dict)
        else {}
    )

    return result


def normalize_results(
    results: Dict[str, Any],
) -> Dict[str, Any]:

    return correlate_results(
        results
    )


def process_findings(
    findings: List[Dict[str, Any]],
) -> Dict[str, Any]:

    return correlate_results(
        {
            "scanner": findings or [],
        }
    )