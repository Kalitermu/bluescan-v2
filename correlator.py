from typing import Any, Dict, List


# ============================================================
# CONFIGURAÇÃO
# ============================================================

SEVERITY_ORDER = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFO": 1,
}

VALID_STATUS = {
    "confirmed",
    "review",
    "informational",
    "scanner_error",
}


# ============================================================
# HELPERS
# ============================================================

def _text(
    value: Any,
    default: str = "",
) -> str:

    if value is None:
        return default

    return str(value).strip()


def _normalize_severity(
    value: Any,
) -> str:

    severity = _text(
        value,
        "INFO",
    ).upper()

    if severity not in SEVERITY_ORDER:
        return "INFO"

    return severity


def _normalize_status(
    value: Any,
) -> str:

    status = _text(
        value,
    ).lower()

    if status in VALID_STATUS:
        return status

    return ""


def _status_from_finding(
    finding: Dict[str, Any],
) -> str:

    explicit = _normalize_status(
        finding.get("status")
    )

    if explicit:
        return explicit

    severity = _normalize_severity(
        finding.get("severity")
    )

    if severity == "INFO":
        return "informational"

    return "review"


# ============================================================
# NORMALIZAÇÃO
# ============================================================

def normalize_finding(
    finding: Dict[str, Any],
    source: str = "",
) -> Dict[str, Any]:

    severity = _normalize_severity(
        finding.get("severity")
    )

    status = _status_from_finding(
        finding
    )

    classification = status

    normalized = {
        "title": _text(
            finding.get(
                "title",
                "Achado sem título",
            ),
            "Achado sem título",
        ),

        "category": _text(
            finding.get(
                "category",
                "Security",
            ),
            "Security",
        ),

        "severity": severity,

        "source": _text(
            finding.get(
                "source",
                source,
            ),
            source,
        ),

        "evidence": _text(
            finding.get(
                "evidence",
            )
        ),

        "impact": _text(
            finding.get(
                "impact",
            )
        ),

        "consequence": _text(
            finding.get(
                "consequence",
            )
        ),

        "recommendation": _text(
            finding.get(
                "recommendation",
            )
        ),

        "confidence": _text(
            finding.get(
                "confidence",
                "medium",
            ),
            "medium",
        ),

        "status": status,

        "classification": classification,
    }

    return normalized


# ============================================================
# DEDUPLICAÇÃO
# ============================================================

def deduplicate_findings(
    findings: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:

    unique: List[Dict[str, Any]] = []

    seen = set()

    for finding in findings:

        key = (
            _text(finding.get("title")).lower(),
            _text(finding.get("source")).lower(),
            _text(finding.get("severity")).upper(),
            _text(finding.get("status")).lower(),
            _text(finding.get("evidence")).lower(),
        )

        if key in seen:
            continue

        seen.add(key)

        unique.append(
            finding
        )

    return unique


# ============================================================
# ORDENAÇÃO
# ============================================================

def _sort_findings(
    findings: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:

    return sorted(
        findings,
        key=lambda item: (
            -SEVERITY_ORDER.get(
                _normalize_severity(
                    item.get("severity")
                ),
                1,
            ),
            _text(
                item.get("title")
            ).lower(),
        ),
    )


# ============================================================
# SEVERIDADE OBSERVADA
# ============================================================

def _observed_severity(
    findings: List[Dict[str, Any]],
) -> str:

    confirmed = [
        item
        for item in findings
        if item.get("classification")
        == "confirmed"
    ]

    if not confirmed:
        return "NONE"

    highest = max(
        confirmed,
        key=lambda item: SEVERITY_ORDER.get(
            _normalize_severity(
                item.get("severity")
            ),
            1,
        ),
    )

    return _normalize_severity(
        highest.get("severity")
    )


# ============================================================
# RESUMO
# ============================================================

def build_summary(
    findings: List[Dict[str, Any]],
) -> Dict[str, Any]:

    confirmed = [
        item
        for item in findings
        if item.get("classification")
        == "confirmed"
    ]

    review = [
        item
        for item in findings
        if item.get("classification")
        == "review"
    ]

    informational = [
        item
        for item in findings
        if item.get("classification")
        == "informational"
    ]

    scanner_errors = [
        item
        for item in findings
        if item.get("classification")
        == "scanner_error"
    ]

    counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0,
    }

    for finding in findings:

        severity = _normalize_severity(
            finding.get("severity")
        )

        counts[severity] += 1

    severity = _observed_severity(
        findings
    )

    if confirmed:

        message = (
            "Foram encontradas evidências "
            "classificadas como confirmadas."
        )

    elif review:

        message = (
            "Nenhuma vulnerabilidade foi confirmada. "
            "Existem achados que requerem revisão."
        )

    else:

        message = (
            "Nenhuma vulnerabilidade foi confirmada "
            "pelos testes executados."
        )

    return {
        "total": len(findings),

        "confirmed": len(confirmed),

        "review": len(review),

        "informational": len(informational),

        "scanner_errors": len(scanner_errors),

        "counts": counts,

        "severity": severity,

        "message": message,
    }


# ============================================================
# CORRELATOR PRINCIPAL
# ============================================================

def correlate_results(
    results: Dict[str, Any],
) -> Dict[str, Any]:

    findings: List[Dict[str, Any]] = []

    sources: Dict[str, str] = {}

    checks: Dict[str, str] = {}

    if not isinstance(
        results,
        dict,
    ):

        summary = build_summary([])

        return {
            "findings": [],
            "sources": {},
            "checks": {},
            "total": 0,
            "counts": summary["counts"],
            "confirmed": [],
            "review": [],
            "informational": [],
            "scanner_error": [],
            "severity": "NONE",
            "summary": summary,
        }

    ignored_keys = {
        "target",
        "url",
        "summary",
        "technical",
        "metadata",
        "status",
        "checks",
        "findings",
    }

    for source, raw_findings in results.items():

        if source in ignored_keys:
            continue

        sources[str(source)] = "executed"

        if isinstance(
            raw_findings,
            dict,
        ):

            if isinstance(
                raw_findings.get("findings"),
                list,
            ):

                module_checks = raw_findings.get(
                    "checks"
                )

                if isinstance(
                    module_checks,
                    dict,
                ):

                    checks.update(
                        {
                            str(k): str(v)
                            for k, v
                            in module_checks.items()
                        }
                    )

                raw_findings = raw_findings[
                    "findings"
                ]

            elif isinstance(
                raw_findings.get("results"),
                list,
            ):

                raw_findings = raw_findings[
                    "results"
                ]

            else:

                raw_findings = [
                    raw_findings
                ]

        if not isinstance(
            raw_findings,
            list,
        ):
            continue

        for finding in raw_findings:

            if not isinstance(
                finding,
                dict,
            ):
                continue

            normalized = normalize_finding(
                finding,
                str(source),
            )

            findings.append(
                normalized
            )

    # ========================================================
    # DEDUPLICAÇÃO
    # ========================================================

    unique = deduplicate_findings(
        findings
    )

    # ========================================================
    # ORDENAÇÃO
    # ========================================================

    unique = _sort_findings(
        unique
    )

    # ========================================================
    # RESUMO
    # ========================================================

    summary = build_summary(
        unique
    )

    # ========================================================
    # LISTAS POR STATUS
    # ========================================================

    confirmed = [
        item
        for item in unique
        if item.get("classification")
        == "confirmed"
    ]

    review = [
        item
        for item in unique
        if item.get("classification")
        == "review"
    ]

    informational = [
        item
        for item in unique
        if item.get("classification")
        == "informational"
    ]

    scanner_error = [
        item
        for item in unique
        if item.get("classification")
        == "scanner_error"
    ]

    # ========================================================
    # RETORNO NORMALIZADO
    # ========================================================

    return {
        "findings": unique,

        "sources": sources,

        "checks": checks,

        "total": len(unique),

        "counts": summary["counts"],

        "confirmed": confirmed,

        "review": review,

        "informational": informational,

        "scanner_error": scanner_error,

        "severity": summary["severity"],

        "summary": summary,
    }


# ============================================================
# COMPATIBILIDADE
# ============================================================

def correlate(
    findings: List[Dict[str, Any]],
    checks: Dict[str, Any] | None = None,
    technical: Dict[str, Any] | None = None,
    target: str = "",
) -> Dict[str, Any]:

    return correlate_results(
        {
            "Security Checks": {
                "findings": findings,
                "checks": checks or {},
            }
        }
    )


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
            "Findings": findings
        }
    )