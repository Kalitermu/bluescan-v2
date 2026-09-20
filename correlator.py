cd ~/bluescan-v2
source .venv/bin/activate

cat > correlator.py <<'PY'
SEVERITY_ORDER = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


VALID_STATUSES = {
    "OBSERVATION",
    "INDICATION",
    "CONFIRMED",
}


def make_id(title):
    return (
        str(title)
        .lower()
        .replace(" ", "-")
        .replace("/", "-")
        .replace(":", "")
    )


def infer_finding_type(finding):
    """
    Determina o tipo sem transformar observações em vulnerabilidades.
    """

    explicit_type = str(
        finding.get("type", "")
    ).upper().strip()

    if explicit_type in {
        "INFORMATION",
        "RECONNAISSANCE",
        "CONFIGURATION",
        "VULNERABILITY",
        "HARDENING",
    }:
        return explicit_type

    title = str(
        finding.get("title", "")
    ).lower()

    category = str(
        finding.get("category", "")
    ).lower()

    text = f"{title} {category}"

    if any(
        word in text
        for word in (
            "header",
            "cabeçalho",
            "política",
            "policy",
            "cookie",
            "configuração",
            "configuration",
            "hardening",
            "security header",
        )
    ):
        return "CONFIGURATION"

    if any(
        word in text
        for word in (
            "endpoint",
            "reconnaissance",
            "reconhecimento",
            "parameter",
            "parâmetro",
            "url descoberta",
        )
    ):
        return "RECONNAISSANCE"

    if str(
        finding.get("severity", "INFO")
    ).upper() == "INFO":
        return "INFORMATION"

    return "VULNERABILITY"


def normalize_status(finding, finding_type):
    """
    Preserva o status informado pelo módulo.

    IMPORTANTE:
    O correlator NÃO pode transformar OBSERVATION em CONFIRMED.
    """

    original = str(
        finding.get("status", "")
    ).upper().strip()

    if original in VALID_STATUSES:
        return original

    # Se o módulo não informou status, inferimos de forma conservadora.
    if finding_type in {
        "INFORMATION",
        "RECONNAISSANCE",
    }:
        return "OBSERVATION"

    if finding_type in {
        "CONFIGURATION",
        "HARDENING",
        "VULNERABILITY",
    }:
        return "INDICATION"

    return "OBSERVATION"


def normalize_confidence(finding):
    confidence = str(
        finding.get("confidence", "MEDIUM")
    ).upper().strip()

    if confidence not in {
        "HIGH",
        "MEDIUM",
        "LOW",
    }:
        confidence = "MEDIUM"

    return confidence


def normalize_finding(finding, source):
    title = str(
        finding.get(
            "title",
            "Achado sem título",
        )
    )

    severity = str(
        finding.get(
            "severity",
            "INFO",
        )
    ).upper().strip()

    if severity not in SEVERITY_ORDER:
        severity = "INFO"

    evidence = str(
        finding.get(
            "evidence",
            "",
        )
    )

    finding_type = infer_finding_type(finding)

    status = normalize_status(
        finding,
        finding_type,
    )

    confidence = normalize_confidence(
        finding
    )

    if finding_type in {
        "CONFIGURATION",
        "HARDENING",
    }:
        description = (
            "Foi identificada uma configuração ou "
            "controle de segurança que pode ser "
            "melhorado."
        )

        impact = (
            "A ausência ou configuração inadequada "
            "pode reduzir determinadas camadas de "
            "proteção da aplicação."
        )

        consequence = (
            "Dependendo do contexto da aplicação, "
            "a proteção disponível contra determinados "
            "cenários de ataque pode ser reduzida."
        )

        default_recommendation = (
            "Revisar a configuração identificada e "
            "aplicar o controle de segurança adequado."
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
            "Se a condição for explorável no contexto "
            "real da aplicação, poderá afetar a "
            "confidencialidade, integridade ou disponibilidade."
        )

        default_recommendation = (
            "Validar manualmente a condição e, caso "
            "confirmada, aplicar a correção correspondente."
        )

    elif finding_type == "RECONNAISSANCE":
        description = (
            "Foram identificadas informações relacionadas "
            "à superfície de ataque do alvo."
        )

        impact = (
            "Essas informações podem auxiliar a compreensão "
            "dos endpoints e recursos expostos."
        )

        consequence = (
            "A descoberta isoladamente não significa "
            "que exista uma vulnerabilidade."
        )

        default_recommendation = (
            "Revisar os endpoints identificados e confirmar "
            "se a exposição é esperada."
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

        default_recommendation = (
            "Avaliar a informação no contexto da aplicação "
            "e verificar se a exposição é esperada."
        )

    return {
        "id": finding.get(
            "id",
            make_id(title),
        ),
        "title": title,
        "severity": severity,
        "type": finding.get(
            "type",
            finding_type,
        ),
        "status": status,
        "confidence": confidence,
        "category": finding.get(
            "category",
            source.upper(),
        ),
        "source": source,
        "cve": finding.get("cve"),
        "cwe": finding.get("cwe"),
        "evidence": evidence,
        "description": finding.get(
            "description",
            description,
        ),
        "impact": finding.get(
            "impact",
            impact,
        ),
        "consequence": finding.get(
            "consequence",
            consequence,
        ),
        "recommendation": finding.get(
            "recommendation",
            default_recommendation,
        ),
        "validation": finding.get(
            "validation",
            "Executar novamente o BlueScan após "
            "a correção e verificar se a condição "
            "continua presente.",
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
            [],
        )

        if not isinstance(raw_findings, list):
            continue

        for finding in raw_findings:
            if not isinstance(finding, dict):
                continue

            findings.append(
                normalize_finding(
                    finding,
                    source,
                )
            )

    # Remove apenas duplicatas realmente iguais.
    unique = {}

    for finding in findings:
        key = (
            finding["title"],
            finding["source"],
            finding["evidence"],
        )

        if key not in unique:
            unique[key] = finding

    findings = list(
        unique.values()
    )

    findings.sort(
        key=lambda item: (
            SEVERITY_ORDER.get(
                item["severity"],
                0,
            ),
            item["status"],
        ),
        reverse=True,
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
        "RECONNAISSANCE": 0,
    }

    statuses = {
        "CONFIRMED": 0,
        "INDICATION": 0,
        "OBSERVATION": 0,
    }

    for finding in findings:
        severity = finding.get(
            "severity",
            "INFO",
        )

        if severity in counts:
            counts[severity] += 1

        finding_type = finding.get(
            "type",
            "INFORMATION",
        )

        if finding_type in types:
            types[finding_type] += 1

        status = finding.get(
            "status",
            "OBSERVATION",
        )

        if status in statuses:
            statuses[status] += 1

    highest_severity = "INFO"

    for severity in (
        "CRITICAL",
        "HIGH",
        "MEDIUM",
        "LOW",
        "INFO",
    ):
        if counts[severity] > 0:
            highest_severity = severity
            break

    # O risco é baseado na severidade encontrada,
    # mas não transforma uma observação em confirmação.
    if highest_severity == "CRITICAL":
        risk = "CRÍTICO"
    elif highest_severity == "HIGH":
        risk = "ALTO"
    elif highest_severity == "MEDIUM":
        risk = "MÉDIO"
    elif highest_severity == "LOW":
        risk = "BAIXO"
    else:
        risk = "INFORMATIVO"

    summary = {
        "total_findings": len(findings),

        "confirmed": statuses["CONFIRMED"],
        "indications": statuses["INDICATION"],
        "observations": statuses["OBSERVATION"],

        "severity": counts,

        "types": types,

        "vulnerabilities": types["VULNERABILITY"],
        "configuration": types["CONFIGURATION"],
        "hardening": types["HARDENING"],
        "information": types["INFORMATION"],
        "reconnaissance": types["RECONNAISSANCE"],

        "status": statuses,

        "highest_severity": highest_severity,
        "risk": risk,
    }

    return {
        "status": "completed",
        "findings": findings,
        "summary": summary,
    }


if __name__ == "__main__":
    print(
        "OK - correlator carregado."
    )
PY

echo
echo "===== VALIDANDO SINTAXE ====="
python3 -m py_compile correlator.py

echo
echo "===== VALIDANDO IMPORT ====="
python3 - <<'PY'
import correlator

print("OK - correlator importado")
print("OK - correlate disponível:", callable(correlator.correlate))
PY