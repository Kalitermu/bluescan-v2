import json
from datetime import datetime, timezone

import streamlit as st

import scanner
import target_policy


# ============================================================
# CONFIGURAÇÃO
# ============================================================

st.set_page_config(
    page_title="BlueScan",
    page_icon="🛡️",
    layout="wide",
)


# ============================================================
# FUNÇÕES AUXILIARES
# ============================================================

def safe_text(value, default=""):
    if value is None:
        return default

    if isinstance(value, (dict, list)):
        return str(value)

    return str(value)


def normalize_severity(value):
    """
    Normaliza severidades vindas do scanner.
    """
    if value is None:
        return "info"

    severity = str(value).strip().lower()

    aliases = {
        "critical": "critical",
        "crit": "critical",

        "high": "high",

        "medium": "medium",
        "moderate": "medium",

        "low": "low",

        "info": "info",
        "informational": "info",
        "information": "info",
    }

    return aliases.get(severity, "info")


def get_findings(result):
    """
    Retorna somente findings em formato de lista.
    """
    if not isinstance(result, dict):
        return []

    findings = result.get("findings", [])

    if not isinstance(findings, list):
        return []

    valid = []

    for finding in findings:
        if isinstance(finding, dict):
            valid.append(finding)

    return valid


def calculate_severity_distribution(findings):
    """
    Calcula a distribuição real dos findings.
    """
    distribution = {
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

        if severity in distribution:
            distribution[severity] += 1

    return distribution


def calculate_summary(findings):
    """
    Calcula o resumo a partir dos findings reais.

    Confirmadas:
        Findings explicitamente confirmados.

    Para revisão:
        Findings que precisam de validação.

    Informativas:
        Findings INFO e findings sem indicação
        de confirmação/revisão.

    Erros do scanner:
        Findings marcados como erro ou categoria de erro.
    """

    confirmed = 0
    review = 0
    informational = 0
    errors = 0

    for finding in findings:

        severity = normalize_severity(
            finding.get("severity")
        )

        status = str(
            finding.get("status", "")
        ).strip().lower()

        category = str(
            finding.get("category", "")
        ).strip().lower()

        title = str(
            finding.get("title", "")
        ).strip().lower()

        # --------------------------------------------
        # Erros do scanner
        # --------------------------------------------

        if (
            status in {
                "error",
                "failed",
                "failure",
            }
            or "scanner error" in category
            or "erro do scanner" in category
            or "scanner error" in title
            or "erro do scanner" in title
        ):
            errors += 1
            continue

        # --------------------------------------------
        # Confirmadas
        # --------------------------------------------

        if status in {
            "confirmed",
            "confirmado",
            "confirmed_finding",
        }:
            confirmed += 1
            continue

        # --------------------------------------------
        # Para revisão
        # --------------------------------------------

        if status in {
            "review",
            "revisar",
            "review_required",
            "needs_review",
            "to_review",
        }:
            review += 1
            continue

        # --------------------------------------------
        # Informativas
        # --------------------------------------------

        if severity == "info":
            informational += 1
            continue

        # --------------------------------------------
        # Findings de segurança sem status explícito
        #
        # Mantemos LOW/MEDIUM/HIGH/CRITICAL como
        # findings ainda não classificados, em vez
        # de inventar que estão confirmados.
        # --------------------------------------------

        review += 1

    return {
        "confirmed": confirmed,
        "review": review,
        "informational": informational,
        "errors": errors,
    }


def calculate_observed_severity(findings):
    """
    Retorna a maior severidade observada.
    """
    if not findings:
        return "NONE"

    levels = {
        "info": 1,
        "low": 2,
        "medium": 3,
        "high": 4,
        "critical": 5,
    }

    reverse = {
        1: "INFO",
        2: "LOW",
        3: "MEDIUM",
        4: "HIGH",
        5: "CRITICAL",
    }

    highest = 0

    for finding in findings:
        severity = normalize_severity(
            finding.get("severity")
        )

        highest = max(
            highest,
            levels.get(severity, 1),
        )

    return reverse.get(highest, "NONE")


def get_module_status(result):
    """
    Tenta encontrar os status dos módulos em diferentes
    formatos possíveis usados pelo scanner.
    """

    if not isinstance(result, dict):
        return {}

    possible_keys = [
        "module_status",
        "module_statuses",
        "modules_status",
        "modules",
        "status",
    ]

    for key in possible_keys:

        value = result.get(key)

        if isinstance(value, dict):
            return value

    return {}


def format_duration(value):
    if value is None:
        return "N/A"

    try:
        return f"{float(value):.2f} segundos"
    except Exception:
        return safe_text(value, "N/A")


def format_datetime(value):
    if not value:
        return "N/A"

    return safe_text(value)


# ============================================================
# CABEÇALHO
# ============================================================

st.title("🛡️ BlueScan")

st.markdown(
    "**Scanner de segurança para alvos próprios "
    "ou explicitamente autorizados.**"
)

st.caption(
    "Use somente sistemas que você possui ou para os quais "
    "possui autorização explícita para realizar testes."
)


# ============================================================
# STATUS DOS MÓDULOS
# ============================================================

st.subheader("⚙️ Status dos módulos")

scanner_loaded = False
target_policy_loaded = False

try:
    scanner_loaded = callable(
        getattr(scanner, "scan_target", None)
    )
except Exception:
    scanner_loaded = False

try:
    target_policy_loaded = target_policy is not None
except Exception:
    target_policy_loaded = False


if scanner_loaded:
    st.success("Scanner carregado corretamente.")
else:
    st.error("Scanner não carregado corretamente.")

if target_policy_loaded:
    st.success("target_policy carregado corretamente.")
else:
    st.error("target_policy não carregado corretamente.")


# ============================================================
# ALVO
# ============================================================

st.subheader("🎯 Alvo")

target = st.text_input(
    "URL do alvo",
    placeholder="https://exemplo.com",
)


# ============================================================
# EXECUÇÃO
# ============================================================

scan_clicked = st.button(
    "🔎 Executar análise",
    type="primary",
    use_container_width=True,
)


if scan_clicked:

    if not target.strip():
        st.warning("Informe uma URL para iniciar a análise.")
        st.stop()

    target = target.strip()

    # --------------------------------------------------------
    # Validação
    # --------------------------------------------------------

    try:
        policy_result = None

        if hasattr(target_policy, "validate_target"):
            policy_result = target_policy.validate_target(
                target
            )

        elif hasattr(target_policy, "is_allowed"):
            policy_result = target_policy.is_allowed(
                target
            )

        elif hasattr(target_policy, "check_target"):
            policy_result = target_policy.check_target(
                target
            )

        # Se a função existir e retornar False,
        # bloquear o alvo.
        if policy_result is False:
            st.error(
                "O alvo foi rejeitado pela política de autorização."
            )
            st.stop()

        # Alguns módulos retornam dict.
        if isinstance(policy_result, dict):

            allowed = policy_result.get(
                "allowed",
                policy_result.get(
                    "valid",
                    True,
                ),
            )

            if allowed is False:
                reason = policy_result.get(
                    "reason",
                    "Alvo não autorizado pela política.",
                )

                st.error(
                    f"Alvo rejeitado: {reason}"
                )
                st.stop()

    except Exception as exc:

        st.error(
            f"Erro ao validar o alvo: {exc}"
        )

        st.stop()

    # --------------------------------------------------------
    # Execução do scanner
    # --------------------------------------------------------

    st.info(
        "BlueScan executando a análise defensiva..."
    )

    started_ui = datetime.now(timezone.utc)

    try:

        result = scanner.scan_target(target)

    except Exception as exc:

        finished_ui = datetime.now(timezone.utc)

        result = {
            "target": target,
            "final_url": target,
            "status_code": None,
            "started_at": started_ui.isoformat(),
            "finished_at": finished_ui.isoformat(),
            "duration_seconds": (
                finished_ui - started_ui
            ).total_seconds(),
            "findings": [
                {
                    "title": "Erro durante a execução do scanner",
                    "severity": "high",
                    "category": "Scanner Error",
                    "source": "BlueScan",
                    "evidence": str(exc),
                    "impact": (
                        "A análise não pôde ser concluída "
                        "normalmente."
                    ),
                    "recommendation": (
                        "Verificar os logs e a implementação "
                        "do módulo responsável."
                    ),
                    "status": "error",
                }
            ],
        }

    st.success("Análise concluída.")


    # ========================================================
    # NORMALIZAÇÃO DO RESULTADO
    # ========================================================

    if not isinstance(result, dict):

        result = {
            "target": target,
            "final_url": target,
            "status_code": None,
            "findings": [],
            "scanner_error": (
                "O scanner retornou um formato inválido."
            ),
        }

    findings = get_findings(result)

    distribution = calculate_severity_distribution(
        findings
    )

    summary = calculate_summary(
        findings
    )

    observed_severity = calculate_observed_severity(
        findings
    )


    # ========================================================
    # RESUMO
    # ========================================================

    st.divider()

    st.subheader("📊 Resumo da análise")

    summary_cols = st.columns(4)

    summary_cols[0].metric(
        "Confirmadas",
        summary["confirmed"],
    )

    summary_cols[1].metric(
        "Para revisão",
        summary["review"],
    )

    summary_cols[2].metric(
        "Informativas",
        summary["informational"],
    )

    summary_cols[3].metric(
        "Erros do scanner",
        summary["errors"],
    )

    st.markdown(
        f"**Severidade observada:** "
        f"`{observed_severity}`"
    )


    # ========================================================
    # DISTRIBUIÇÃO
    # ========================================================

    st.subheader("📊 Distribuição por severidade")

    distribution_cols = st.columns(6)

    distribution_cols[0].metric(
        "Total",
        len(findings),
    )

    distribution_cols[1].metric(
        "Critical",
        distribution["critical"],
    )

    distribution_cols[2].metric(
        "High",
        distribution["high"],
    )

    distribution_cols[3].metric(
        "Medium",
        distribution["medium"],
    )

    distribution_cols[4].metric(
        "Low",
        distribution["low"],
    )

    distribution_cols[5].metric(
        "Info",
        distribution["info"],
    )


    # ========================================================
    # STATUS DOS MÓDULOS
    # ========================================================

    st.subheader("🧩 Status dos módulos")

    module_status = get_module_status(
        result
    )

    if module_status:

        module_cols = st.columns(
            min(
                len(module_status),
                4,
            )
        )

        for index, (name, status) in enumerate(
            module_status.items()
        ):

            col = module_cols[
                index % len(module_cols)
            ]

            if isinstance(status, dict):

                module_value = status.get(
                    "status",
                    status.get(
                        "state",
                        status.get(
                            "available",
                            "available",
                        ),
                    ),
                )

            else:

                module_value = status

            col.metric(
                str(name),
                str(module_value),
            )

    else:

        # Tenta montar um status mínimo a partir dos
        # componentes efetivamente encontrados no resultado.

        inferred_modules = {}

        technical = result.get(
            "technical",
            {},
        )

        if isinstance(technical, dict):

            if "dns" in technical:
                inferred_modules["DNS"] = (
                    "disponível"
                    if technical.get("dns")
                    else "sem dados"
                )

            if "tls" in technical:
                inferred_modules["TLS"] = (
                    "disponível"
                    if technical.get("tls")
                    else "sem dados"
                )

            if "technologies" in technical:
                inferred_modules["Tecnologias"] = (
                    "disponível"
                    if technical.get("technologies")
                    else "sem dados"
                )

        if findings:
            inferred_modules["HTTP"] = "executado"

        if inferred_modules:

            module_cols = st.columns(
                min(
                    len(inferred_modules),
                    4,
                )
            )

            for index, (
                name,
                status,
            ) in enumerate(
                inferred_modules.items()
            ):

                module_cols[
                    index % len(module_cols)
                ].metric(
                    name,
                    status,
                )

        else:

            st.info(
                "Nenhum status de módulo disponível."
            )


    # ========================================================
    # ALVO ANALISADO
    # ========================================================

    st.divider()

    st.subheader("🎯 Alvo analisado")

    analyzed_target = result.get(
        "target",
        target,
    )

    final_url = result.get(
        "final_url",
        analyzed_target,
    )

    status_code = result.get(
        "status_code",
        result.get(
            "http_status",
            "N/A",
        ),
    )

    duration = result.get(
        "duration_seconds",
        None,
    )

    st.markdown(
        f"**URL:** `{analyzed_target}`"
    )

    st.markdown(
        f"**URL final:** `{final_url}`"
    )

    st.markdown(
        f"**HTTP:** `{status_code}`"
    )

    st.markdown(
        f"**Duração:** `{format_duration(duration)}`"
    )


    # ========================================================
    # ACHADOS CONSOLIDADOS
    # ========================================================

    st.subheader("🔎 Achados consolidados")

    if not findings:

        st.success(
            "Nenhum achado foi identificado."
        )

    else:

        for index, finding in enumerate(
            findings,
            start=1,
        ):

            title = safe_text(
                finding.get(
                    "title",
                    "Achado sem título",
                ),
                "Achado sem título",
            )

            severity = normalize_severity(
                finding.get(
                    "severity",
                    "info",
                )
            ).upper()

            category = safe_text(
                finding.get(
                    "category",
                    "N/A",
                ),
                "N/A",
            )

            source = safe_text(
                finding.get(
                    "source",
                    "BlueScan",
                ),
                "BlueScan",
            )

            evidence = safe_text(
                finding.get(
                    "evidence",
                    "Nenhuma evidência fornecida.",
                ),
                "Nenhuma evidência fornecida.",
            )

            impact = safe_text(
                finding.get(
                    "impact",
                    "N/A",
                ),
                "N/A",
            )

            recommendation = safe_text(
                finding.get(
                    "recommendation",
                    "N/A",
                ),
                "N/A",
            )

            st.markdown(
                f"### {index}. [{severity}] {title}"
            )

            st.markdown(
                f"**Severidade:** `{severity}`"
            )

            st.markdown(
                f"**Categoria:** `{category}`"
            )

            st.markdown(
                f"**Fonte:** `{source}`"
            )

            st.markdown("**Evidência**")

            st.code(
                evidence,
                language="text",
            )

            st.markdown(
                f"**Impacto:** {impact}"
            )

            st.markdown(
                f"**Recomendação:** {recommendation}"
            )

            st.divider()


    # ========================================================
    # DADOS TÉCNICOS
    # ========================================================

    st.subheader("🛠️ Dados técnicos")

    technical = result.get(
        "technical",
        {},
    )

    if isinstance(technical, dict):

        dns = technical.get(
            "dns"
        )

        technologies = technical.get(
            "technologies"
        )

        tls = technical.get(
            "tls"
        )

        with st.expander("🌐 DNS"):

            if dns:

                st.json(dns)

            else:

                st.info(
                    "Nenhuma informação DNS disponível."
                )

        with st.expander("🧬 Tecnologias"):

            if technologies:

                st.json(technologies)

            else:

                st.info(
                    "Nenhuma tecnologia identificada."
                )

        with st.expander("🔐 TLS"):

            if tls:

                st.json(tls)

            else:

                st.info(
                    "Nenhuma informação TLS disponível."
                )

    else:

        st.info(
            "Nenhum dado técnico disponível."
        )


    # ========================================================
    # RESULTADO COMPLETO
    # ========================================================

    with st.expander(
        "📄 Resultado técnico completo"
    ):

        st.json(result)


# ============================================================
# RODAPÉ
# ============================================================

st.divider()

st.caption(
    "BlueScan • análise defensiva • uso autorizado"
)