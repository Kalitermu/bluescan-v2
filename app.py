import streamlit as st

from scanner import scan_target
from target_policy import validate_target


st.set_page_config(
    page_title="BlueScan",
    page_icon="🔵",
    layout="wide",
)


st.title("🛡️ BlueScan")

st.markdown(
    """
**Scanner de segurança para alvos próprios ou explicitamente autorizados.**

Use somente sistemas que você possui ou para os quais possui
autorização explícita para realizar testes.
"""
)


# ============================================================
# STATUS
# ============================================================

st.subheader("⚙️ Status dos módulos")

try:
    from scanner import scan_target as _scanner_check

    if callable(_scanner_check):
        st.success("Scanner carregado corretamente.")
    else:
        st.error("Falha ao carregar o scanner.")

except Exception as exc:
    st.error("Falha ao carregar o scanner.")
    st.code(repr(exc))


try:
    from target_policy import validate_target as _policy_check

    if callable(_policy_check):
        st.success("target_policy carregado corretamente.")
    else:
        st.error("Falha ao carregar target_policy.")

except Exception as exc:
    st.error("Falha ao carregar target_policy.")
    st.code(repr(exc))


st.divider()


# ============================================================
# ALVO
# ============================================================

st.subheader("🎯 Alvo")

target = st.text_input(
    "URL do alvo",
    placeholder="https://example.com",
    help="Somente sistemas próprios ou explicitamente autorizados.",
)


# ============================================================
# EXECUÇÃO
# ============================================================

if st.button("🔎 Executar análise", type="primary"):

    if not target.strip():
        st.warning("Informe uma URL antes de executar a análise.")
        st.stop()

    valid, message = validate_target(target)

    if not valid:
        st.error(message)
        st.stop()

    st.info("BlueScan executando a análise defensiva...")

    try:
        result = scan_target(target)

        if not isinstance(result, dict):
            st.error("O scanner retornou um resultado inválido.")
            st.write(result)
            st.stop()

        st.success("Análise concluída.")

        # ====================================================
        # DADOS PRINCIPAIS
        # ====================================================

        st.subheader("📊 Resumo da análise")

        summary = result.get("summary", {})

        if not isinstance(summary, dict):
            summary = {}

        counts = summary.get("counts", {})

        if not isinstance(counts, dict):
            counts = {}

        total = summary.get(
            "total",
            len(result.get("findings", [])),
        )

        critical = counts.get("CRITICAL", 0)
        high = counts.get("HIGH", 0)
        medium = counts.get("MEDIUM", 0)
        low = counts.get("LOW", 0)
        info = counts.get("INFO", 0)

        confirmed = summary.get("confirmed", [])
        review = summary.get("review", [])
        informational = summary.get("informational", [])
        scanner_errors = summary.get("scanner_errors", [])

        if not isinstance(confirmed, list):
            confirmed = []

        if not isinstance(review, list):
            review = []

        if not isinstance(informational, list):
            informational = []

        if not isinstance(scanner_errors, list):
            scanner_errors = []

        confirmed_count = len(confirmed)
        review_count = len(review)
        informational_count = len(informational)
        scanner_error_count = len(scanner_errors)

        observed_severity = summary.get(
            "observed_severity",
            summary.get("severity", "NONE"),
        )

        message = summary.get("message", "")

        # ====================================================
        # CLASSIFICAÇÃO DOS ACHADOS
        # ====================================================

        st.markdown("### 🧭 Classificação dos achados")

        status_cols = st.columns(4)

        status_cols[0].metric(
            "Confirmadas",
            confirmed_count,
        )

        status_cols[1].metric(
            "Para revisão",
            review_count,
        )

        status_cols[2].metric(
            "Informativas",
            informational_count,
        )

        status_cols[3].metric(
            "Erros do scanner",
            scanner_error_count,
        )

        if message:
            st.info(str(message))

        st.caption(
            f"Severidade observada: **{observed_severity}**"
        )

        # ====================================================
        # DISTRIBUIÇÃO POR SEVERIDADE
        # ====================================================

        st.markdown("### 📊 Distribuição por severidade")

        severity_cols = st.columns(6)

        severity_cols[0].metric("Total", total)
        severity_cols[1].metric("Critical", critical)
        severity_cols[2].metric("High", high)
        severity_cols[3].metric("Medium", medium)
        severity_cols[4].metric("Low", low)
        severity_cols[5].metric("Info", info)

        st.divider()


        # ====================================================
        # STATUS DOS MÓDULOS
        # ====================================================

        st.subheader("🧩 Status dos módulos")

        modules = result.get("modules", {})

        if isinstance(modules, dict) and modules:

            module_cols = st.columns(
                min(len(modules), 4)
            )

            for index, (name, status) in enumerate(
                modules.items()
            ):

                col = module_cols[
                    index % len(module_cols)
                ]

                if isinstance(status, dict):

                    module_status = status.get(
                        "status",
                        status.get(
                            "state",
                            "available",
                        ),
                    )

                    col.metric(
                        str(name),
                        str(module_status),
                    )

                else:

                    col.metric(
                        str(name),
                        str(status),
                    )

        else:
            st.info("Nenhum status de módulo disponível.")


        st.divider()


        # ====================================================
        # ALVO ANALISADO
        # ====================================================

        st.subheader("🎯 Alvo analisado")

        st.markdown(
            f"**URL:** {result.get('target', target)}"
        )

        st.markdown(
            f"**URL final:** "
            f"{result.get('final_url', 'N/A')}"
        )

        st.markdown(
            f"**HTTP:** "
            f"{result.get('status_code', 'N/A')}"
        )

        st.markdown(
            f"**Duração:** "
            f"{result.get('duration_seconds', 'N/A')} segundos"
        )


        st.divider()


        # ====================================================
        # ACHADOS
        # ====================================================

        st.subheader("🔎 Achados consolidados")

        findings = result.get("findings", [])

        if isinstance(findings, list) and findings:

            for index, finding in enumerate(
                findings,
                start=1,
            ):

                if not isinstance(finding, dict):
                    st.write(f"{index}. {finding}")
                    continue

                title = finding.get(
                    "title",
                    f"Achado {index}",
                )

                severity = str(
                    finding.get(
                        "severity",
                        "INFO",
                    )
                ).upper()

                category = finding.get(
                    "category",
                    "N/A",
                )

                source = finding.get(
                    "source",
                    "N/A",
                )

                evidence = finding.get(
                    "evidence",
                    "",
                )

                impact = finding.get(
                    "impact",
                    "",
                )

                consequence = finding.get(
                    "consequence",
                    "",
                )

                recommendation = finding.get(
                    "recommendation",
                    "",
                )

                with st.expander(
                    f"{index}. [{severity}] {title}"
                ):

                    st.markdown(
                        f"**Severidade:** {severity}"
                    )

                    st.markdown(
                        f"**Categoria:** {category}"
                    )

                    st.markdown(
                        f"**Fonte:** {source}"
                    )

                    if evidence:
                        st.markdown("**Evidência**")
                        st.code(
                            str(evidence),
                            language="text",
                        )

                    if impact:
                        st.markdown(
                            f"**Impacto:** {impact}"
                        )

                    if consequence:
                        st.markdown(
                            f"**Consequência:** "
                            f"{consequence}"
                        )

                    if recommendation:
                        st.markdown(
                            f"**Recomendação:** "
                            f"{recommendation}"
                        )

        else:

            st.info(
                "Nenhum finding foi registrado."
            )


        st.divider()


        # ====================================================
        # DETALHES DO WAPITI
        # ====================================================

        wapiti = modules.get("Wapiti")

        if isinstance(wapiti, dict):

            st.subheader("🛡️ Wapiti")

            wapiti_status = wapiti.get(
                "status",
                "unknown",
            )

            wapiti_coverage = wapiti.get(
                "coverage",
                "unavailable",
            )

            urls_found = wapiti.get(
                "urls_found",
                0,
            )

            forms_found = wapiti.get(
                "forms_found",
                0,
            )

            protocol_error = wapiti.get(
                "protocol_error",
                False,
            )

            wapiti_cols = st.columns(5)

            wapiti_cols[0].metric(
                "Status",
                str(wapiti_status),
            )

            wapiti_cols[1].metric(
                "Cobertura",
                str(wapiti_coverage),
            )

            wapiti_cols[2].metric(
                "URLs/Formulários",
                str(urls_found),
            )

            wapiti_cols[3].metric(
                "Formulários",
                str(forms_found),
            )

            wapiti_cols[4].metric(
                "Erro protocolo",
                "Sim" if protocol_error else "Não",
            )

            if wapiti_coverage == "limited":

                st.warning(
                    "⚠️ A análise do Wapiti teve cobertura limitada "
                    "neste teste. Os resultados não devem ser "
                    "interpretados como uma varredura completa."
                )

            elif wapiti_status == "completed":

                st.success(
                    "✅ Wapiti concluiu a execução com cobertura "
                    "normal."
                )

            elif wapiti_status == "error":

                st.error(
                    "❌ O Wapiti apresentou erro durante a análise."
                )

            report_path = wapiti.get("report_path")

            if report_path:

                st.caption(
                    f"Relatório JSON: `{report_path}`"
                )


        # ====================================================
        # DADOS TÉCNICOS
        # ====================================================

        st.subheader("🛠️ Dados técnicos")

        technical = result.get(
            "technical",
            {},
        )

        if isinstance(technical, dict):

            dns = technical.get("dns")
            technologies = technical.get(
                "technologies"
            )
            tls = technical.get("tls")

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
                "Nenhum dado técnico estruturado disponível."
            )


        # ====================================================
        # RESULTADO COMPLETO
        # ====================================================

        with st.expander(
            "📄 Resultado técnico completo"
        ):
            st.json(result)


    except Exception as exc:

        st.error(
            "Falha durante a execução do scanner."
        )

        st.exception(exc)


st.divider()

st.caption(
    "BlueScan • análise defensiva • uso autorizado"
)
