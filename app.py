import streamlit as st

from scanner import scan_target
from target_policy import validate_target


st.set_page_config(
    page_title="BlueScan",
    page_icon="🔵",
    layout="wide",
)


# ============================================================
# CABEÇALHO
# ============================================================

st.title("🔵 BlueScan")

st.markdown(
    """
    **Scanner de segurança para alvos próprios ou explicitamente autorizados.**

    Use somente sistemas próprios ou sistemas para os quais você
    tenha autorização explícita para realizar testes.
    """
)

st.divider()


# ============================================================
# ALVO
# ============================================================

st.subheader("🎯 Alvo autorizado")

target = st.text_input(
    "Informe a URL do alvo",
    placeholder="https://exemplo.com",
)

st.caption(
    "Exemplo: https://kalitermu.github.io/jlsites/"
)


# ============================================================
# BOTÃO
# ============================================================

if st.button(
    "🔍 Iniciar análise de segurança",
    type="primary",
    use_container_width=True,
):

    # --------------------------------------------------------
    # VALIDAÇÃO
    # --------------------------------------------------------

    if not target.strip():
        st.warning("Informe uma URL para iniciar a análise.")
        st.stop()

    target = target.strip()

    try:
        accepted, message = validate_target(target)

    except Exception as error:
        st.error(
            f"Erro ao validar o alvo: {error}"
        )
        st.stop()

    if not accepted:
        st.error(
            f"❌ {message}"
        )
        st.stop()

    st.success(
        f"✅ {message}"
    )

    st.divider()

    # --------------------------------------------------------
    # EXECUÇÃO
    # --------------------------------------------------------

    st.info(
        "🔵 BlueScan iniciando os módulos de segurança..."
    )

    status = st.empty()
    progress = st.progress(0)

    status.markdown(
        "🌐 **Executando análise HTTP...**"
    )

    progress.progress(20)

    try:

        result = scan_target(target)

    except Exception as error:

        progress.empty()
        status.empty()

        st.error(
            f"❌ Erro durante a análise: {error}"
        )

        st.exception(error)

        st.stop()

    progress.progress(100)

    status.success(
        "✅ Análise concluída."
    )

    st.divider()

    # ========================================================
    # RESULTADO
    # ========================================================

    st.header("📊 Resultado da análise")

    if result is None:

        st.warning(
            "O scanner não retornou resultados."
        )

        st.stop()


    # ========================================================
    # RESULTADO EM DICIONÁRIO
    # ========================================================

    if isinstance(result, dict):

        findings = result.get(
            "findings",
            []
        )

        if not isinstance(findings, list):
            findings = []


        # ----------------------------------------------------
        # CONTADORES
        # ----------------------------------------------------

        critical = 0
        high = 0
        medium = 0
        low = 0
        info = 0

        for finding in findings:

            if not isinstance(finding, dict):
                continue

            severity = str(
                finding.get(
                    "severity",
                    finding.get(
                        "risk",
                        "info"
                    )
                )
            ).lower()

            if severity == "critical":
                critical += 1

            elif severity == "high":
                high += 1

            elif severity == "medium":
                medium += 1

            elif severity == "low":
                low += 1

            else:
                info += 1


        # ----------------------------------------------------
        # MÉTRICAS
        # ----------------------------------------------------

        col1, col2, col3, col4, col5 = st.columns(5)

        col1.metric(
            "Total",
            len(findings)
        )

        col2.metric(
            "Crítico",
            critical
        )

        col3.metric(
            "Alto",
            high
        )

        col4.metric(
            "Médio",
            medium
        )

        col5.metric(
            "Baixo",
            low
        )


        # ----------------------------------------------------
        # INFORMAÇÕES DA ANÁLISE
        # ----------------------------------------------------

        result_target = result.get(
            "target",
            target
        )

        st.write(
            f"🎯 **Alvo analisado:** `{result_target}`"
        )


        duration = result.get(
            "duration_seconds"
        )

        if duration is not None:

            st.write(
                f"⏱️ **Duração:** {duration} segundos"
            )


        # ====================================================
        # ACHADOS
        # ====================================================

        if findings:

            st.subheader(
                "🔎 Achados de segurança"
            )

            for number, finding in enumerate(
                findings,
                start=1
            ):

                if not isinstance(finding, dict):
                    continue

                title = finding.get(
                    "title",
                    finding.get(
                        "name",
                        f"Achado {number}"
                    )
                )

                severity = finding.get(
                    "severity",
                    finding.get(
                        "risk",
                        "INFO"
                    )
                )

                category = finding.get(
                    "category",
                    "Segurança"
                )

                source = finding.get(
                    "source",
                    "BlueScan"
                )

                evidence = finding.get(
                    "evidence",
                    ""
                )

                impact = finding.get(
                    "impact",
                    finding.get(
                        "consequence",
                        ""
                    )
                )

                recommendation = finding.get(
                    "recommendation",
                    ""
                )


                with st.expander(
                    f"{str(severity).upper()} — {title}"
                ):

                    st.write(
                        f"**Categoria:** {category}"
                    )

                    st.write(
                        f"**Fonte:** {source}"
                    )

                    if evidence:

                        st.write(
                            "**Evidência:**"
                        )

                        st.code(
                            str(evidence)
                        )


                    if impact:

                        st.write(
                            "**Impacto / consequência:**"
                        )

                        st.write(
                            str(impact)
                        )


                    if recommendation:

                        st.write(
                            "**Recomendação:**"
                        )

                        st.write(
                            str(recommendation)
                        )

        else:

            st.success(
                "✅ Nenhum achado de segurança foi registrado."
            )


        # ====================================================
        # DADOS TÉCNICOS
        # ====================================================

        with st.expander(
            "🧾 Resultado técnico completo"
        ):

            st.json(result)


    # ========================================================
    # RESULTADO NÃO-DICT
    # ========================================================

    else:

        st.subheader(
            "🧾 Resultado"
        )

        st.write(result)


# ============================================================
# RODAPÉ
# ============================================================

st.divider()

st.caption(
    "BlueScan — análise defensiva para sistemas próprios "
    "ou explicitamente autorizados."
)