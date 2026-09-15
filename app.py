import streamlit as st


# ============================================================
# CONFIGURAÇÃO
# ============================================================

st.set_page_config(
    page_title="BlueScan",
    page_icon="🔵",
    layout="wide",
)


# ============================================================
# IMPORTAÇÃO DO SCANNER
# ============================================================

scanner_available = True
scanner_error = None
scan_target = None

try:
    from scanner import scan_target
except Exception as error:
    scanner_available = False
    scanner_error = error


# ============================================================
# POLÍTICA DE ALVO
# ============================================================

policy_available = True
policy_error = None
validate_target = None

try:
    from target_policy import validate_target
except Exception as error:
    policy_available = False
    policy_error = error


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
# STATUS DO SISTEMA
# ============================================================

with st.expander("⚙️ Status do BlueScan", expanded=False):

    if scanner_available:
        st.success("✅ Módulo scanner carregado.")
    else:
        st.error("❌ Não foi possível carregar o módulo scanner.")

        st.code(
            str(scanner_error),
            language="text",
        )

    if policy_available:
        st.success("✅ Política de validação carregada.")
    else:
        st.error(
            "❌ Não foi possível carregar target_policy."
        )

        st.code(
            str(policy_error),
            language="text",
        )


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
# BOTÃO DE ANÁLISE
# ============================================================

start_scan = st.button(
    "🔍 Iniciar análise de segurança",
    type="primary",
    use_container_width=True,
)


if start_scan:

    # --------------------------------------------------------
    # VERIFICAÇÃO DA URL
    # --------------------------------------------------------

    if not target.strip():

        st.warning(
            "Informe uma URL para iniciar a análise."
        )

        st.stop()


    target = target.strip()


    # --------------------------------------------------------
    # VERIFICAÇÃO DO MÓDULO
    # --------------------------------------------------------

    if not scanner_available:

        st.error(
            "❌ O BlueScan não conseguiu carregar o scanner."
        )

        st.info(
            "Abra o painel Manage app → Logs para verificar "
            "qual dependência ou módulo do scanner está causando "
            "o problema."
        )

        st.code(
            str(scanner_error),
            language="text",
        )

        st.stop()


    # --------------------------------------------------------
    # VALIDAÇÃO DO ALVO
    # --------------------------------------------------------

    if not policy_available:

        st.error(
            "❌ O módulo target_policy não pôde ser carregado."
        )

        st.code(
            str(policy_error),
            language="text",
        )

        st.stop()


    try:

        accepted, message = validate_target(
            target
        )

    except Exception as error:

        st.error(
            "❌ Erro durante a validação do alvo."
        )

        st.exception(error)

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
    # INÍCIO DA ANÁLISE
    # --------------------------------------------------------

    st.info(
        "🔵 BlueScan iniciando os módulos de segurança..."
    )

    progress = st.progress(0)

    status = st.empty()

    status.markdown(
        "🌐 **Executando análise HTTP...**"
    )

    progress.progress(10)


    # --------------------------------------------------------
    # EXECUÇÃO DO SCANNER
    # --------------------------------------------------------

    try:

        result = scan_target(
            target
        )

        progress.progress(100)

        status.success(
            "✅ Análise concluída."
        )

    except Exception as error:

        progress.empty()
        status.empty()

        st.error(
            "❌ O scanner encontrou um erro durante a execução."
        )

        st.exception(error)

        st.stop()


    # --------------------------------------------------------
    # VERIFICAÇÃO DO RESULTADO
    # --------------------------------------------------------

    if result is None:

        st.warning(
            "O scanner terminou, mas não retornou resultados."
        )

        st.stop()


    # ========================================================
    # RESULTADO
    # ========================================================

    st.divider()

    st.header("📊 Resultado da análise")


    # ========================================================
    # RESULTADO EM DICIONÁRIO
    # ========================================================

    if isinstance(result, dict):

        result_target = result.get(
            "target",
            target,
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


        # ----------------------------------------------------
        # FINDINGS
        # ----------------------------------------------------

        findings = result.get(
            "findings",
            []
        )


        if not isinstance(
            findings,
            list
        ):

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

            if not isinstance(
                finding,
                dict
            ):
                continue


            severity = str(
                finding.get(
                    "severity",
                    finding.get(
                        "risk",
                        "info",
                    ),
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
        # DASHBOARD
        # ----------------------------------------------------

        col1, col2, col3, col4, col5 = st.columns(5)


        col1.metric(
            "Total",
            len(findings),
        )


        col2.metric(
            "Crítico",
            critical,
        )


        col3.metric(
            "Alto",
            high,
        )


        col4.metric(
            "Médio",
            medium,
        )


        col5.metric(
            "Baixo",
            low,
        )


        # ----------------------------------------------------
        # ACHADOS
        # ----------------------------------------------------

        if findings:

            st.subheader(
                "🔎 Achados de segurança"
            )


            for number, finding in enumerate(
                findings,
                start=1,
            ):

                if not isinstance(
                    finding,
                    dict,
                ):
                    continue


                title = finding.get(
                    "title",
                    finding.get(
                        "name",
                        f"Achado {number}",
                    ),
                )


                severity = finding.get(
                    "severity",
                    finding.get(
                        "risk",
                        "INFO",
                    ),
                )


                category = finding.get(
                    "category",
                    "Segurança",
                )


                source = finding.get(
                    "source",
                    "BlueScan",
                )


                evidence = finding.get(
                    "evidence",
                    "",
                )


                impact = finding.get(
                    "impact",
                    finding.get(
                        "consequence",
                        "",
                    ),
                )


                recommendation = finding.get(
                    "recommendation",
                    "",
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


        # ----------------------------------------------------
        # RESULTADO TÉCNICO
        # ----------------------------------------------------

        with st.expander(
            "🧾 Resultado técnico completo"
        ):

            st.json(
                result
            )


    # ========================================================
    # RESULTADO QUE NÃO É DICT
    # ========================================================

    else:

        st.subheader(
            "🧾 Resultado"
        )

        st.write(
            result
        )


# ============================================================
# RODAPÉ
# ============================================================

st.divider()

st.caption(
    "BlueScan — análise defensiva para sistemas próprios "
    "ou explicitamente autorizados."
)