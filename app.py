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
# CARREGAMENTO DOS MÓDULOS
# ============================================================

scanner_available = False
scanner_error = None
scan_target = None

try:
    from scanner import scan_target

    scanner_available = callable(scan_target)

    if not scanner_available:
        scanner_error = "scanner.scan_target não é uma função válida."

except Exception as error:
    scanner_error = error


policy_available = False
policy_error = None
validate_target = None

try:
    from target_policy import validate_target

    policy_available = callable(validate_target)

    if not policy_available:
        policy_error = "target_policy.validate_target não é uma função válida."

except Exception as error:
    policy_error = error


# ============================================================
# STATUS
# ============================================================

with st.expander("⚙️ Status do BlueScan", expanded=True):

    if scanner_available:
        st.success("✅ Scanner carregado com sucesso.")
    else:
        st.error("❌ Falha ao carregar o scanner.")

        if scanner_error is not None:
            st.code(
                repr(scanner_error),
                language="text",
            )

    if policy_available:
        st.success("✅ Política de alvo carregada.")
    else:
        st.error("❌ Falha ao carregar target_policy.")

        if policy_error is not None:
            st.code(
                repr(policy_error),
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
# BOTÃO
# ============================================================

start_scan = st.button(
    "🔍 Iniciar análise de segurança",
    type="primary",
    use_container_width=True,
)


# ============================================================
# EXECUÇÃO
# ============================================================

if start_scan:

    # --------------------------------------------------------
    # URL
    # --------------------------------------------------------

    target = target.strip()

    if not target:
        st.warning("Informe uma URL para iniciar a análise.")
        st.stop()


    # --------------------------------------------------------
    # SCANNER
    # --------------------------------------------------------

    if not scanner_available:

        st.error(
            "❌ O BlueScan não conseguiu carregar o scanner."
        )

        st.info(
            "O erro exibido em 'Status do BlueScan' identifica "
            "o módulo que precisa ser corrigido."
        )

        st.stop()


    # --------------------------------------------------------
    # POLÍTICA
    # --------------------------------------------------------

    if not policy_available:

        st.error(
            "❌ O módulo de validação de alvo não está disponível."
        )

        st.info(
            "Verifique o erro exibido em 'Status do BlueScan'."
        )

        st.stop()


    # --------------------------------------------------------
    # VALIDAÇÃO
    # --------------------------------------------------------

    try:

        validation = validate_target(target)

        if not isinstance(validation, tuple) or len(validation) != 2:

            st.error(
                "❌ target_policy.validate_target retornou "
                "um formato inesperado."
            )

            st.code(
                repr(validation),
                language="text",
            )

            st.stop()

        accepted, message = validation

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
    # SCAN
    # --------------------------------------------------------

    st.info(
        "🔵 BlueScan iniciando a análise..."
    )

    progress = st.progress(0)

    status = st.empty()

    status.markdown(
        "🔄 **Executando scanner...**"
    )

    progress.progress(10)


    try:

        result = scan_target(target)

        progress.progress(100)

        status.success(
            "✅ Análise concluída."
        )

    except Exception as error:

        progress.empty()
        status.empty()

        st.error(
            "❌ O scanner encontrou um erro."
        )

        st.exception(error)

        st.stop()


    # --------------------------------------------------------
    # RESULTADO
    # --------------------------------------------------------

    if result is None:

        st.warning(
            "O scanner terminou sem retornar resultados."
        )

        st.stop()


    st.divider()

    st.header("📊 Resultado da análise")


    # ========================================================
    # DICIONÁRIO
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


        findings = result.get(
            "findings",
            [],
        )

        if not isinstance(findings, list):
            findings = []


        # ----------------------------------------------------
        # CONTADORES
        # ----------------------------------------------------

        counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }


        for finding in findings:

            if not isinstance(finding, dict):
                continue

            severity = str(
                finding.get(
                    "severity",
                    finding.get(
                        "risk",
                        "info",
                    ),
                )
            ).strip().lower()


            if severity in counts:
                counts[severity] += 1
            else:
                counts["info"] += 1


        # ----------------------------------------------------
        # DASHBOARD
        # ----------------------------------------------------

        columns = st.columns(5)

        columns[0].metric(
            "Total",
            len(findings),
        )

        columns[1].metric(
            "Crítico",
            counts["critical"],
        )

        columns[2].metric(
            "Alto",
            counts["high"],
        )

        columns[3].metric(
            "Médio",
            counts["medium"],
        )

        columns[4].metric(
            "Baixo",
            counts["low"],
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

                if not isinstance(finding, dict):
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
                            str(evidence),
                            language="text",
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