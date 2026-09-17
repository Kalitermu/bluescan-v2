cd ~/bluescan-v2
source .venv/bin/activate

cat > app.py <<'PY'
import streamlit as st

from scanner import scan_target
from target_policy import validate_target


st.set_page_config(
    page_title="BlueScan",
    page_icon="🔵",
    layout="wide",
)


st.title("🔵 BlueScan")

st.markdown(
    """
**Scanner de segurança para alvos próprios ou explicitamente autorizados.**

Use somente sistemas próprios ou sistemas para os quais você tenha
autorização explícita para realizar testes.
"""
)


# ============================================================
# STATUS
# ============================================================

st.subheader("⚙️ Status do BlueScan")

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

st.subheader("🎯 Alvo autorizado")

st.caption(
    "Use somente sistemas próprios ou sistemas para os quais "
    "você tenha autorização explícita para realizar testes."
)

target = st.text_input(
    "Informe a URL do alvo",
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

        st.success("Análise concluída.")

        st.subheader("📊 Resultado")

        if isinstance(result, dict):

            # =================================================
            # INFORMAÇÕES DA ANÁLISE
            # =================================================

            col1, col2, col3 = st.columns(3)

            col1.metric(
                "Status HTTP",
                result.get("status_code", "N/A"),
            )

            col2.metric(
                "Duração",
                f"{result.get('duration_seconds', 0)} s",
            )

            col3.metric(
                "Findings",
                result.get("summary", {}).get("total", 0),
            )

            st.divider()

            # =================================================
            # RESUMO POR SEVERIDADE
            # =================================================

            summary = result.get("summary")

            if isinstance(summary, dict):

                st.markdown("### 📈 Resumo por severidade")

                cols = st.columns(6)

                cols[0].metric(
                    "Total",
                    summary.get("total", 0),
                )

                cols[1].metric(
                    "Crítico",
                    summary.get("critical", 0),
                )

                cols[2].metric(
                    "Alto",
                    summary.get("high", 0),
                )

                cols[3].metric(
                    "Médio",
                    summary.get("medium", 0),
                )

                cols[4].metric(
                    "Baixo",
                    summary.get("low", 0),
                )

                cols[5].metric(
                    "Info",
                    summary.get("info", 0),
                )

            # =================================================
            # ACHADOS
            # =================================================

            findings = result.get("findings")

            if isinstance(findings, list) and findings:

                st.markdown("### 🔍 Achados")

                for index, finding in enumerate(
                    findings,
                    start=1,
                ):

                    if not isinstance(finding, dict):
                        st.write(finding)
                        continue

                    title = finding.get(
                        "title",
                        f"Achado {index}",
                    )

                    severity = str(
                        finding.get(
                            "severity",
                            "info",
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

                        if recommendation:
                            st.markdown(
                                f"**Recomendação:** "
                                f"{recommendation}"
                            )

            else:
                st.info(
                    "Nenhum finding foi registrado."
                )

            # =================================================
            # DADOS TÉCNICOS
            # =================================================

            with st.expander(
                "📄 Resultado técnico completo"
            ):
                st.json(result)

        else:
            with st.expander(
                "📄 Resultado"
            ):
                st.write(result)

    except Exception as exc:

        st.error(
            "Falha durante a execução do scanner."
        )

        st.code(
            repr(exc)
        )
PY