cat > ~/bluescan-v2/app.py <<'PY'
import json

import streamlit as st

from scanner import scan_target
from target_policy import validate_target


st.set_page_config(
    page_title="BlueScan",
    page_icon="🔵",
    layout="wide",
)


st.title("🔵 BlueScan")
st.caption("Scanner de segurança para laboratório autorizado")


target = st.text_input(
    "Alvo do laboratório",
    value="https://example.com",
    placeholder="https://exemplo.com",
)


scan_button = st.button(
    "🚀 Iniciar análise",
    type="primary",
    use_container_width=True,
)


if scan_button:

    # ---------------------------------------------------------
    # Validação do alvo
    # ---------------------------------------------------------

    allowed, reason = validate_target(target)

    if not allowed:
        st.error(reason)
        st.stop()

    st.success(reason)

    # ---------------------------------------------------------
    # Execução do scanner
    # ---------------------------------------------------------

    with st.spinner("Executando análise..."):

        try:
            result = scan_target(target)

        except Exception as exc:
            st.error(
                f"Erro durante a análise: {exc}"
            )
            st.stop()

    # ---------------------------------------------------------
    # Correlação / risco
    # ---------------------------------------------------------

    correlation = result.get(
        "correlation",
        {},
    )

    summary = correlation.get(
        "summary",
        {},
    )

    risk = correlation.get(
        "risk",
        "INFO",
    ).upper()

    # ---------------------------------------------------------
    # Risco geral
    # ---------------------------------------------------------

    st.subheader("📊 Risco geral")

    if risk == "CRITICAL":
        st.error("🔴 CRÍTICO")

    elif risk == "HIGH":
        st.error("🟠 ALTO")

    elif risk == "MEDIUM":
        st.warning("🟡 MÉDIO")

    elif risk == "LOW":
        st.info("🔵 BAIXO")

    else:
        st.success("🟢 INFORMAÇÕES")

    col1, col2, col3, col4, col5 = st.columns(5)

    with col1:
        st.metric(
            "Crítico",
            summary.get("critical", 0),
        )

    with col2:
        st.metric(
            "Alto",
            summary.get("high", 0),
        )

    with col3:
        st.metric(
            "Médio",
            summary.get("medium", 0),
        )

    with col4:
        st.metric(
            "Baixo",
            summary.get("low", 0),
        )

    with col5:
        st.metric(
            "Informações",
            summary.get("info", 0),
        )

    st.divider()

    # ---------------------------------------------------------
    # Resumo dos módulos
    # ---------------------------------------------------------

    col_http, col_tls, col_dns, col_tech = st.columns(4)

    # ---------------------------------------------------------
    # HTTP
    # ---------------------------------------------------------

    with col_http:

        st.subheader("🌐 HTTP")

        http = result.get("http")

        if http and not http.get("error"):

            status = http.get(
                "status",
                "OK",
            )

            st.success(
                f"HTTP {status}"
            )

        else:

            error = ""

            if isinstance(http, dict):
                error = http.get(
                    "error",
                    "",
                )

            st.error("Falha")

            if error:
                st.caption(str(error))

    # ---------------------------------------------------------
    # TLS
    # ---------------------------------------------------------

    with col_tls:

        st.subheader("🔐 TLS")

        tls = result.get("tls")

        if tls and not tls.get("error"):

            tls_version = tls.get(
                "tls_version",
                "OK",
            )

            st.success(
                tls_version
            )

        elif target.lower().startswith("https://"):

            st.error("Falha")

            if isinstance(tls, dict):

                error = tls.get(
                    "error",
                    "",
                )

                if error:
                    st.caption(str(error))

        else:

            st.info(
                "Não aplicável"
            )

    # ---------------------------------------------------------
    # DNS
    # ---------------------------------------------------------

    with col_dns:

        st.subheader("📡 DNS")

        dns = result.get("dns")

        if dns and not dns.get("error"):

            st.success(
                "Analisado"
            )

        else:

            st.error(
                "Falha"
            )

    # ---------------------------------------------------------
    # Tecnologia
    # ---------------------------------------------------------

    with col_tech:

        st.subheader("🧩 Tecnologia")

        technology_result = result.get(
            "technology",
            {},
        )

        technology_count = technology_result.get(
            "count",
            0,
        )

        if technology_count == 1:
            texto = "1 detectada"

        else:
            texto = f"{technology_count} detectadas"

        st.info(texto)

    st.divider()

    # ---------------------------------------------------------
    # Tecnologias detectadas
    # ---------------------------------------------------------

    st.subheader("🔎 Tecnologias detectadas")

    technologies = result.get(
        "technology",
        {},
    ).get(
        "technologies",
        [],
    )

    if technologies:

        for technology in technologies:

            name = technology.get(
                "name",
                "Tecnologia",
            )

            evidence = technology.get(
                "evidence",
                "",
            )

            if evidence:

                st.write(
                    f"**{name}** — {evidence}"
                )

            else:

                st.write(
                    f"**{name}**"
                )

    else:

        st.write(
            "Nenhuma tecnologia identificada."
        )

    st.divider()

    # ---------------------------------------------------------
    # Achados
    # ---------------------------------------------------------

    st.subheader("⚠️ Achados de segurança")

    findings = correlation.get(
        "findings",
        [],
    )

    if not findings:

        st.success(
            "Nenhum achado foi identificado."
        )

    else:

        for finding in findings:

            severity = str(
                finding.get(
                    "severity",
                    "INFO",
                )
            ).upper()

            title = finding.get(
                "title",
                "Achado",
            )

            category = finding.get(
                "category",
                "",
            )

            source = finding.get(
                "source",
                "",
            )

            evidence = finding.get(
                "evidence",
                "",
            )

            # Normalização visual da severidade
            severity_labels = {
                "CRITICAL": "CRÍTICO",
                "HIGH": "ALTO",
                "MEDIUM": "MÉDIO",
                "LOW": "BAIXO",
                "INFO": "INFO",
            }

            severity_label = severity_labels.get(
                severity,
                "INFO",
            )

            with st.expander(
                f"[{severity_label}] {title}"
            ):

                if category:
                    st.write(
                        f"**Categoria:** {category}"
                    )

                if source:
                    st.write(
                        f"**Origem:** {source}"
                    )

                if evidence:
                    st.write(
                        f"**Evidência:** {evidence}"
                    )

                recommendation = finding.get(
                    "recommendation",
                    "",
                )

                if recommendation:
                    st.write(
                        f"**Recomendação:** {recommendation}"
                    )

    st.divider()

    # ---------------------------------------------------------
    # Relatório JSON
    # ---------------------------------------------------------

    st.subheader("📄 Relatório JSON")

    json_result = json.dumps(
        result,
        indent=2,
        ensure_ascii=False,
    )

    st.download_button(
        label="⬇️ Baixar relatório JSON",
        data=json_result,
        file_name="bluescan-report.json",
        mime="application/json",
        use_container_width=True,
    )

    with st.expander(
        "🔍 Ver JSON completo"
    ):
        st.json(result)
PY
