import streamlit as st
import json
from scanner import scan_target
from target_policy import validate_target


st.set_page_config(
    page_title="BlueScan",
    page_icon="🔵",
    layout="wide"
)

st.title("🔵 BlueScan")
st.caption("Scanner de segurança para laboratório autorizado")


target = st.text_input(
    "Alvo do laboratório",
    value="https://127.0.0.1:8443"
)

scan_button = st.button(
    "🚀 Iniciar análise",
    type="primary"
)


if scan_button:

    allowed, reason = validate_target(target)

    if not allowed:
        st.error(reason)
        st.stop()

    st.success(reason)

    with st.spinner("Executando análise..."):
        try:
            result = scan_target(target)
        except Exception as exc:
            st.error(f"Erro durante a análise: {exc}")
            st.stop()

    correlation = result.get("correlation", {})
    summary = correlation.get("summary", {})

    risk = correlation.get("risk", "INFO")

    st.subheader("Risco geral")

    if risk == "CRITICAL":
        st.error("🔴 CRITICAL")
    elif risk == "HIGH":
        st.error("🟠 HIGH")
    elif risk == "MEDIUM":
        st.warning("🟡 MEDIUM")
    elif risk == "LOW":
        st.info("🔵 LOW")
    else:
        st.success("🟢 INFO")

    col1, col2, col3, col4, col5 = st.columns(5)

    col1.metric(
        "Critical",
        summary.get("critical", 0)
    )

    col2.metric(
        "High",
        summary.get("high", 0)
    )

    col3.metric(
        "Medium",
        summary.get("medium", 0)
    )

    col4.metric(
        "Low",
        summary.get("low", 0)
    )

    col5.metric(
        "Info",
        summary.get("info", 0)
    )

    st.divider()

    col_http, col_tls, col_dns, col_tech = st.columns(4)

    with col_http:
        st.subheader("🌐 HTTP")
        http = result.get("http")

        if http and not http.get("error"):
            st.success(
                f"HTTP {http.get('status')}"
            )
        else:
            st.error("Falha")

    with col_tls:
        st.subheader("🔐 TLS")

        tls = result.get("tls")

        if tls and not tls.get("error"):
            st.success(
                tls.get("tls_version", "OK")
            )
        elif target.startswith("https://"):
            st.error("Falha")
        else:
            st.info("Não aplicável")

    with col_dns:
        st.subheader("📡 DNS")

        dns = result.get("dns")

        if dns:
            st.success("Analisado")
        else:
            st.error("Falha")

    with col_tech:
        st.subheader("🧩 Tecnologia")

        tech = result.get("technology", {})

        st.info(
            f"{tech.get('count', 0)} detectadas"
        )

    st.divider()

    st.subheader("🔎 Tecnologias detectadas")

    technologies = result.get(
        "technology",
        {}
    ).get("technologies", [])

    if technologies:
        for technology in technologies:
            st.write(
                f"**{technology['name']}** — "
                f"{technology['evidence']}"
            )
    else:
        st.write("Nenhuma tecnologia identificada.")

    st.subheader("⚠️ Achados")

    findings = correlation.get(
        "findings",
        []
    )

    if not findings:
        st.success(
            "Nenhum achado foi identificado."
        )
    else:
        for finding in findings:

            severity = finding.get(
                "severity",
                "INFO"
            )

            title = finding.get(
                "title",
                "Achado"
            )

            evidence = finding.get(
                "evidence",
                ""
            )

            source = finding.get(
                "source",
                ""
            )

            with st.expander(
                f"[{severity}] {title}"
            ):
                st.write(
                    f"**Categoria:** "
                    f"{finding.get('category', '')}"
                )

                st.write(
                    f"**Origem:** {source}"
                )

                st.write(
                    f"**Evidência:** {evidence}"
                )

    st.divider()

    st.subheader("📄 Resultado JSON")

    st.download_button(
        "⬇️ Baixar JSON",
        data=json.dumps(
            result,
            indent=2,
            ensure_ascii=False
        ),
        file_name="bluescan-report.json",
        mime="application/json"
    )

    with st.expander("Ver JSON completo"):
        st.json(result)
