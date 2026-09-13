cd ~/bluescan-v2

cat > app.py <<'PY'
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
st.caption(
    "Scanner de segurança para laboratório autorizado"
)


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

    # =========================================================
    # VALIDAÇÃO
    # =========================================================

    allowed, reason = validate_target(target)

    if not allowed:
        st.error(reason)
        st.stop()

    st.success(reason)

    # =========================================================
    # SCANNER
    # =========================================================

    with st.spinner("Executando análise..."):

        try:
            result = scan_target(target)

        except Exception as exc:
            st.error("Erro durante a análise.")
            st.exception(exc)
            st.stop()

    # =========================================================
    # CORRELAÇÃO
    # =========================================================

    try:

        correlation = result.get(
            "correlation",
            {},
        )

        if not isinstance(correlation, dict):
            correlation = {}

        summary = correlation.get(
            "summary",
            {},
        )

        if not isinstance(summary, dict):
            summary = {}

        risk = str(
            correlation.get(
                "risk",
                "INFO",
            )
        ).upper()

    except Exception as exc:

        st.error("Erro ao processar o resultado.")
        st.exception(exc)
        st.stop()

    # =========================================================
    # RISCO GERAL
    # =========================================================

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

    # =========================================================
    # RESUMO
    # =========================================================

    critical = summary.get("critical", 0)
    high = summary.get("high", 0)
    medium = summary.get("medium", 0)
    low = summary.get("low", 0)
    info = summary.get("info", 0)

    col1, col2, col3, col4, col5 = st.columns(5)

    with col1:
        st.metric("Crítico", critical)

    with col2:
        st.metric("Alto", high)

    with col3:
        st.metric("Médio", medium)

    with col4:
        st.metric("Baixo", low)

    with col5:
        st.metric("Informações", info)

    st.divider()

    # =========================================================
    # MÓDULOS
    # =========================================================

    col_http, col_tls, col_dns, col_tech = st.columns(4)

    # ---------------------------------------------------------
    # HTTP
    # ---------------------------------------------------------

    with col_http:

        st.subheader("🌐 HTTP")

        http = result.get("http")

        if isinstance(http, dict) and not http.get("error"):

            status = http.get(
                "status",
                "N/D",
            )

            st.success(
                f"HTTP {status}"
            )

        else:

            st.error("Falha")

            if isinstance(http, dict):
                if http.get("error"):
                    st.caption(
                        str(http["error"])
                    )

    # ---------------------------------------------------------
    # TLS
    # ---------------------------------------------------------

    with col_tls:

        st.subheader("🔐 TLS")

        tls = result.get("tls")

        if isinstance(tls, dict) and not tls.get("error"):

            tls_version = tls.get(
                "tls_version",
                "N/D",
            )

            st.success(
                tls_version
            )

        elif target.lower().startswith("https://"):

            st.error("Falha")

            if isinstance(tls, dict):
                if tls.get("error"):
                    st.caption(
                        str(tls["error"])
                    )

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

        if isinstance(dns, dict) and not dns.get("error"):
            st.success("Analisado")

        else:
            st.error("Falha")

    # ---------------------------------------------------------
    # TECNOLOGIA
    # ---------------------------------------------------------

    with col_tech:

        st.subheader("🧩 Tecnologia")

        technology_result = result.get(
            "technology",
            {},
        )

        if not isinstance(
            technology_result,
            dict,
        ):
            technology_result = {}

        technology_count = technology_result.get(
            "count",
            0,
        )

        st.info(
            f"{technology_count} detectada(s)"
        )

    st.divider()

    # =========================================================
    # WHATWEB
    # =========================================================

    st.subheader("🔎 Fingerprinting — WhatWeb")

    whatweb = result.get(
        "whatweb",
        {},
    )

    if not isinstance(
        whatweb,
        dict,
    ):
        whatweb = {}

    whatweb_status = whatweb.get(
        "status",
        "error",
    )

    if whatweb_status == "ok":

        plugin_count = whatweb.get(
            "plugin_count",
            0,
        )

        st.success(
            f"WhatWeb executado — {plugin_count} "
            f"detecção(ões)"
        )

        plugins = whatweb.get(
            "plugins",
            [],
        )

        if plugins:

            rows = []

            for plugin in plugins:

                if not isinstance(
                    plugin,
                    dict,
                ):
                    continue

                name = plugin.get(
                    "name",
                    "N/D",
                )

                details = plugin.get(
                    "details",
                    [],
                )

                if isinstance(
                    details,
                    list,
                ):
                    details_text = ", ".join(
                        str(x)
                        for x in details
                    )
                else:
                    details_text = str(details)

                rows.append(
                    {
                        "Tecnologia / Plugin": name,
                        "Detalhes": details_text or "—",
                    }
                )

            if rows:
                st.dataframe(
                    rows,
                    use_container_width=True,
                    hide_index=True,
                )

        warning = whatweb.get(
            "warning"
        )

        if warning:
            st.warning(
                str(warning)
            )

    else:

        st.warning(
            "WhatWeb não conseguiu concluir a análise."
        )

        error = whatweb.get(
            "error"
        )

        if error:
            st.caption(
                str(error)
            )

    st.divider()

    # =========================================================
    # TECNOLOGIAS DETECTADAS PELO BLUESCAN
    # =========================================================

    st.subheader("🧩 Tecnologias detectadas pelo BlueScan")

    technologies = technology_result.get(
        "technologies",
        [],
    )

    if technologies:

        for technology in technologies:

            if not isinstance(
                technology,
                dict,
            ):
                continue

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

    # =========================================================
    # ACHADOS DE SEGURANÇA
    # =========================================================

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

        severity_labels = {
            "CRITICAL": "CRÍTICO",
            "HIGH": "ALTO",
            "MEDIUM": "MÉDIO",
            "LOW": "BAIXO",
            "INFO": "INFO",
        }

        for finding in findings:

            if not isinstance(
                finding,
                dict,
            ):
                continue

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

            recommendation = finding.get(
                "recommendation",
                "",
            )

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

                if recommendation:
                    st.write(
                        f"**Recomendação:** {recommendation}"
                    )

    st.divider()

    # =========================================================
    # JSON
    # =========================================================

    st.subheader("📄 Resultado JSON")

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
