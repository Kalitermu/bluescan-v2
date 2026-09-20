import streamlit as st
import time
from scanner import scan_target


st.set_page_config(
    page_title="BlueScan",
    page_icon="🛡️",
    layout="wide",
)


st.title("🛡️ BlueScan")

st.caption(
    "Scanner de segurança para alvos próprios ou explicitamente autorizados."
)

st.info(
    "Use somente em sistemas que você possui ou para os quais possui autorização."
)


target = st.text_input(
    "Alvo",
    placeholder="https://exemplo.com",
)


if st.button("🔎 Iniciar análise", type="primary"):

    target = target.strip()

    if not target:
        st.warning("Informe uma URL válida.")
        st.stop()

    try:
        with st.spinner(
            "Executando HTTP, Headers, TLS, DNS, Technology, "
            "WhatWeb, Wapiti, subfinder e dnsx..."
        ):
            result = scan_target(target)

        st.success("Análise concluída.")

        if not isinstance(result, dict):
            st.error("O scanner retornou um formato inesperado.")
            st.write(result)
            st.stop()

        # =========================================================
        # RESUMO
        # =========================================================

        summary = result.get("summary", {})
        counts = summary.get("counts", {})

        st.subheader("📊 Resumo da análise")

        col1, col2, col3, col4, col5, col6 = st.columns(6)

        col1.metric(
            "Total",
            summary.get("total", 0),
        )

        col2.metric(
            "Critical",
            counts.get("CRITICAL", 0),
        )

        col3.metric(
            "High",
            counts.get("HIGH", 0),
        )

        col4.metric(
            "Medium",
            counts.get("MEDIUM", 0),
        )

        col5.metric(
            "Low",
            counts.get("LOW", 0),
        )

        col6.metric(
            "Info",
            counts.get("INFO", 0),
        )

        # =========================================================
        # STATUS DOS MÓDULOS
        # =========================================================

        st.subheader("🧩 Status dos módulos")

        tool_status = result.get("tool_status", {})

        if tool_status:

            for name, info in tool_status.items():

                status = info.get("status", "unknown")
                error = info.get("error")

                if status == "completed":
                    st.success(f"✅ {name}: concluído")

                elif status == "not_applicable":
                    st.info(f"ℹ️ {name}: não aplicável")

                elif status == "not_run":
                    st.warning(f"⚠️ {name}: não executado")

                elif status == "timeout":
                    st.warning(f"⏱️ {name}: tempo limite atingido")

                else:
                    if error:
                        st.error(
                            f"❌ {name}: {status} — {error}"
                        )
                    else:
                        st.error(
                            f"❌ {name}: {status}"
                        )

        # =========================================================
        # DADOS PRINCIPAIS
        # =========================================================

        st.subheader("🎯 Alvo analisado")

        st.write(
            f"**URL:** {result.get('target', target)}"
        )

        st.write(
            f"**URL final:** {result.get('final_url', '-')}"
        )

        st.write(
            f"**HTTP:** {result.get('status_code', '-')}"
        )

        st.write(
            f"**Duração:** "
            f"{result.get('duration_seconds', '-')} segundos"
        )

        # =========================================================
        # ACHADOS
        # =========================================================

        findings = result.get("findings", [])

        st.subheader(
            f"🔎 Achados consolidados ({len(findings)})"
        )

        if not findings:

            st.success(
                "Nenhum achado foi retornado pelos módulos executados."
            )

        else:

            for index, finding in enumerate(
                findings,
                start=1,
            ):

                if not isinstance(finding, dict):
                    st.write(
                        f"{index}. {finding}"
                    )
                    continue

                severity = str(
                    finding.get("severity", "INFO")
                ).upper()

                title = (
                    finding.get("title")
                    or "Achado sem título"
                )

                source = (
                    finding.get("source")
                    or "BlueScan"
                )

                category = (
                    finding.get("category")
                    or "Security"
                )

                label = (
                    f"{index}. "
                    f"[{severity}] "
                    f"{title}"
                )

                with st.expander(label):

                    st.write(
                        f"**Categoria:** {category}"
                    )

                    st.write(
                        f"**Fonte:** {source}"
                    )

                    st.write("**Evidência**")

                    st.code(
                        str(
                            finding.get(
                                "evidence",
                                "",
                            )
                        )
                    )

                    st.write("**Impacto**")

                    st.write(
                        finding.get(
                            "impact",
                            "Não informado.",
                        )
                    )

                    st.write("**Consequência**")

                    st.write(
                        finding.get(
                            "consequence",
                            "Não informado.",
                        )
                    )

                    st.write("**Recomendação**")

                    st.write(
                        finding.get(
                            "recommendation",
                            "Não informado.",
                        )
                    )

        # =========================================================
        # DADOS TÉCNICOS
        # =========================================================

        technical = result.get("technical", {})

        st.subheader("🛠️ Dados técnicos")

        col1, col2 = st.columns(2)

        with col1:

            st.write("**DNS**")

            dns = technical.get("dns", [])

            if dns:
                for address in dns:
                    st.code(str(address))
            else:
                st.write("Nenhum endereço retornado.")

        with col2:

            st.write("**Tecnologias**")

            technologies = technical.get(
                "technologies",
                [],
            )

            if technologies:
                for technology in technologies:
                    st.code(str(technology))
            else:
                st.write(
                    "Nenhuma tecnologia identificada pelos headers."
                )

        tls = technical.get("tls", {})

        st.write("**TLS**")

        if tls:

            st.json(tls)

        else:

            st.write(
                "Nenhuma informação TLS disponível."
            )

        # =========================================================
        # RESULTADOS POR MÓDULO
        # =========================================================

        modules = result.get("modules", {})

        if modules:

            with st.expander(
                "📦 Resultados detalhados por módulo"
            ):

                for module_name, module_data in modules.items():

                    st.write(
                        f"### {module_name}"
                    )

                    if isinstance(
                        module_data,
                        dict,
                    ):

                        st.write(
                            f"Status: "
                            f"`{module_data.get('status', 'unknown')}`"
                        )

                        module_error = module_data.get(
                            "error"
                        )

                        if module_error:
                            st.error(
                                str(module_error)
                            )

                        module_findings = module_data.get(
                            "findings",
                            [],
                        )

                        if module_findings:
                            st.write(
                                f"Achados do módulo: "
                                f"{len(module_findings)}"
                            )

                    else:

                        st.write(module_data)

        # =========================================================
        # JSON COMPLETO
        # =========================================================

        with st.expander(
            "📄 Resultado técnico completo"
        ):

            st.json(result)

    except Exception as error:

        st.error(
            "Ocorreu um erro durante a análise."
        )

        with st.expander(
            "🔧 Detalhes técnicos"
        ):

            st.exception(error)


st.divider()

st.caption(
    "BlueScan • análise defensiva • uso autorizado"
)