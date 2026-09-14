cat > app.py <<'PY'
import json
from datetime import datetime

import streamlit as st

from scanner import scan_target
from target_policy import validate_target
from history import load_history, save_scan, clear_history


st.set_page_config(
    page_title="BlueScan",
    page_icon="🔵",
    layout="wide",
)


# =========================================================
# FUNÇÕES AUXILIARES
# =========================================================

def normalize_findings(findings):
    result = {}

    if not isinstance(findings, list):
        return result

    for finding in findings:

        if not isinstance(finding, dict):
            continue

        title = str(
            finding.get(
                "title",
                "Achado",
            )
        )

        severity = str(
            finding.get(
                "severity",
                "INFO",
            )
        ).upper()

        source = str(
            finding.get(
                "source",
                "",
            )
        )

        finding_id = str(
            finding.get(
                "id",
                f"{severity}|{source}|{title}",
            )
        )

        result[finding_id] = {
            "id": finding_id,
            "title": title,
            "severity": severity,
            "source": source,
        }

    return result


def format_duration(seconds):
    if seconds is None:
        return "N/D"

    try:
        seconds = float(seconds)
    except Exception:
        return "N/D"

    if seconds < 60:
        return f"{seconds:.2f} s"

    minutes = int(seconds // 60)
    remaining = seconds % 60

    return f"{minutes} min {remaining:.1f} s"


def module_status(data):
    if not isinstance(data, dict):
        return "⚠️"

    if data.get("error"):
        return "❌"

    status = str(
        data.get(
            "status",
            "",
        )
    ).lower()

    if status in ("error", "failed", "failure"):
        return "❌"

    return "✅"


def get_previous_scan(history, target):
    for entry in reversed(history):

        if not isinstance(entry, dict):
            continue

        if entry.get("target") == target:
            return entry

    return None


# =========================================================
# SIDEBAR
# =========================================================

with st.sidebar:

    st.title("🔵 BlueScan")

    st.caption(
        "Scanner modular de segurança"
    )

    st.divider()

    st.subheader("🧩 Módulos")

    st.write("🌐 HTTP")
    st.write("🔐 TLS")
    st.write("📡 DNS")
    st.write("🧩 Technology")
    st.write("🔎 WhatWeb")
    st.write("☢️ Security Checks")

    st.divider()

    history = load_history()

    st.metric(
        "📜 Análises armazenadas",
        len(history),
    )

    if st.button(
        "🗑️ Limpar histórico",
        use_container_width=True,
    ):

        clear_history()

        st.success(
            "Histórico apagado."
        )

        st.rerun()


# =========================================================
# CABEÇALHO
# =========================================================

st.title("🔵 BlueScan")

st.caption(
    "Scanner modular de segurança para alvos próprios "
    "ou explicitamente autorizados."
)


# =========================================================
# ALVO
# =========================================================

target = st.text_input(
    "🎯 Alvo autorizado",
    value="https://example.com",
    placeholder="https://exemplo.com",
)


scan_button = st.button(
    "🚀 Iniciar análise",
    type="primary",
    use_container_width=True,
)


# =========================================================
# EXECUÇÃO
# =========================================================

if scan_button:

    # -----------------------------------------------------
    # VALIDAÇÃO
    # -----------------------------------------------------

    allowed, reason = validate_target(
        target
    )

    if not allowed:

        st.error(reason)

        st.stop()

    st.success(reason)

    # -----------------------------------------------------
    # HISTÓRICO ANTERIOR
    # -----------------------------------------------------

    history_before = load_history()

    previous_scan = get_previous_scan(
        history_before,
        target,
    )

    # -----------------------------------------------------
    # SCANNER
    # -----------------------------------------------------

    with st.spinner(
        "🔎 BlueScan executando os módulos..."
    ):

        try:

            result = scan_target(
                target
            )

        except Exception as exc:

            st.error(
                "Erro durante a análise."
            )

            st.exception(exc)

            st.stop()

    # -----------------------------------------------------
    # SALVAR HISTÓRICO
    # -----------------------------------------------------

    try:

        save_scan(result)

    except Exception as exc:

        st.warning(
            "A análise terminou, mas não foi possível "
            "salvar o histórico."
        )

        st.caption(
            str(exc)
        )

    # -----------------------------------------------------
    # CORRELAÇÃO
    # -----------------------------------------------------

    correlation = result.get(
        "correlation",
        {},
    )

    if not isinstance(
        correlation,
        dict,
    ):
        correlation = {}

    summary = correlation.get(
        "summary",
        {},
    )

    if not isinstance(
        summary,
        dict,
    ):
        summary = {}

    risk = str(
        correlation.get(
            "risk",
            "INFO",
        )
    ).upper()

    # =====================================================
    # CABEÇALHO DO RESULTADO
    # =====================================================

    st.divider()

    st.subheader(
        "📊 Resultado da análise"
    )

    col_risk, col_time, col_target = st.columns(
        3
    )

    with col_risk:

        st.metric(
            "Risco geral",
            risk,
        )

    with col_time:

        st.metric(
            "⏱️ Tempo",
            format_duration(
                result.get(
                    "duration_seconds"
                )
            ),
        )

    with col_target:

        st.metric(
            "🎯 Alvo",
            result.get(
                "target",
                target,
            ),
        )

    # =====================================================
    # INDICADOR DE RISCO
    # =====================================================

    if risk == "CRITICAL":

        st.error(
            "🔴 RISCO CRÍTICO"
        )

    elif risk == "HIGH":

        st.error(
            "🟠 RISCO ALTO"
        )

    elif risk == "MEDIUM":

        st.warning(
            "🟡 RISCO MÉDIO"
        )

    elif risk == "LOW":

        st.info(
            "🔵 RISCO BAIXO"
        )

    else:

        st.success(
            "🟢 INFORMAÇÕES"
        )

    # =====================================================
    # RESUMO DE SEVERIDADE
    # =====================================================

    st.subheader(
        "📈 Severidade"
    )

    critical = summary.get(
        "critical",
        0,
    )

    high = summary.get(
        "high",
        0,
    )

    medium = summary.get(
        "medium",
        0,
    )

    low = summary.get(
        "low",
        0,
    )

    info = summary.get(
        "info",
        0,
    )

    vulnerabilities = summary.get(
        "vulnerabilities",
        0,
    )

    configuration = summary.get(
        "configuration",
        0,
    )

    hardening = summary.get(
        "hardening",
        0,
    )

    information = summary.get(
        "information",
        0,
    )

    col1, col2, col3, col4, col5 = st.columns(
        5
    )

    with col1:
        st.metric(
            "🔴 Crítico",
            critical,
        )

    with col2:
        st.metric(
            "🟠 Alto",
            high,
        )

    with col3:
        st.metric(
            "🟡 Médio",
            medium,
        )

    with col4:
        st.metric(
            "🔵 Baixo",
            low,
        )

    with col5:
        st.metric(
            "⚪ Info",
            info,
        )

    # =====================================================
    # CATEGORIAS
    # =====================================================

    st.subheader(
        "🛡️ Classificação"
    )

    col1, col2, col3, col4 = st.columns(
        4
    )

    with col1:
        st.metric(
            "Vulnerabilidades",
            vulnerabilities,
        )

    with col2:
        st.metric(
            "Configuração",
            configuration,
        )

    with col3:
        st.metric(
            "Hardening",
            hardening,
        )

    with col4:
        st.metric(
            "Informações",
            information,
        )

    # =====================================================
    # GRÁFICO
    # =====================================================

    st.subheader(
        "📊 Distribuição de severidade"
    )

    chart_data = {
        "Crítico": critical,
        "Alto": high,
        "Médio": medium,
        "Baixo": low,
        "Info": info,
    }

    st.bar_chart(
        chart_data
    )

    # =====================================================
    # STATUS DOS MÓDULOS
    # =====================================================

    st.subheader(
        "🧩 Status dos módulos"
    )

    http = result.get(
        "http"
    )

    tls = result.get(
        "tls"
    )

    dns = result.get(
        "dns"
    )

    technology = result.get(
        "technology"
    )

    whatweb = result.get(
        "whatweb"
    )

    security_checks = result.get(
        "security_checks"
    )

    col1, col2, col3, col4, col5, col6 = st.columns(
        6
    )

    with col1:
        st.metric(
            "HTTP",
            module_status(http),
        )

    with col2:

        if target.lower().startswith(
            "https://"
        ):

            st.metric(
                "TLS",
                module_status(tls),
            )

        else:

            st.metric(
                "TLS",
                "N/A",
            )

    with col3:
        st.metric(
            "DNS",
            module_status(dns),
        )

    with col4:
        st.metric(
            "Technology",
            module_status(
                technology
            ),
        )

    with col5:
        st.metric(
            "WhatWeb",
            module_status(
                whatweb
            ),
        )

    with col6:
        st.metric(
            "Security Checks",
            module_status(
                security_checks
            ),
        )

    # =====================================================
    # COMPARAÇÃO
    # =====================================================

    st.divider()

    st.subheader(
        "🔄 Comparação com análise anterior"
    )

    current_findings = normalize_findings(
        correlation.get(
            "findings",
            [],
        )
    )

    previous_findings = {}

    if previous_scan:

        previous_findings = normalize_findings(
            previous_scan.get(
                "findings",
                [],
            )
        )

    new_ids = set(
        current_findings
    ) - set(
        previous_findings
    )

    resolved_ids = set(
        previous_findings
    ) - set(
        current_findings
    )

    if previous_scan:

        col1, col2, col3 = st.columns(
            3
        )

        with col1:

            st.metric(
                "🆕 Novos achados",
                len(new_ids),
            )

        with col2:

            st.metric(
                "✅ Resolvidos",
                len(resolved_ids),
            )

        with col3:

            st.metric(
                "📋 Achados anteriores",
                len(previous_findings),
            )

        if new_ids:

            st.write(
                "**🆕 Novos achados**"
            )

            for finding_id in new_ids:

                finding = current_findings[
                    finding_id
                ]

                st.warning(
                    f"[{finding['severity']}] "
                    f"{finding['title']}"
                )

        if resolved_ids:

            st.write(
                "**✅ Achados resolvidos**"
            )

            for finding_id in resolved_ids:

                finding = previous_findings[
                    finding_id
                ]

                st.success(
                    f"[{finding['severity']}] "
                    f"{finding['title']}"
                )

        if not new_ids and not resolved_ids:

            st.success(
                "Nenhuma mudança detectada "
                "em relação à análise anterior."
            )

    else:

        st.info(
            "Esta é a primeira análise registrada "
            "para este alvo."
        )

    # =====================================================
    # WHATWEB
    # =====================================================

    st.divider()

    st.subheader(
        "🔎 Fingerprinting — WhatWeb"
    )

    if isinstance(
        whatweb,
        dict,
    ):

        if whatweb.get("status") == "ok":

            plugin_count = whatweb.get(
                "plugin_count",
                0,
            )

            st.success(
                f"WhatWeb executado — "
                f"{plugin_count} detecção(ões)"
            )

            plugins = whatweb.get(
                "plugins",
                [],
            )

            rows = []

            if isinstance(
                plugins,
                list,
            ):

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

                        details_text = str(
                            details
                        )

                    rows.append(
                        {
                            "Tecnologia / Plugin": name,
                            "Detalhes": (
                                details_text
                                or "—"
                            ),
                        }
                    )

            if rows:

                st.dataframe(
                    rows,
                    use_container_width=True,
                    hide_index=True,
                )

        else:

            st.warning(
                "WhatWeb não conseguiu concluir "
                "a análise."
            )

            if whatweb.get("error"):

                st.caption(
                    str(
                        whatweb["error"]
                    )
                )

    # =====================================================
    # TECNOLOGIAS
    # =====================================================

    st.subheader(
        "🧩 Tecnologias detectadas pelo BlueScan"
    )

    if not isinstance(
        technology,
        dict,
    ):
        technology = {}

    technologies = technology.get(
        "technologies",
        [],
    )

    if technologies:

        for item in technologies:

            if not isinstance(
                item,
                dict,
            ):
                continue

            name = item.get(
                "name",
                "Tecnologia",
            )

            evidence = item.get(
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

    # =====================================================
    # SECURITY CHECKS / NUCLEI
    # =====================================================

    st.divider()

    st.subheader(
        "☢️ Security Checks"
    )

    if isinstance(
        security_checks,
        dict,
    ):

        security_status = security_checks.get(
            "status",
            "unknown",
        )

        security_count = security_checks.get(
            "count",
            0,
        )

        if security_status == "ok":

            st.success(
                f"Security Checks executado — "
                f"{security_count} indicação(ões)"
            )

        elif security_status == "timeout":

            st.warning(
                "Security Checks atingiu o timeout."
            )

        else:

            st.error(
                "Security Checks apresentou erro."
            )

        security_findings = security_checks.get(
            "findings",
            [],
        )

        if security_findings:

            st.dataframe(
                security_findings,
                use_container_width=True,
                hide_index=True,
            )

        if security_checks.get("error"):

            st.caption(
                str(
                    security_checks["error"]
                )
            )

    else:

        st.info(
            "Security Checks não retornou dados."
        )

    # =====================================================
    # ACHADOS DE SEGURANÇA
    # =====================================================

    st.divider()

    st.subheader(
        "⚠️ Achados de segurança"
    )

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

            label = severity_labels.get(
                severity,
                "INFO",
            )

            with st.expander(
                f"[{label}] {title}"
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
                        f"**Recomendação:** "
                        f"{recommendation}"
                    )

    # =====================================================
    # METADADOS DA ANÁLISE
    # =====================================================

    st.divider()

    st.subheader(
        "🕒 Informações da execução"
    )

    started_at = result.get(
        "started_at"
    )

    finished_at = result.get(
        "finished_at"
    )

    col1, col2 = st.columns(
        2
    )

    with col1:

        st.write(
            "**Início:**",
            started_at or "N/D",
        )

    with col2:

        st.write(
            "**Fim:**",
            finished_at or "N/D",
        )

    # =====================================================
    # JSON
    # =====================================================

    st.divider()

    st.subheader(
        "📄 Relatório JSON"
    )

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


# =========================================================
# HISTÓRICO
# =========================================================

st.divider()

st.subheader(
    "📜 Histórico de análises"
)

history = load_history()

if not history:

    st.info(
        "Nenhuma análise armazenada ainda."
    )

else:

    history_rows = []

    for entry in reversed(history):

        if not isinstance(
            entry,
            dict,
        ):
            continue

        summary = entry.get(
            "summary",
            {},
        )

        if not isinstance(
            summary,
            dict,
        ):
            summary = {}

        history_rows.append(
            {
                "Data": entry.get(
                    "timestamp",
                    "N/D",
                ),

                "Alvo": entry.get(
                    "target",
                    "N/D",
                ),

                "Risco": entry.get(
                    "risk",
                    "INFO",
                ),

                "Tempo": format_duration(
                    entry.get(
                        "duration_seconds"
                    )
                ),

                "Crítico": summary.get(
                    "critical",
                    0,
                ),

                "Alto": summary.get(
                    "high",
                    0,
                ),

                "Médio": summary.get(
                    "medium",
                    0,
                ),

                "Baixo": summary.get(
                    "low",
                    0,
                ),

                "Info": summary.get(
                    "info",
                    0,
                ),
            }
        )

    st.dataframe(
        history_rows,
        use_container_width=True,
        hide_index=True,
    )
PY
