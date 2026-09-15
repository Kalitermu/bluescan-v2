
source .venv/bin/activate

cp app.py app.before_smart_summary.py

cat > app.py <<'PY'
import json
import streamlit as st

from scanner import scan_target
from target_policy import validate_target


st.set_page_config(
    page_title="BlueScan",
    page_icon="🔵",
    layout="wide"
)


# ============================================================
# FUNÇÕES AUXILIARES
# ============================================================

def normalize(value):
    if value is None:
        return ""
    return str(value).strip().lower()


def find_result_lists(obj):
    """
    Procura listas de resultados dentro do JSON do scanner.
    """

    found = []

    if isinstance(obj, dict):

        for key, value in obj.items():

            key_normalized = normalize(key)

            if key_normalized in (
                "resultados",
                "results",
                "findings",
                "achados",
                "findings_list"
            ):
                if isinstance(value, list):
                    found.extend(value)

            else:
                found.extend(find_result_lists(value))

    elif isinstance(obj, list):

        for item in obj:
            found.extend(find_result_lists(item))

    return found


def is_relevant_finding(item):
    """
    Decide se um resultado merece aparecer no resumo.
    """

    if not isinstance(item, dict):
        return False

    severity = normalize(
        item.get("gravidade")
        or item.get("severity")
        or item.get("risco")
    )

    classification = normalize(
        item.get("classificação")
        or item.get("classificacao")
        or item.get("classification")
    )

    status = item.get("status")

    try:
        status_code = int(status)
    except (TypeError, ValueError):
        status_code = None

    # Bloqueios conhecidos não são interessantes para o resumo.
    if status_code in (403, 404):
        return False

    if classification in (
        "bloqueado",
        "blocked",
        "não encontrado",
        "nao encontrado",
        "not found"
    ):
        return False

    # Gravidades relevantes.
    if severity in (
        "crítica",
        "critica",
        "critical",
        "alta",
        "high",
        "média",
        "media",
        "medium"
    ):
        return True

    # Respostas potencialmente interessantes.
    if status_code in (200, 206):
        return True

    # Erros do servidor merecem investigação.
    if status_code is not None and status_code >= 500:
        return True

    return False


def get_summary(result):
    """
    Gera um resumo simples para apresentação no dashboard.
    """

    findings = find_result_lists(result)

    relevant = [
        item for item in findings
        if is_relevant_finding(item)
    ]

    # Remove duplicados simples.
    unique = []

    seen = set()

    for item in relevant:

        identifier = (
            normalize(item.get("url") or item.get("URL")),
            normalize(
                item.get("título")
                or item.get("titulo")
                or item.get("title")
            ),
            str(item.get("status", ""))
        )

        if identifier not in seen:
            seen.add(identifier)
            unique.append(item)

    relevant = unique

    # Informações gerais.
    duration = (
        result.get("duração_segundos")
        or result.get("duration_seconds")
        or result.get("duracao_segundos")
    )

    target = (
        result.get("alvo")
        or result.get("target")
        or result.get("target_url")
        or ""
    )

    # Procura dados do motor de exposição.
    exposure = {}

    if isinstance(result.get("exposição"), dict):
        exposure = result["exposição"]

    elif isinstance(result.get("exposicao"), dict):
        exposure = result["exposicao"]

    elif isinstance(result.get("exposure"), dict):
        exposure = result["exposure"]

    checked = (
        exposure.get("caminhos_verificados")
        or exposure.get("recursos_verificados")
        or exposure.get("paths_checked")
        or exposure.get("resources_checked")
        or 0
    )

    discovered = (
        exposure.get("recursos_descobertos")
        or exposure.get("resources_discovered")
        or 0
    )

    return {
        "target": target,
        "duration": duration,
        "checked": checked,
        "discovered": discovered,
        "findings": relevant,
        "all_findings": findings
    }


def show_finding(item, number):
    """
    Exibe somente um achado relevante.
    """

    severity = (
        item.get("gravidade")
        or item.get("severity")
        or "Atenção"
    )

    severity_text = normalize(severity)

    if severity_text in ("crítica", "critica", "critical"):
        icon = "🔴"

    elif severity_text in ("alta", "high"):
        icon = "🟠"

    elif severity_text in ("média", "media", "medium"):
        icon = "🟡"

    else:
        icon = "🔎"

    title = (
        item.get("título")
        or item.get("titulo")
        or item.get("title")
        or "Resultado que merece atenção"
    )

    url = (
        item.get("URL")
        or item.get("url")
        or ""
    )

    status = item.get("status")

    evidence = (
        item.get("evidência")
        or item.get("evidencia")
        or item.get("evidence")
        or ""
    )

    impact = (
        item.get("impacto")
        or item.get("impact")
        or ""
    )

    recommendation = (
        item.get("recomendação")
        or item.get("recomendacao")
        or item.get("recommendation")
        or ""
    )

    st.markdown(
        f"### {icon} {title}"
    )

    if severity:
        st.write(f"**Gravidade:** {severity}")

    if url:
        st.code(str(url), language="text")

    if status is not None:
        st.write(f"**HTTP:** `{status}`")

    if evidence:
        st.write(f"**Evidência:** {evidence}")

    if impact:
        st.write(f"**Impacto:** {impact}")

    if recommendation:
        st.write(f"**Recomendação:** {recommendation}")

    st.divider()


# ============================================================
# INTERFACE
# ============================================================

st.title("🔵 BlueScan")

st.markdown(
    "Scanner de segurança para alvos próprios ou explicitamente autorizados."
)

st.warning(
    "Use somente sistemas próprios ou sistemas para os quais você "
    "tenha autorização explícita para realizar testes."
)

st.subheader("🎯 Alvo autorizado")

target = st.text_input(
    "Informe a URL do alvo",
    placeholder="https://kalitermu.github.io/jlsites/"
)

st.caption(
    "Exemplo: https://kalitermu.github.io/jlsites/"
)


# ============================================================
# EXECUÇÃO
# ============================================================

if st.button("🔍 Executar análise", type="primary"):

    if not target.strip():
        st.error("Informe um alvo.")
        st.stop()

    try:

        valid, message = validate_target(target.strip())

        if not valid:
            st.error(message)
            st.stop()

        st.success("Alvo aceito.")

        st.info(
            "🔵 BlueScan iniciando os módulos de segurança..."
        )

        progress = st.progress(0)

        status = st.empty()

        status.info(
            "🌐 Executando análise HTTP..."
        )

        progress.progress(20)

        result = scan_target(
            target.strip()
        )

        progress.progress(100)

        status.success(
            "✅ Análise concluída."
        )

        st.divider()

        st.header("📊 Resultado da análise")


        # ====================================================
        # RESULTADO NÃO É JSON
        # ====================================================

        if not isinstance(result, dict):

            st.write(result)

            st.stop()


        # ====================================================
        # RESUMO INTELIGENTE
        # ====================================================

        summary = get_summary(result)

        target_result = summary["target"]
        duration = summary["duration"]
        checked = summary["checked"]
        discovered = summary["discovered"]
        findings = summary["findings"]
        all_findings = summary["all_findings"]


        st.subheader("🧠 Resumo inteligente")


        if findings:

            st.error(
                f"🔴 {len(findings)} resultado(s) merece(m) atenção."
            )

        else:

            st.success(
                "🟢 Nenhuma exposição relevante identificada."
            )


        # ====================================================
        # MÉTRICAS
        # ====================================================

        col1, col2, col3, col4 = st.columns(4)

        with col1:
            st.metric(
                "🔎 Caminhos verificados",
                checked
            )

        with col2:
            st.metric(
                "📂 Recursos descobertos",
                discovered
            )

        with col3:
            st.metric(
                "🚨 Achados relevantes",
                len(findings)
            )

        with col4:

            if duration is not None:

                try:
                    duration_text = f"{float(duration):.2f}s"

                except (TypeError, ValueError):
                    duration_text = str(duration)

            else:
                duration_text = "N/D"

            st.metric(
                "⏱️ Duração",
                duration_text
            )


        # ====================================================
        # CONCLUSÃO
        # ====================================================

        st.subheader("📝 Conclusão")

        if findings:

            st.warning(
                "O BlueScan identificou resultados que merecem "
                "investigação. Consulte os achados abaixo."
            )

        else:

            st.info(
                "Os caminhos analisados não apresentaram "
                "exposição relevante. Respostas bloqueadas, como "
                "HTTP 403, não são tratadas como vulnerabilidades."
            )


        # ====================================================
        # ACHADOS RELEVANTES
        # ====================================================

        if findings:

            st.subheader(
                "🚨 O que merece atenção"
            )

            for index, finding in enumerate(
                findings,
                start=1
            ):

                show_finding(
                    finding,
                    index
                )

        else:

            st.subheader(
                "✅ Nenhum achado relevante"
            )

            st.write(
                "O BlueScan realizou os testes previstos e não "
                "encontrou evidências classificadas como exposição."
            )


        # ====================================================
        # OBSERVAÇÕES
        # ====================================================

        if all_findings:

            ignored = len(all_findings) - len(findings)

            if ignored > 0:

                st.caption(
                    f"ℹ️ {ignored} resposta(s) técnica(s) "
                    "não foram exibidas no resumo por não "
                    "representarem um achado relevante."
                )


        # ====================================================
        # DETALHES TÉCNICOS
        # ====================================================

        st.divider()

        with st.expander(
            "🔍 Ver detalhes técnicos da análise"
        ):

            st.json(result)


        # ====================================================
        # JSON COMPLETO
        # ====================================================

        with st.expander(
            "📄 Visualizar JSON completo"
        ):

            st.json(result)


        # ====================================================
        # DOWNLOAD
        # ====================================================

        json_data = json.dumps(
            result,
            indent=2,
            ensure_ascii=False
        )

        st.download_button(
            label="📥 Baixar relatório JSON",
            data=json_data,
            file_name="bluescan_report.json",
            mime="application/json"
        )


    except Exception as e:

        st.error(
            "❌ O BlueScan encontrou um erro durante a análise."
        )

        st.exception(e)

        st.info(
            "O erro acima é importante para identificar qual "
            "módulo está interrompendo a execução."
        )
PY

python -m py_compile app.py
