cd ~/bluescan-v2

cat > app.py <<'PY'
import json
import time

import streamlit as st

from scanner import scan_target
from target_policy import validate_target


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
    "Scanner de segurança para alvos próprios ou explicitamente autorizados."
)

st.warning(
    "Use somente sistemas próprios ou sistemas para os quais você "
    "tenha autorização explícita para realizar testes."
)


# ============================================================
# ENTRADA DO ALVO
# ============================================================

st.subheader("🎯 Alvo autorizado")

target = st.text_input(
    "Informe a URL do alvo",
    placeholder="https://kalitermu.github.io/jlsites/",
)

st.caption(
    "Exemplo: https://kalitermu.github.io/jlsites/"
)


# ============================================================
# EXECUÇÃO
# ============================================================

if st.button("🔍 Executar análise", type="primary"):

    # --------------------------------------------------------
    # Validação básica
    # --------------------------------------------------------

    if not target.strip():
        st.error("Informe um alvo autorizado.")
        st.stop()

    try:
        valid, message = validate_target(target.strip())

        if not valid:
            st.error(message)
            st.stop()

        st.success("Alvo aceito.")

        # ----------------------------------------------------
        # Área de status
        # ----------------------------------------------------

        status = st.empty()
        progress = st.progress(0)

        status.info(
            "🔵 BlueScan iniciando os módulos de segurança..."
        )

        progress.progress(5)

        # ----------------------------------------------------
        # Informações do processamento
        # ----------------------------------------------------

        info_box = st.empty()

        inicio = time.time()

        info_box.info(
            "⏳ O scanner está executando as verificações. "
            "Isso pode levar alguns segundos."
        )

        status.info(
            "🌐 Executando análise de segurança..."
        )

        progress.progress(10)

        # ----------------------------------------------------
        # Scanner principal
        #
        # scan_target executa os módulos internamente.
        # Mantemos essa chamada intacta.
        # ----------------------------------------------------

        result = scan_target(target.strip())

        # ----------------------------------------------------
        # Finalização
        # ----------------------------------------------------

        tempo_total = time.time() - inicio

        progress.progress(100)

        status.success(
            f"✅ Análise concluída em {tempo_total:.2f} segundos."
        )

        info_box.success(
            "🔵 Todos os módulos do BlueScan finalizaram."
        )

        # ----------------------------------------------------
        # Resultado
        # ----------------------------------------------------

        st.divider()

        st.header("📊 Resultado da análise")

        if isinstance(result, dict):

            # ------------------------------------------------
            # Resumo rápido
            # ------------------------------------------------

            correlation = result.get("correlation", {})

            total_findings = correlation.get(
                "total_findings",
                0,
            )

            confirmed = correlation.get(
                "confirmed_vulnerabilities",
                0,
            )

            review = correlation.get(
                "review_findings",
                0,
            )

            col1, col2, col3 = st.columns(3)

            with col1:
                st.metric(
                    "Achados",
                    total_findings,
                )

            with col2:
                st.metric(
                    "Vulnerabilidades confirmadas",
                    confirmed,
                )

            with col3:
                st.metric(
                    "Itens para revisão",
                    review,
                )

            st.divider()

            # ------------------------------------------------
            # JSON completo
            # ------------------------------------------------

            with st.expander(
                "📄 Visualizar resultado completo",
                expanded=False,
            ):
                st.json(result)

            # ------------------------------------------------
            # Download
            # ------------------------------------------------

            json_data = json.dumps(
                result,
                indent=2,
                ensure_ascii=False,
            )

            st.download_button(
                label="📥 Baixar relatório JSON",
                data=json_data,
                file_name="bluescan_report.json",
                mime="application/json",
            )

        else:

            st.write(result)

    except Exception as e:

        st.error(
            "❌ O BlueScan encontrou um erro durante a análise."
        )

        st.exception(e)

        st.info(
            "O erro acima é importante para identificar qual módulo "
            "está interrompendo a execução."
        )
PY
