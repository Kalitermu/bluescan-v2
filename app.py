import json
import streamlit as st

from scanner import scan_target
from target_policy import validate_target


st.set_page_config(
    page_title="BlueScan",
    page_icon="🔵",
    layout="wide"
)

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

if st.button("🔍 Executar análise", type="primary"):

    if not target.strip():
        st.error("Informe um alvo autorizado.")
        st.stop()

    try:
        valid, message = validate_target(target.strip())

        if not valid:
            st.error(message)
            st.stop()

        st.success("Alvo aceito.")

        st.info("🔵 BlueScan iniciando os módulos de segurança...")

        progress = st.progress(0)

        status = st.empty()

        status.info("🌐 Executando análise HTTP...")
        progress.progress(20)

        result = scan_target(target.strip())

        progress.progress(100)

        status.success("✅ Análise concluída.")

        st.divider()

        st.header("📊 Resultado da análise")

        if isinstance(result, dict):

            st.json(result)

            st.download_button(
                label="📥 Baixar relatório JSON",
                data=json.dumps(
                    result,
                    indent=2,
                    ensure_ascii=False
                ),
                file_name="bluescan_report.json",
                mime="application/json"
            )

        else:
            st.write(result)

    except Exception as e:

        st.error("❌ O BlueScan encontrou um erro durante a análise.")

        st.exception(e)

        st.info(
            "O erro acima é importante para identificar qual módulo "
            "está interrompendo a execução."
        )
