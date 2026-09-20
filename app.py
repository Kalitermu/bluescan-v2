cd ~/bluescan-v2
source .venv/bin/activate

cat > app.py <<'PY'
import streamlit as st
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

scan_button = st.button(
    "🔎 Iniciar análise",
    type="primary",
)


if scan_button:

    if not target.strip():
        st.warning("Informe uma URL válida.")
        st.stop()

    target = target.strip()

    st.write("### 🔍 Analisando")
    st.code(target)

    try:
        with st.spinner("Executando análise..."):
            result = scan_target(target)

        st.success("Análise concluída.")

        if isinstance(result, dict):

            summary = result.get("summary")

            if summary:
                st.subheader("📊 Resumo")
                st.write(summary)

            findings = result.get("findings", [])

            if findings:
                st.subheader(f"🚨 Achados ({len(findings)})")

                for index, finding in enumerate(findings, start=1):

                    if isinstance(finding, dict):

                        title = (
                            finding.get("title")
                            or finding.get("name")
                            or f"Achado {index}"
                        )

                        with st.expander(
                            f"{index}. {title}",
                            expanded=False,
                        ):
                            st.json(finding)

                    else:
                        with st.expander(
                            f"{index}. Achado",
                            expanded=False,
                        ):
                            st.write(finding)

            else:
                st.success(
                    "Nenhum achado relevante foi identificado pela análise."
                )

            with st.expander("📄 Resultado técnico completo"):
                st.json(result)

        else:
            with st.expander("📄 Resultado"):
                st.write(result)

    except Exception as error:
        st.error("Ocorreu um erro durante a análise.")

        with st.expander("🔧 Detalhes técnicos"):
            st.exception(error)


st.divider()

st.caption(
    "BlueScan • análise defensiva • uso autorizado"
)
PY

echo "===== VALIDANDO APP ====="
python3 -m py_compile app.py

echo
echo "===== PRIMEIRAS LINHAS ====="
head -n 12 app.py

echo
echo "===== INICIANDO STREAMLIT ====="
streamlit run app.py