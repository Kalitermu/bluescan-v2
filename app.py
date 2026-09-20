import streamlit as st
import time
from scanner import scan_target


# ============================================================
# CONFIGURAÇÃO
# ============================================================

st.set_page_config(
    page_title="BlueScan",
    page_icon="🛡️",
    layout="wide",
)


# ============================================================
# CABEÇALHO
# ============================================================

st.title("🛡️ BlueScan")

st.caption(
    "Scanner de segurança para alvos próprios ou explicitamente autorizados."
)

st.info(
    "Use somente em sistemas que você possui ou para os quais possui autorização."
)


# ============================================================
# CAMPO DO ALVO
# ============================================================

target = st.text_input(
    "Alvo",
    placeholder="https://exemplo.com",
    help="Informe uma URL HTTP ou HTTPS do sistema autorizado.",
)


# ============================================================
# BOTÃO DE SCAN
# ============================================================

scan_button = st.button(
    "🔎 Iniciar escaneamento",
    type="primary",
    use_container_width=True,
)


# ============================================================
# FUNÇÕES AUXILIARES
# ============================================================

def format_value(value):
    """
    Converte valores do resultado para uma representação segura
    para exibição no Streamlit.
    """

    if value is None:
        return "Não informado"

    if isinstance(value, bool):
        return "Sim" if value else "Não"

    if isinstance(value, (dict, list)):
        return value

    return str(value)


def show_dict(data, title=None):
    """
    Exibe um dicionário de forma organizada.
    """

    if title:
        st.subheader(title)

    if not isinstance(data, dict):
        st.write(format_value(data))
        return

    if not data:
        st.info("Nenhum dado disponível.")
        return

    for key, value in data.items():

        label = str(key).replace("_", " ").title()

        if isinstance(value, dict):
            with st.expander(f"📂 {label}"):
                show_dict(value)

        elif isinstance(value, list):

            with st.expander(f"📋 {label}"):

                if not value:
                    st.info("Nenhum item encontrado.")
                    continue

                for item in value:

                    if isinstance(item, dict):
                        st.json(item)

                    else:
                        st.write(f"• {item}")

        else:

            st.write(
                f"**{label}:** {format_value(value)}"
            )


# ============================================================
# EXECUÇÃO DO SCAN
# ============================================================

if scan_button:

    if not target.strip():

        st.warning(
            "Informe um alvo antes de iniciar o escaneamento."
        )
        st.stop()

    target = target.strip()

    # --------------------------------------------------------
    # VALIDAÇÃO BÁSICA
    # --------------------------------------------------------

    if not (
        target.startswith("http://")
        or target.startswith("https://")
    ):

        st.error(
            "O alvo deve começar com http:// ou https://."
        )
        st.stop()

    # --------------------------------------------------------
    # STATUS
    # --------------------------------------------------------

    st.divider()

    status_container = st.empty()

    progress_bar = st.progress(
        0,
        text="Preparando escaneamento...",
    )

    try:

        status_container.info(
            f"🎯 Alvo selecionado: {target}"
        )

        progress_bar.progress(
            10,
            text="Validando alvo...",
        )

        time.sleep(0.2)

        status_container.info(
            "🔎 Executando módulos do BlueScan..."
        )

        progress_bar.progress(
            30,
            text="Executando scanner...",
        )

        # ----------------------------------------------------
        # SCANNER PRINCIPAL
        # ----------------------------------------------------

        start_time = time.time()

        result = scan_target(target)

        elapsed = time.time() - start_time

        progress_bar.progress(
            80,
            text="Processando resultados...",
        )

        time.sleep(0.2)

        progress_bar.progress(
            100,
            text="Escaneamento concluído.",
        )

        status_container.success(
            f"✅ Escaneamento concluído em {elapsed:.2f} segundos."
        )

    except Exception as exc:

        progress_bar.empty()

        status_container.error(
            "❌ Ocorreu um erro durante o escaneamento."
        )

        st.exception(exc)

        st.stop()


    # ========================================================
    # RESULTADO
    # ========================================================

    st.divider()

    st.header("📊 Resultado do escaneamento")

    if result is None:

        st.warning(
            "O scanner não retornou resultados."
        )

        st.stop()


    # ========================================================
    # RESULTADO NÃO-DICT
    # ========================================================

    if not isinstance(result, dict):

        st.write(result)

        st.stop()


    # ========================================================
    # RESUMO
    # ========================================================

    st.subheader("🧾 Resumo")

    summary = result.get(
        "summary",
        {},
    )

    if isinstance(summary, dict):

        summary_cols = st.columns(4)

        summary_items = list(
            summary.items()
        )

        for index, (key, value) in enumerate(
            summary_items[:4]
        ):

            col = summary_cols[
                index % len(summary_cols)
            ]

            label = (
                str(key)
                .replace("_", " ")
                .title()
            )

            col.metric(
                label,
                format_value(value),
            )

    else:

        st.write(
            format_value(summary)
        )


    # ========================================================
    # CLASSIFICAÇÃO
    # ========================================================

    severity = result.get(
        "severity",
        result.get(
            "risk",
            result.get(
                "classification",
                None,
            ),
        ),
    )

    if severity is not None:

        st.subheader("🚦 Classificação")

        st.metric(
            "Nível",
            format_value(severity),
        )


    # ========================================================
    # ACHADOS
    # ========================================================

    findings = result.get(
        "findings",
        result.get(
            "vulnerabilities",
            result.get(
                "issues",
                [],
            ),
        ),
    )

    st.subheader("🔍 Achados de segurança")

    if findings is None:

        st.info(
            "Nenhum dado de achados foi retornado."
        )

    elif isinstance(findings, list):

        if len(findings) == 0:

            st.success(
                "Nenhum achado registrado pelo scanner."
            )

        else:

            for index, finding in enumerate(
                findings,
                start=1,
            ):

                if isinstance(finding, dict):

                    title = finding.get(
                        "title",
                        finding.get(
                            "name",
                            f"Achado {index}",
                        ),
                    )

                    category = finding.get(
                        "category",
                        finding.get(
                            "type",
                            "Não informado",
                        ),
                    )

                    severity_finding = finding.get(
                        "severity",
                        finding.get(
                            "risk",
                            "Não informado",
                        ),
                    )

                    with st.expander(
                        f"🔎 {title}"
                    ):

                        col1, col2 = st.columns(2)

                        with col1:

                            st.write(
                                "**Categoria:**",
                                format_value(category),
                            )

                        with col2:

                            st.write(
                                "**Severidade:**",
                                format_value(
                                    severity_finding
                                ),
                            )

                        if "source" in finding:

                            st.write(
                                "**Fonte:**",
                                format_value(
                                    finding.get(
                                        "source"
                                    )
                                ),
                            )

                        if "evidence" in finding:

                            st.write(
                                "**Evidência:**"
                            )

                            st.code(
                                format_value(
                                    finding.get(
                                        "evidence"
                                    )
                                )
                            )

                        if "impact" in finding:

                            st.write(
                                "**Impacto:**",
                                format_value(
                                    finding.get(
                                        "impact"
                                    )
                                ),
                            )

                        if "consequence" in finding:

                            st.write(
                                "**Consequência:**",
                                format_value(
                                    finding.get(
                                        "consequence"
                                    )
                                ),
                            )

                        if "recommendation" in finding:

                            st.write(
                                "**Recomendação:**",
                                format_value(
                                    finding.get(
                                        "recommendation"
                                    )
                                ),
                            )

                        # Campos adicionais
                        extra_fields = {
                            key: value
                            for key, value in finding.items()
                            if key not in {
                                "title",
                                "name",
                                "category",
                                "type",
                                "severity",
                                "risk",
                                "source",
                                "evidence",
                                "impact",
                                "consequence",
                                "recommendation",
                            }
                        }

                        if extra_fields:

                            with st.expander(
                                "📎 Dados adicionais"
                            ):

                                st.json(
                                    extra_fields
                                )

                else:

                    st.write(
                        f"{index}. {finding}"
                    )

    elif isinstance(findings, dict):

        show_dict(
            findings
        )

    else:

        st.write(
            format_value(findings)
        )


    # ========================================================
    # DADOS TÉCNICOS
    # ========================================================

    st.divider()

    st.subheader("🛠️ Dados técnicos")

    technical = result.get(
        "technical",
        {},
    )

    if isinstance(technical, dict):

        dns = technical.get(
            "dns"
        )

        technologies = technical.get(
            "technologies"
        )

        tls = technical.get(
            "tls"
        )

        http = technical.get(
            "http"
        )

        # ----------------------------------------------------
        # DNS
        # ----------------------------------------------------

        with st.expander("🌐 DNS"):

            if dns:

                if isinstance(dns, dict):
                    st.json(dns)

                else:
                    st.write(
                        format_value(dns)
                    )

            else:

                st.info(
                    "Nenhuma informação DNS disponível."
                )

        # ----------------------------------------------------
        # TECNOLOGIAS
        # ----------------------------------------------------

        with st.expander("⚙️ Tecnologias"):

            if technologies:

                if isinstance(
                    technologies,
                    dict,
                ):

                    st.json(
                        technologies
                    )

                elif isinstance(
                    technologies,
                    list,
                ):

                    for technology in technologies:

                        st.write(
                            f"• {technology}"
                        )

                else:

                    st.write(
                        format_value(
                            technologies
                        )
                    )

            else:

                st.info(
                    "Nenhuma tecnologia identificada."
                )

        # ----------------------------------------------------
        # TLS
        # ----------------------------------------------------

        with st.expander("🔐 TLS"):

            if tls:

                if isinstance(tls, dict):
                    st.json(tls)

                else:
                    st.write(
                        format_value(tls)
                    )

            else:

                st.info(
                    "Nenhuma informação TLS disponível."
                )

        # ----------------------------------------------------
        # HTTP
        # ----------------------------------------------------

        with st.expander("🌍 HTTP"):

            if http:

                if isinstance(http, dict):
                    st.json(http)

                else:
                    st.write(
                        format_value(http)
                    )

            else:

                st.info(
                    "Nenhuma informação HTTP disponível."
                )

    else:

        st.info(
            "Nenhum dado técnico disponível."
        )


    # ========================================================
    # STATUS DOS MÓDULOS
    # ========================================================

    st.divider()

    st.subheader("🧩 Status dos módulos")

    modules = result.get(
        "modules",
        result.get(
            "module_status",
            result.get(
                "status",
                {},
            ),
        ),
    )

    if isinstance(modules, dict):

        module_items = list(
            modules.items()
        )

        if module_items:

            module_cols = st.columns(
                min(
                    len(module_items),
                    4,
                )
            )

            for index, (name, status) in enumerate(
                module_items
            ):

                col = module_cols[
                    index % len(module_cols)
                ]

                if isinstance(status, dict):

                    module_status = status.get(
                        "status",
                        status.get(
                            "state",
                            "available",
                        ),
                    )

                    col.metric(
                        str(name),
                        str(module_status),
                    )

                else:

                    col.metric(
                        str(name),
                        str(status),
                    )

        else:

            st.info(
                "Nenhum status de módulo disponível."
            )

    else:

        st.info(
            "Nenhum status de módulo disponível."
        )


    # ========================================================
    # OUTROS DADOS
    # ========================================================

    known_sections = {
        "summary",
        "severity",
        "risk",
        "classification",
        "findings",
        "vulnerabilities",
        "issues",
        "technical",
        "modules",
        "module_status",
        "status",
    }

    extra_result = {
        key: value
        for key, value in result.items()
        if key not in known_sections
    }

    if extra_result:

        st.divider()

        with st.expander(
            "📦 Outros dados retornados pelo scanner"
        ):

            st.json(
                extra_result
            )


    # ========================================================
    # RESULTADO BRUTO
    # ========================================================

    st.divider()

    with st.expander(
        "🧪 Resultado bruto do scanner"
    ):

        st.json(
            result
        )

Como colocar no seu BlueScan

No Kali, dentro do projeto:

cd ~/bluescan-v2
source .venv/bin/activate

Faça backup do atual:

cp app.py app.py.bak

Depois substitua o conteúdo do "app.py" pelo código acima.

Em seguida, valide antes de abrir o Streamlit:

python3 -m py_compile app.py

Se não aparecer nenhuma mensagem, rode:

streamlit run app.py

Esse "app.py" foi feito para ser tolerante ao formato do retorno do scanner: ele procura "summary", "findings", "technical", "modules", "severity" etc., mas também aceita algumas variações como "vulnerabilities", "issues", "risk" e "module_status".

Importante: ele não altera "scanner.py", "scanner_checks.py", "correlator.py" ou os demais módulos. O ponto de integração continua sendo:

result = scan_target(target)

Assim, o próximo diagnóstico fica bem mais fácil: se "py_compile" passar mas algum resultado aparecer errado, sabemos que o problema está no formato retornado pelo "scanner.py", e não na sintaxe do "app.py".