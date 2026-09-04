# ================================================================
# AULA 48 V2 - FECHAMENTO E DOCUMENTACAO FINAL
# CyberSentinel-ML
#
# Objetivo:
# Consolidar os resultados finais do laboratorio e gerar:
#
# - README_FINAL.md
# - docs/ARQUITETURA_FINAL.md
# - docs/RESUMO_EXECUTIVO.md
# - docs/inventario_tecnico.json
# - alertas/relatorio_aula_48.json
#
# Tambem registra o fechamento no SQLite.
#
# IMPORTANTE:
# - nao retreina modelos
# - nao recalcula scores
# - nao cria novas decisoes
# - nao altera Cases
# - nao executa Lifecycle
# - nao executa contencao
# - nao bloqueia IP
# - nao altera firewall
#
# Modo operacional: SIMULACAO
# ================================================================

import json
import sqlite3
import uuid

from datetime import datetime, timezone
from pathlib import Path


# ================================================================
# CONFIGURACOES
# ================================================================

PROJETO = "CyberSentinel-ML"
AULA = 48
VERSAO = "2.0"

MODO_OPERACIONAL = "SIMULACAO"

BASE_DIR = Path(__file__).resolve().parent

DADOS_DIR = BASE_DIR / "dados"
MODELOS_DIR = BASE_DIR / "modelos"
PIPELINE_DIR = BASE_DIR / "pipeline"
METRICAS_DIR = BASE_DIR / "metricas"
TESTES_DIR = BASE_DIR / "testes"
ALERTAS_DIR = BASE_DIR / "alertas"
DOCS_DIR = BASE_DIR / "docs"

DB_PATH = DADOS_DIR / "cybersentinel.db"

README_PATH = BASE_DIR / "README_FINAL.md"

ARQUITETURA_PATH = (
    DOCS_DIR / "ARQUITETURA_FINAL.md"
)

RESUMO_PATH = (
    DOCS_DIR / "RESUMO_EXECUTIVO.md"
)

INVENTARIO_PATH = (
    DOCS_DIR / "inventario_tecnico.json"
)

RELATORIO_PATH = (
    ALERTAS_DIR / "relatorio_aula_48.json"
)

ARQUIVO_OBSERVABILITY = (
    METRICAS_DIR / "soc_metrics_aula_45.json"
)

ARQUIVO_E2E = (
    PIPELINE_DIR / "end_to_end_aula_46.json"
)

ARQUIVO_TESTES = (
    TESTES_DIR / "final_validation_aula_47.json"
)

TABELA_FECHAMENTO = (
    "soc_project_closure"
)

LARGURA = 80


# ================================================================
# COMPONENTES DO PROJETO
# ================================================================

COMPONENTES = [
    "Machine Learning - Binary Classification",
    "Machine Learning - Multiclass Classification",
    "JSON / JSONL Ingestion",
    "REST API",
    "Batch Processing",
    "SQLite Persistence",
    "Operational Observability",
    "Operational Alerts",
    "Threat Intelligence",
    "AbuseIPDB Integration",
    "IOC Enrichment",
    "Risk Score V2",
    "Historical IOC Correlation",
    "Campaign Detection",
    "Incident Timeline",
    "Incident Response Playbooks",
    "MITRE ATT&CK Context",
    "Incident Evidence Correlation",
    "SOC Incident Decision Engine",
    "SOC Case Management",
    "SOC Case Lifecycle",
    "Human Approval Gate",
    "SOC Metrics & Observability",
    "Pipeline End-to-End",
    "Final Validation Test Suite",
]


# ================================================================
# ARTEFATOS ML
# ================================================================

ARTEFATOS_ML = {
    "modelo_binario":
        MODELOS_DIR
        / "unsw_decision_tree.joblib",

    "configuracao_binaria":
        MODELOS_DIR
        / "configuracao_modelo.joblib",

    "modelo_multiclasse":
        MODELOS_DIR
        / "unsw_attack_multiclass_otimizado.joblib",

    "configuracao_multiclasse":
        MODELOS_DIR
        / "configuracao_multiclasse_otimizada_aula_22.joblib",
}


# ================================================================
# VISUAL
# ================================================================

def linha():
    print("=" * LARGURA)


def separador():
    print("-" * LARGURA)


def titulo(valor):
    linha()
    print(valor)
    linha()


def ok(valor):
    print(f"[OK] {valor}")


def erro(valor):
    print(f"[ERRO] {valor}")


def aviso(valor):
    print(f"[AVISO] {valor}")


def info(valor):
    print(f"[INFO] {valor}")


# ================================================================
# AUXILIARES
# ================================================================

def agora_iso():
    return datetime.now(
        timezone.utc
    ).isoformat()


def gerar_id(prefixo):

    timestamp = datetime.now(
        timezone.utc
    ).strftime(
        "%Y%m%d%H%M%S%f"
    )

    sufixo = (
        uuid.uuid4()
        .hex[:8]
        .upper()
    )

    return (
        f"{prefixo}-"
        f"{timestamp}-"
        f"{sufixo}"
    )


def texto(
    valor,
    padrao=""
):
    if valor is None:
        return padrao

    valor = str(
        valor
    ).strip()

    if not valor:
        return padrao

    return valor


def inteiro(
    valor,
    padrao=0
):
    try:
        if valor is None:
            return padrao

        return int(
            valor
        )

    except (
        TypeError,
        ValueError,
    ):
        return padrao


def numero(
    valor,
    padrao=0.0
):
    try:
        if valor is None:
            return padrao

        return float(
            valor
        )

    except (
        TypeError,
        ValueError,
    ):
        return padrao


def booleano(valor):

    if isinstance(
        valor,
        bool
    ):
        return valor

    if valor is None:
        return False

    if isinstance(
        valor,
        (int, float)
    ):
        return valor != 0

    return (
        str(valor)
        .strip()
        .upper()
        in {
            "SIM",
            "TRUE",
            "YES",
            "1",
            "VERDADEIRO",
        }
    )


def carregar_json(caminho):

    try:

        with open(
            caminho,
            "r",
            encoding="utf-8",
        ) as arquivo:

            return json.load(
                arquivo
            )

    except (
        OSError,
        json.JSONDecodeError,
    ):

        return None


def salvar_json(
    caminho,
    dados
):

    caminho.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with open(
        caminho,
        "w",
        encoding="utf-8",
    ) as arquivo:

        json.dump(
            dados,
            arquivo,
            indent=4,
            ensure_ascii=False,
            default=str,
        )


def salvar_texto(
    caminho,
    conteudo
):

    caminho.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with open(
        caminho,
        "w",
        encoding="utf-8",
    ) as arquivo:

        arquivo.write(
            conteudo
        )


# ================================================================
# SQLITE
# ================================================================

def conectar_banco():

    conexao = sqlite3.connect(
        DB_PATH
    )

    conexao.row_factory = (
        sqlite3.Row
    )

    return conexao


def tabela_existe(
    conexao,
    tabela
):

    cursor = conexao.cursor()

    cursor.execute(
        """
        SELECT name
        FROM sqlite_master
        WHERE type = 'table'
          AND name = ?
        """,
        (tabela,),
    )

    return (
        cursor.fetchone()
        is not None
    )


def listar_tabelas(
    conexao
):

    cursor = conexao.cursor()

    cursor.execute(
        """
        SELECT name
        FROM sqlite_master
        WHERE type = 'table'
          AND name NOT LIKE 'sqlite_%'
        ORDER BY name
        """
    )

    return [
        registro["name"]
        for registro
        in cursor.fetchall()
    ]


def contar_registros(
    conexao,
    tabela
):

    cursor = conexao.cursor()

    cursor.execute(
        f"""
        SELECT COUNT(*)
        FROM {tabela}
        """
    )

    resultado = (
        cursor.fetchone()
    )

    if not resultado:
        return 0

    return inteiro(
        resultado[0]
    )


def obter_colunas(
    conexao,
    tabela
):

    cursor = conexao.cursor()

    cursor.execute(
        f"""
        PRAGMA table_info(
            {tabela}
        )
        """
    )

    return [
        registro["name"]
        for registro
        in cursor.fetchall()
    ]


# ================================================================
# TABELA DE FECHAMENTO
# ================================================================

def criar_tabela_fechamento(
    conexao
):

    cursor = conexao.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS soc_project_closure (
            closure_id TEXT PRIMARY KEY,
            timestamp TEXT,

            projeto TEXT,
            aula INTEGER,
            versao TEXT,

            artefatos_ml INTEGER,
            tabelas_sqlite INTEGER,

            iocs_ativos INTEGER,

            testes_total INTEGER,
            testes_ok INTEGER,
            testes_falha INTEGER,
            cobertura_testes REAL,

            end_to_end_health REAL,
            observability_health REAL,

            execucoes_reais INTEGER,
            bloqueios_automaticos INTEGER,

            modo_operacional TEXT,

            status TEXT
        )
        """
    )

    conexao.commit()


def persistir_fechamento(
    conexao,
    dados
):

    cursor = conexao.cursor()

    cursor.execute(
        """
        INSERT INTO soc_project_closure (
            closure_id,
            timestamp,

            projeto,
            aula,
            versao,

            artefatos_ml,
            tabelas_sqlite,

            iocs_ativos,

            testes_total,
            testes_ok,
            testes_falha,
            cobertura_testes,

            end_to_end_health,
            observability_health,

            execucoes_reais,
            bloqueios_automaticos,

            modo_operacional,

            status
        )
        VALUES (
            ?, ?,
            ?, ?, ?,
            ?, ?,
            ?,
            ?, ?, ?, ?,
            ?, ?,
            ?, ?,
            ?,
            ?
        )
        """,
        (
            dados["closure_id"],
            dados["timestamp"],

            PROJETO,
            AULA,
            VERSAO,

            dados["artefatos_ml"],
            dados["tabelas_sqlite"],

            dados["iocs_ativos"],

            dados["testes_total"],
            dados["testes_ok"],
            dados["testes_falha"],
            dados["cobertura_testes"],

            dados["end_to_end_health"],
            dados["observability_health"],

            dados["execucoes_reais"],
            dados["bloqueios_automaticos"],

            MODO_OPERACIONAL,

            dados["status"],
        )
    )

    conexao.commit()


# ================================================================
# GERACAO DO README
# ================================================================

def gerar_readme(
    inventario
):

    testes = inventario[
        "testes_finais"
    ]

    e2e = inventario[
        "end_to_end"
    ]

    observability = inventario[
        "observability"
    ]

    seguranca = inventario[
        "seguranca"
    ]

    linhas = [
        "# CyberSentinel-ML",
        "",
        "Laboratório educacional de Machine Learning aplicado à Cybersecurity e operações SOC.",
        "",
        "> Projeto executado em ambiente controlado e mantido em modo **SIMULAÇÃO**.",
        "",
        "## Visão geral",
        "",
        "O CyberSentinel-ML integra Machine Learning, Threat Intelligence,",
        "correlação histórica, gerenciamento de incidentes, contexto MITRE ATT&CK,",
        "Evidence Correlation, Decision Engine, Case Management e observabilidade.",
        "",
        "O laboratório foi projetado para demonstrar uma arquitetura defensiva,",
        "auditável e segura, sem executar ações destrutivas na infraestrutura.",
        "",
        "## Pipeline",
        "",
        "```text",
        "Machine Learning",
        "       |",
        "       v",
        "Threat Intelligence",
        "       |",
        "       v",
        "IOC Enrichment",
        "       |",
        "       v",
        "Risk Score V2",
        "       |",
        "       v",
        "Historical Correlation",
        "       |",
        "       v",
        "Campaign Detection",
        "       |",
        "       v",
        "Incident Timeline",
        "       |",
        "       v",
        "Incident Response",
        "       |",
        "       v",
        "MITRE ATT&CK Context",
        "       |",
        "       v",
        "Incident Evidence",
        "       |",
        "       v",
        "SOC Decision Engine",
        "       |",
        "       v",
        "Case Management",
        "       |",
        "       v",
        "Case Lifecycle",
        "       |",
        "       v",
        "Human Approval Gate",
        "       |",
        "       v",
        "Metrics & Observability",
        "       |",
        "       v",
        "End-to-End Validation",
        "       |",
        "       v",
        "Final Test Suite",
        "```",
        "",
        "## Principais componentes",
        "",
    ]

    for componente in COMPONENTES:
        linhas.append(
            f"- {componente}"
        )

    linhas.extend(
        [
            "",
            "## Machine Learning",
            "",
            "Modelos binário e multiclasse persistidos com Joblib.",
            "",
            "Features utilizadas:",
            "",
            "- spkts",
            "- dpkts",
            "- sbytes",
            "- dbytes",
            "- rate",
            "- sttl",
            "- dttl",
            "- sload",
            "- dload",
            "",
            "## Threat Intelligence",
            "",
            "O laboratório inclui enriquecimento de IOC e integração com AbuseIPDB.",
            "",
            "Credenciais e chaves devem permanecer em variáveis de ambiente e nunca",
            "devem ser publicadas no repositório.",
            "",
            "## Lineage",
            "",
            "O vínculo principal validado é:",
            "",
            "```text",
            "Decision.evidence_id",
            "        ==",
            "Evidence.evidence_id",
            "```",
            "",
            "## MITRE ATT&CK",
            "",
            "O mapeamento MITRE é contextual e conservador.",
            "Technique IDs não são atribuídos quando não há evidência suficiente.",
            "",
            "O contexto MITRE canônico do End-to-End é obtido do Evidence",
            "referenciado pela Decision.",
            "",
            "## Resultados finais",
            "",
            f"- Testes executados: {testes['total']}",
            f"- Testes aprovados: {testes['ok']}",
            f"- Falhas: {testes['falhas']}",
            f"- Cobertura: {testes['cobertura']:.2f}%",
            f"- End-to-End Health: {e2e['health']:.2f}%",
            f"- Observability Health: {observability['health']:.2f}%",
            f"- IOCs ativos: {inventario['iocs_ativos']}",
            "",
            "## Segurança operacional",
            "",
            f"- Execuções reais: {seguranca['execucoes_reais']}",
            f"- Bloqueios automáticos: {seguranca['bloqueios_automaticos']}",
            "- Contenção real: não executada",
            "- Firewall: não alterado",
            f"- Modo operacional: {MODO_OPERACIONAL}",
            "",
            "## Arquivos principais de validação",
            "",
            "- `metricas/soc_metrics_aula_45.json`",
            "- `metricas/soc_metrics_aula_45.prom`",
            "- `pipeline/end_to_end_aula_46.json`",
            "- `testes/final_validation_aula_47.json`",
            "- `docs/inventario_tecnico.json`",
            "- `docs/ARQUITETURA_FINAL.md`",
            "- `docs/RESUMO_EXECUTIVO.md`",
            "",
            "## Uso responsável",
            "",
            "Projeto desenvolvido para treinamento e pesquisa defensiva.",
            "",
            "Não realiza bloqueio automático de IP, alteração de firewall",
            "ou contenção operacional real.",
            "",
            "## Status",
            "",
            "**PROJETO CONCLUÍDO**",
            "",
            f"Modo final: **{MODO_OPERACIONAL}**",
            "",
        ]
    )

    return "\n".join(
        linhas
    )


# ================================================================
# GERACAO DA ARQUITETURA
#
# Nesta versao NAO usamos f-string tripla.
# Isso elimina o SyntaxError encontrado na V1.
# ================================================================

def gerar_arquitetura(
    inventario
):

    linhas = [
        "# Arquitetura Final - CyberSentinel-ML",
        "",
        "## Visão geral",
        "",
        "O CyberSentinel-ML é um laboratório SOC defensivo que integra",
        "Machine Learning, Threat Intelligence, correlação, evidência,",
        "decisão, gestão de casos, aprovação e observabilidade.",
        "",
        "## Arquitetura",
        "",
        "```text",
        "                   CYBERSENTINEL-ML",
        "                          |",
        "                          v",
        "                 MACHINE LEARNING",
        "                    |         |",
        "                    v         v",
        "                 BINARIO   MULTICLASSE",
        "                    |         |",
        "                    +----+----+",
        "                         |",
        "                         v",
        "                EVENT CLASSIFICATION",
        "                         |",
        "                         v",
        "                THREAT INTELLIGENCE",
        "                         |",
        "                         v",
        "                   IOC ENRICHMENT",
        "                         |",
        "                         v",
        "                    RISK SCORE V2",
        "                         |",
        "                         v",
        "               HISTORICAL CORRELATION",
        "                         |",
        "                         v",
        "                 CAMPAIGN DETECTION",
        "                         |",
        "                         v",
        "                  INCIDENT TIMELINE",
        "                         |",
        "                         v",
        "                 INCIDENT RESPONSE",
        "                         |",
        "                         v",
        "                MITRE ATT&CK CONTEXT",
        "                         |",
        "                         v",
        "                  INCIDENT EVIDENCE",
        "                         |",
        "                         v",
        "                 SOC DECISION ENGINE",
        "                         |",
        "                         v",
        "                  CASE MANAGEMENT",
        "                         |",
        "                         v",
        "                   CASE LIFECYCLE",
        "                         |",
        "                         v",
        "                 HUMAN APPROVAL GATE",
        "                         |",
        "                         v",
        "              METRICS & OBSERVABILITY",
        "                         |",
        "                         v",
        "               END-TO-END VALIDATION",
        "                         |",
        "                         v",
        "                  FINAL TEST SUITE",
        "                         |",
        "                         v",
        "                  PROJECT CLOSURE",
        "```",
        "",
        "## Lineage principal",
        "",
        "```text",
        "Decision",
        "   |",
        "   +-- evidence_id",
        "            |",
        "            v",
        "         Evidence",
        "            |",
        "            +-- evidence_score",
        "            +-- mitre_contexto",
        "            +-- mitre_tatica",
        "            +-- mitre_confianca",
        "```",
        "",
        "Regra validada:",
        "",
        "```text",
        "Decision.evidence_id == Evidence.evidence_id",
        "```",
        "",
        "## Persistência",
        "",
        "Banco:",
        "",
        "```text",
        "dados/cybersentinel.db",
        "```",
        "",
        "Total de tabelas no fechamento:",
        "",
        f"{inventario['sqlite']['total_tabelas']}",
        "",
        "## Machine Learning",
        "",
        (
            "Artefatos ML: "
            f"{inventario['machine_learning']['disponiveis']}/"
            f"{inventario['machine_learning']['esperados']}"
        ),
        "",
        "## Observability",
        "",
        (
            "Pipeline Health: "
            f"{inventario['observability']['health']:.2f}%"
        ),
        "",
        "## End-to-End",
        "",
        (
            "Health: "
            f"{inventario['end_to_end']['health']:.2f}%"
        ),
        "",
        (
            "Lineages completos: "
            f"{inventario['end_to_end']['lineages_completos']}"
        ),
        "",
        "## Testes finais",
        "",
        (
            "Executados: "
            f"{inventario['testes_finais']['total']}"
        ),
        (
            "Aprovados: "
            f"{inventario['testes_finais']['ok']}"
        ),
        (
            "Falhas: "
            f"{inventario['testes_finais']['falhas']}"
        ),
        (
            "Cobertura: "
            f"{inventario['testes_finais']['cobertura']:.2f}%"
        ),
        "",
        "## Segurança",
        "",
        "```text",
        (
            "Execuções reais ............... "
            f"{inventario['seguranca']['execucoes_reais']}"
        ),
        (
            "Bloqueios automáticos ......... "
            f"{inventario['seguranca']['bloqueios_automaticos']}"
        ),
        "Contenção real ................ NAO",
        "Firewall ...................... NAO ALTERADO",
        (
            "Modo operacional .............. "
            f"{MODO_OPERACIONAL}"
        ),
        "```",
        "",
        "## Princípio arquitetural",
        "",
        "```text",
        "DETECCAO",
        "   !=",
        "EVIDENCIA",
        "   !=",
        "DECISAO",
        "   !=",
        "APROVACAO",
        "   !=",
        "EXECUCAO",
        "```",
        "",
        "Nenhuma decisão crítica resulta automaticamente",
        "em alteração real de infraestrutura.",
        "",
        "## Status",
        "",
        "**CYBERSENTINEL-ML CONCLUÍDO**",
        "",
    ]

    return "\n".join(
        linhas
    )


# ================================================================
# GERACAO DO RESUMO EXECUTIVO
# ================================================================

def gerar_resumo(
    inventario
):

    linhas = [
        "# Resumo Executivo - CyberSentinel-ML",
        "",
        "## Projeto",
        "",
        "CyberSentinel-ML",
        "",
        "## Objetivo",
        "",
        "Construir um laboratório educacional que integra Machine Learning",
        "e operações defensivas de Cybersecurity/SOC.",
        "",
        "## Capacidades demonstradas",
        "",
        "- Classificação binária",
        "- Classificação multiclasse",
        "- Ingestão JSON e JSONL",
        "- Processamento em lote",
        "- API REST",
        "- Persistência SQLite",
        "- Threat Intelligence",
        "- Enriquecimento de IOC",
        "- Risk Score",
        "- Correlação histórica",
        "- Campaign Detection",
        "- Incident Timeline",
        "- Incident Response",
        "- MITRE ATT&CK Context",
        "- Evidence Correlation",
        "- SOC Decision Engine",
        "- Case Management",
        "- Case Lifecycle",
        "- Human Approval Gate",
        "- Observability",
        "- End-to-End Validation",
        "- Test Suite final",
        "",
        "## Resultado final",
        "",
        (
            "Testes executados: "
            f"{inventario['testes_finais']['total']}"
        ),
        "",
        (
            "Testes aprovados: "
            f"{inventario['testes_finais']['ok']}"
        ),
        "",
        (
            "Falhas: "
            f"{inventario['testes_finais']['falhas']}"
        ),
        "",
        (
            "Cobertura: "
            f"{inventario['testes_finais']['cobertura']:.2f}%"
        ),
        "",
        "## Pipeline",
        "",
        (
            "End-to-End Health: "
            f"{inventario['end_to_end']['health']:.2f}%"
        ),
        "",
        (
            "Observability Health: "
            f"{inventario['observability']['health']:.2f}%"
        ),
        "",
        (
            "IOCs ativos: "
            f"{inventario['iocs_ativos']}"
        ),
        "",
        "## Segurança",
        "",
        (
            "- Execuções reais: "
            f"{inventario['seguranca']['execucoes_reais']}"
        ),
        (
            "- Bloqueios automáticos: "
            f"{inventario['seguranca']['bloqueios_automaticos']}"
        ),
        "- Alteração real de firewall: não",
        "- Contenção automática real: não",
        (
            "- Modo operacional: "
            f"{MODO_OPERACIONAL}"
        ),
        "",
        "## Conclusão",
        "",
        "O CyberSentinel-ML demonstra uma arquitetura SOC defensiva,",
        "auditável e orientada a contexto.",
        "",
        "Classificação, evidência, decisão, aprovação e execução",
        "permanecem separadas como camadas distintas.",
        "",
        "**STATUS: PROJETO CONCLUÍDO**",
        "",
    ]

    return "\n".join(
        linhas
    )


# ================================================================
# MAIN
# ================================================================

def main():

    titulo(
        "AULA 48 V2 - FECHAMENTO E DOCUMENTACAO FINAL"
    )

    print(PROJETO)

    print(
        "Project Closure + Final Documentation"
    )

    print()

    print("Objetivo:")

    print(
        "Consolidar todos os resultados finais "
        "e gerar a documentacao do projeto."
    )

    print()

    print(
        "Nenhuma nova funcionalidade operacional sera criada."
    )

    print(
        "Nenhuma contencao sera executada."
    )

    print(
        "Nenhum IP sera bloqueado."
    )

    print(
        f"Modo operacional: "
        f"{MODO_OPERACIONAL}"
    )

    print()

    conexao = None

    validacoes = []

    try:

        # ========================================================
        # ETAPA 1
        # ========================================================

        titulo(
            "ETAPA 1 - PREPARANDO DIRETORIOS"
        )

        for nome, diretorio in [
            ("docs", DOCS_DIR),
            ("alertas", ALERTAS_DIR),
        ]:

            diretorio.mkdir(
                parents=True,
                exist_ok=True,
            )

            resultado = diretorio.exists()

            if resultado:
                ok(
                    f"Diretorio {nome} pronto"
                )
            else:
                erro(
                    f"Diretorio {nome} indisponivel"
                )

            validacoes.append(
                resultado
            )

        # ========================================================
        # ETAPA 2
        # ========================================================

        titulo(
            "ETAPA 2 - VALIDANDO ARTEFATOS ML"
        )

        ml_status = {}
        ml_disponiveis = 0

        for nome, caminho in (
            ARTEFATOS_ML.items()
        ):

            existe = (
                caminho.exists()
                and
                caminho.stat().st_size > 0
            )

            ml_status[
                nome
            ] = {
                "arquivo":
                    str(
                        caminho.relative_to(
                            BASE_DIR
                        )
                    ),

                "disponivel":
                    existe,
            }

            if existe:

                ml_disponiveis += 1

                ok(
                    f"{nome}: "
                    f"{caminho.name}"
                )

            else:

                erro(
                    f"{nome}: ausente ou vazio"
                )

        ml_esperados = len(
            ARTEFATOS_ML
        )

        print()

        print(
            f"Artefatos ML: "
            f"{ml_disponiveis}/"
            f"{ml_esperados}"
        )

        validacoes.append(
            ml_disponiveis
            == ml_esperados
        )

        # ========================================================
        # ETAPA 3
        # ========================================================

        titulo(
            "ETAPA 3 - INVENTARIO SQLITE"
        )

        if not DB_PATH.exists():

            erro(
                "Banco SQLite nao encontrado"
            )

            return

        conexao = conectar_banco()

        ok(
            "Banco SQLite encontrado"
        )

        validacoes.append(
            True
        )

        tabelas = listar_tabelas(
            conexao
        )

        print(
            f"Tabelas encontradas: "
            f"{len(tabelas)}"
        )

        inventario_tabelas = {}

        for tabela in tabelas:

            quantidade = contar_registros(
                conexao,
                tabela
            )

            colunas = obter_colunas(
                conexao,
                tabela
            )

            inventario_tabelas[
                tabela
            ] = {
                "registros":
                    quantidade,

                "colunas":
                    len(
                        colunas
                    ),
            }

            print(
                f"- {tabela}: "
                f"{quantidade} registros | "
                f"{len(colunas)} colunas"
            )

        validacoes.append(
            len(tabelas) > 0
        )

        # ========================================================
        # ETAPA 4
        # ========================================================

        titulo(
            "ETAPA 4 - OBSERVABILITY"
        )

        observability = carregar_json(
            ARQUIVO_OBSERVABILITY
        )

        observability_ok = (
            observability is not None
        )

        if observability_ok:
            ok(
                "Observability carregado"
            )
        else:
            erro(
                "Observability nao encontrado"
            )

        validacoes.append(
            observability_ok
        )

        observability_health = numero(
            (
                observability
                or {}
            )
            .get(
                "saude",
                {}
            )
            .get(
                "percentual",
                0
            )
        )

        iocs_ativos = inteiro(
            (
                observability
                or {}
            )
            .get(
                "pipeline",
                {}
            )
            .get(
                "iocs_ativos",
                0
            )
        )

        print(
            f"Health: "
            f"{observability_health:.2f}%"
        )

        print(
            f"IOCs ativos: "
            f"{iocs_ativos}"
        )

        validacoes.append(
            abs(
                observability_health
                - 100.0
            ) < 0.001
        )

        validacoes.append(
            iocs_ativos == 2
        )

        # ========================================================
        # ETAPA 5
        # ========================================================

        titulo(
            "ETAPA 5 - END-TO-END"
        )

        e2e = carregar_json(
            ARQUIVO_E2E
        )

        e2e_ok = (
            e2e is not None
        )

        if e2e_ok:
            ok(
                "End-to-End carregado"
            )
        else:
            erro(
                "End-to-End nao encontrado"
            )

        validacoes.append(
            e2e_ok
        )

        e2e_health = numero(
            (
                e2e
                or {}
            )
            .get(
                "validacoes",
                {}
            )
            .get(
                "saude",
                0
            )
        )

        lineages_completos = inteiro(
            (
                e2e
                or {}
            )
            .get(
                "estado_atual",
                {}
            )
            .get(
                "lineages_completos",
                0
            )
        )

        semantic_lineage = (
            (
                e2e
                or {}
            )
            .get(
                "semantic_lineage",
                {}
            )
        )

        decision_evidence = booleano(
            semantic_lineage.get(
                "decision_evidence",
                False
            )
        )

        mitre_consistente = booleano(
            semantic_lineage.get(
                "mitre_consistente",
                False
            )
        )

        print(
            f"Health: "
            f"{e2e_health:.2f}%"
        )

        print(
            f"Lineages completos: "
            f"{lineages_completos}"
        )

        print(
            "Decision -> Evidence: "
            f"{'SIM' if decision_evidence else 'NAO'}"
        )

        print(
            "MITRE consistente: "
            f"{'SIM' if mitre_consistente else 'NAO'}"
        )

        validacoes.extend(
            [
                abs(
                    e2e_health
                    - 100.0
                ) < 0.001,

                lineages_completos == 2,

                decision_evidence,

                mitre_consistente,
            ]
        )

        # ========================================================
        # ETAPA 6
        # ========================================================

        titulo(
            "ETAPA 6 - FINAL TEST SUITE"
        )

        testes = carregar_json(
            ARQUIVO_TESTES
        )

        testes_arquivo_ok = (
            testes is not None
        )

        if testes_arquivo_ok:
            ok(
                "Final Test Suite carregado"
            )
        else:
            erro(
                "Final Test Suite nao encontrado"
            )

        validacoes.append(
            testes_arquivo_ok
        )

        resultado_testes = (
            (
                testes
                or {}
            )
            .get(
                "resultado",
                {}
            )
        )

        testes_total = inteiro(
            resultado_testes.get(
                "testes_total",
                0
            )
        )

        testes_ok = inteiro(
            resultado_testes.get(
                "testes_ok",
                0
            )
        )

        testes_falha = inteiro(
            resultado_testes.get(
                "testes_falha",
                0
            )
        )

        cobertura = numero(
            resultado_testes.get(
                "cobertura",
                0
            )
        )

        print(
            f"Testes: "
            f"{testes_ok}/"
            f"{testes_total}"
        )

        print(
            f"Falhas: "
            f"{testes_falha}"
        )

        print(
            f"Cobertura: "
            f"{cobertura:.2f}%"
        )

        validacoes.extend(
            [
                testes_total > 0,
                testes_ok == testes_total,
                testes_falha == 0,
                abs(
                    cobertura
                    - 100.0
                ) < 0.001,
            ]
        )

        # ========================================================
        # ETAPA 7
        # ========================================================

        titulo(
            "ETAPA 7 - SEGURANCA FINAL"
        )

        seguranca_testes = (
            (
                testes
                or {}
            )
            .get(
                "seguranca",
                {}
            )
        )

        execucoes_reais = inteiro(
            seguranca_testes.get(
                "execucoes_reais",
                0
            )
        )

        bloqueios = inteiro(
            seguranca_testes.get(
                "bloqueios_automaticos",
                0
            )
        )

        modo = texto(
            seguranca_testes.get(
                "modo_operacional",
                ""
            )
        ).upper()

        checks_seguranca = [
            (
                "Zero execucoes reais",
                execucoes_reais == 0,
            ),
            (
                "Zero bloqueios automaticos",
                bloqueios == 0,
            ),
            (
                "Modo SIMULACAO",
                modo
                == MODO_OPERACIONAL,
            ),
        ]

        for descricao, resultado in (
            checks_seguranca
        ):

            if resultado:
                ok(descricao)
            else:
                erro(descricao)

            validacoes.append(
                resultado
            )

        # ========================================================
        # ETAPA 8
        # ========================================================

        titulo(
            "ETAPA 8 - INVENTARIO TECNICO"
        )

        inventario = {
            "projeto":
                PROJETO,

            "aula":
                AULA,

            "versao":
                VERSAO,

            "timestamp":
                agora_iso(),

            "machine_learning": {
                "esperados":
                    ml_esperados,

                "disponiveis":
                    ml_disponiveis,

                "artefatos":
                    ml_status,
            },

            "sqlite": {
                "arquivo":
                    str(
                        DB_PATH.relative_to(
                            BASE_DIR
                        )
                    ),

                "total_tabelas":
                    len(tabelas),

                "tabelas":
                    inventario_tabelas,
            },

            "componentes":
                COMPONENTES,

            "iocs_ativos":
                iocs_ativos,

            "observability": {
                "health":
                    observability_health,
            },

            "end_to_end": {
                "health":
                    e2e_health,

                "lineages_completos":
                    lineages_completos,

                "decision_evidence":
                    decision_evidence,

                "mitre_consistente":
                    mitre_consistente,
            },

            "testes_finais": {
                "total":
                    testes_total,

                "ok":
                    testes_ok,

                "falhas":
                    testes_falha,

                "cobertura":
                    cobertura,
            },

            "seguranca": {
                "execucoes_reais":
                    execucoes_reais,

                "bloqueios_automaticos":
                    bloqueios,

                "modo_operacional":
                    MODO_OPERACIONAL,
            },
        }

        salvar_json(
            INVENTARIO_PATH,
            inventario
        )

        ok(
            "Inventario tecnico salvo"
        )

        # ========================================================
        # ETAPA 9
        # ========================================================

        titulo(
            "ETAPA 9 - README FINAL"
        )

        salvar_texto(
            README_PATH,
            gerar_readme(
                inventario
            )
        )

        readme_ok = (
            README_PATH.exists()
            and
            README_PATH.stat().st_size > 0
        )

        if readme_ok:
            ok(
                "README_FINAL.md criado"
            )
        else:
            erro(
                "Falha ao criar README_FINAL.md"
            )

        validacoes.append(
            readme_ok
        )

        # ========================================================
        # ETAPA 10
        # ========================================================

        titulo(
            "ETAPA 10 - ARQUITETURA FINAL"
        )

        salvar_texto(
            ARQUITETURA_PATH,
            gerar_arquitetura(
                inventario
            )
        )

        arquitetura_ok = (
            ARQUITETURA_PATH.exists()
            and
            ARQUITETURA_PATH.stat().st_size > 0
        )

        if arquitetura_ok:
            ok(
                "ARQUITETURA_FINAL.md criada"
            )
        else:
            erro(
                "Falha ao criar arquitetura"
            )

        validacoes.append(
            arquitetura_ok
        )

        # ========================================================
        # ETAPA 11
        # ========================================================

        titulo(
            "ETAPA 11 - RESUMO EXECUTIVO"
        )

        salvar_texto(
            RESUMO_PATH,
            gerar_resumo(
                inventario
            )
        )

        resumo_ok = (
            RESUMO_PATH.exists()
            and
            RESUMO_PATH.stat().st_size > 0
        )

        if resumo_ok:
            ok(
                "RESUMO_EXECUTIVO.md criado"
            )
        else:
            erro(
                "Falha ao criar resumo executivo"
            )

        validacoes.append(
            resumo_ok
        )

        # ========================================================
        # ETAPA 12
        # ========================================================

        titulo(
            "ETAPA 12 - VALIDANDO DOCUMENTACAO"
        )

        documentos = {
            "README_FINAL.md":
                README_PATH,

            "ARQUITETURA_FINAL.md":
                ARQUITETURA_PATH,

            "RESUMO_EXECUTIVO.md":
                RESUMO_PATH,

            "inventario_tecnico.json":
                INVENTARIO_PATH,
        }

        for nome, caminho in (
            documentos.items()
        ):

            resultado = (
                caminho.exists()
                and
                caminho.stat().st_size > 0
            )

            if resultado:
                ok(
                    f"{nome} valido"
                )
            else:
                erro(
                    f"{nome} ausente/vazio"
                )

            validacoes.append(
                resultado
            )

        # ========================================================
        # ETAPA 13
        # ========================================================

        titulo(
            "ETAPA 13 - VALIDACAO DE FECHAMENTO"
        )

        total_validacoes = len(
            validacoes
        )

        validacoes_ok = sum(
            1
            for resultado
            in validacoes
            if resultado
        )

        falhas_validacao = (
            total_validacoes
            - validacoes_ok
        )

        health_final = (
            (
                validacoes_ok
                / total_validacoes
            )
            * 100
            if total_validacoes
            else 0.0
        )

        print(
            f"Validacoes: "
            f"{validacoes_ok}/"
            f"{total_validacoes}"
        )

        print(
            f"Falhas: "
            f"{falhas_validacao}"
        )

        print(
            f"Project Health: "
            f"{health_final:.2f}%"
        )

        status = (
            "PROJETO CONCLUIDO"
            if falhas_validacao == 0
            else
            "PROJETO COM PENDENCIAS"
        )

        if falhas_validacao == 0:

            ok(
                "Todas as validacoes de fechamento foram aprovadas"
            )

        else:

            erro(
                "Existem pendencias no fechamento"
            )

        # ========================================================
        # ETAPA 14
        # ========================================================

        titulo(
            "ETAPA 14 - REGISTRANDO PROJECT CLOSURE"
        )

        criar_tabela_fechamento(
            conexao
        )

        closure_id = gerar_id(
            "CLOSE-48-V2"
        )

        persistir_fechamento(
            conexao,
            {
                "closure_id":
                    closure_id,

                "timestamp":
                    agora_iso(),

                "artefatos_ml":
                    ml_disponiveis,

                "tabelas_sqlite":
                    len(tabelas),

                "iocs_ativos":
                    iocs_ativos,

                "testes_total":
                    testes_total,

                "testes_ok":
                    testes_ok,

                "testes_falha":
                    testes_falha,

                "cobertura_testes":
                    cobertura,

                "end_to_end_health":
                    e2e_health,

                "observability_health":
                    observability_health,

                "execucoes_reais":
                    execucoes_reais,

                "bloqueios_automaticos":
                    bloqueios,

                "status":
                    status,
            }
        )

        ok(
            f"Closure ID: "
            f"{closure_id}"
        )

        # ========================================================
        # ETAPA 15
        # ========================================================

        titulo(
            "ETAPA 15 - RELATORIO FINAL"
        )

        relatorio = {
            "projeto":
                PROJETO,

            "aula":
                AULA,

            "versao":
                VERSAO,

            "closure_id":
                closure_id,

            "timestamp":
                agora_iso(),

            "machine_learning":
                f"{ml_disponiveis}/"
                f"{ml_esperados}",

            "tabelas_sqlite":
                len(tabelas),

            "iocs_ativos":
                iocs_ativos,

            "observability_health":
                observability_health,

            "end_to_end_health":
                e2e_health,

            "lineages_completos":
                lineages_completos,

            "decision_evidence":
                decision_evidence,

            "mitre_consistente":
                mitre_consistente,

            "testes": {
                "total":
                    testes_total,

                "ok":
                    testes_ok,

                "falhas":
                    testes_falha,

                "cobertura":
                    cobertura,
            },

            "seguranca": {
                "execucoes_reais":
                    execucoes_reais,

                "bloqueios_automaticos":
                    bloqueios,

                "modo_operacional":
                    MODO_OPERACIONAL,
            },

            "documentacao": {
                "readme":
                    str(
                        README_PATH.relative_to(
                            BASE_DIR
                        )
                    ),

                "arquitetura":
                    str(
                        ARQUITETURA_PATH.relative_to(
                            BASE_DIR
                        )
                    ),

                "resumo":
                    str(
                        RESUMO_PATH.relative_to(
                            BASE_DIR
                        )
                    ),

                "inventario":
                    str(
                        INVENTARIO_PATH.relative_to(
                            BASE_DIR
                        )
                    ),
            },

            "validacao_fechamento": {
                "total":
                    total_validacoes,

                "ok":
                    validacoes_ok,

                "falhas":
                    falhas_validacao,

                "health":
                    round(
                        health_final,
                        2
                    ),
            },

            "status":
                status,
        }

        salvar_json(
            RELATORIO_PATH,
            relatorio
        )

        ok(
            "Relatorio Aula 48 salvo"
        )

        print(
            "Arquivo: "
            "alertas\\relatorio_aula_48.json"
        )

        # ========================================================
        # RESUMO FINAL
        # ========================================================

        titulo(
            "RESUMO FINAL - CYBERSENTINEL-ML"
        )

        print(
            f"Projeto: "
            f"{PROJETO}"
        )

        print(
            f"Closure ID: "
            f"{closure_id}"
        )

        print()

        print(
            f"Artefatos ML: "
            f"{ml_disponiveis}/"
            f"{ml_esperados}"
        )

        print(
            f"Tabelas SQLite: "
            f"{len(tabelas)}"
        )

        print(
            f"IOCs ativos: "
            f"{iocs_ativos}"
        )

        print()

        print(
            "Observability Health: "
            f"{observability_health:.2f}%"
        )

        print(
            "End-to-End Health: "
            f"{e2e_health:.2f}%"
        )

        print(
            f"Lineages completos: "
            f"{lineages_completos}"
        )

        print()

        print(
            "Decision -> Evidence: "
            f"{'SIM' if decision_evidence else 'NAO'}"
        )

        print(
            "MITRE consistente: "
            f"{'SIM' if mitre_consistente else 'NAO'}"
        )

        print()

        print(
            f"Testes finais: "
            f"{testes_ok}/"
            f"{testes_total}"
        )

        print(
            f"Falhas: "
            f"{testes_falha}"
        )

        print(
            f"Cobertura: "
            f"{cobertura:.2f}%"
        )

        print()

        print(
            f"Execucoes reais: "
            f"{execucoes_reais}"
        )

        print(
            f"Bloqueios automaticos: "
            f"{bloqueios}"
        )

        print(
            f"Modo operacional: "
            f"{MODO_OPERACIONAL}"
        )

        print()

        print(
            "Documentacao gerada:"
        )

        print(
            "- README_FINAL.md"
        )

        print(
            "- docs\\ARQUITETURA_FINAL.md"
        )

        print(
            "- docs\\RESUMO_EXECUTIVO.md"
        )

        print(
            "- docs\\inventario_tecnico.json"
        )

        print(
            "- alertas\\relatorio_aula_48.json"
        )

        print()

        print(
            f"Validacoes fechamento: "
            f"{validacoes_ok}/"
            f"{total_validacoes}"
        )

        print(
            f"Project Health: "
            f"{health_final:.2f}%"
        )

        print()

        print(
            f"STATUS: "
            f"{status}"
        )

        # ========================================================
        # ARQUITETURA VISUAL
        # ========================================================

        titulo(
            "ARQUITETURA FINAL DO PROJETO"
        )

        arquitetura_terminal = [
            "",
            "                    CYBERSENTINEL-ML",
            "                           |",
            "                           v",
            "                    MACHINE LEARNING",
            "                           |",
            "                           v",
            "                 THREAT INTELLIGENCE",
            "                           |",
            "                           v",
            "                     IOC ENRICHMENT",
            "                           |",
            "                           v",
            "                      RISK SCORE V2",
            "                           |",
            "                           v",
            "                HISTORICAL CORRELATION",
            "                           |",
            "                           v",
            "                  CAMPAIGN DETECTION",
            "                           |",
            "                           v",
            "                   INCIDENT TIMELINE",
            "                           |",
            "                           v",
            "                  INCIDENT RESPONSE",
            "                           |",
            "                           v",
            "                 MITRE ATT&CK CONTEXT",
            "                           |",
            "                           v",
            "                  INCIDENT EVIDENCE",
            "                           |",
            "                           v",
            "                 SOC DECISION ENGINE",
            "                           |",
            "                           v",
            "                   CASE MANAGEMENT",
            "                           |",
            "                           v",
            "                    CASE LIFECYCLE",
            "                           |",
            "                           v",
            "                  HUMAN APPROVAL GATE",
            "                           |",
            "                           v",
            "                METRICS & OBSERVABILITY",
            "                           |",
            "                           v",
            "                 END-TO-END VALIDATION",
            "                           |",
            "                           v",
            "                    FINAL TEST SUITE",
            "                           |",
            "                           v",
            "                    PROJECT CLOSURE",
            "",
            "                  SEGURANCA PRESERVADA",
            "",
            f"Execucao real .............. {execucoes_reais}",
            f"Bloqueio automatico ........ {bloqueios}",
            "Contencao real ............. NAO",
            "Firewall ................... NAO ALTERADO",
            f"Modo ....................... {MODO_OPERACIONAL}",
            "",
        ]

        print(
            "\n".join(
                arquitetura_terminal
            )
        )

        linha()
        print(PROJETO)
        linha()

        print(
            "AULA 48 V2 - FECHAMENTO E DOCUMENTACAO FINAL"
        )

        print(
            status
        )

    except sqlite3.Error as excecao:

        titulo(
            "ERRO SQLITE - AULA 48 V2"
        )

        erro(
            str(excecao)
        )

        print(
            "Status: PROJETO COM PENDENCIAS"
        )

    except Exception as excecao:

        titulo(
            "ERRO INESPERADO - AULA 48 V2"
        )

        erro(
            f"{type(excecao).__name__}: "
            f"{excecao}"
        )

        print(
            "Status: PROJETO COM PENDENCIAS"
        )

    finally:

        if conexao is not None:
            conexao.close()


# ================================================================
# EXECUCAO
# ================================================================

if __name__ == "__main__":
    main()