# ================================================================
# AULA 42 - SOC CASE MANAGEMENT / INCIDENT CASE BUILDER
# CyberSentinel-ML
#
# Versao corrigida V2
# Case Management + Safety Validation Integration
#
# IMPORTANTE:
# - Nenhuma contencao e executada.
# - Nenhum IP e bloqueado automaticamente.
# - PREPARAR_CONTENCAO significa somente preparar o contexto
#   para avaliacao/aprovacao humana.
# - O sistema permanece em modo SIMULACAO.
# ================================================================

import os
import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path


# ================================================================
# CONFIGURACOES
# ================================================================

BASE_DIR = Path(__file__).resolve().parent

DADOS_DIR = BASE_DIR / "dados"
CASOS_DIR = BASE_DIR / "casos"
ALERTAS_DIR = BASE_DIR / "alertas"

BANCO_SQLITE = DADOS_DIR / "cybersentinel.db"

ARQUIVO_CASOS = CASOS_DIR / "casos_soc_aula_42.json"
ARQUIVO_ALERTAS = ALERTAS_DIR / "alertas_case_management_aula_42.json"
ARQUIVO_RELATORIO = ALERTAS_DIR / "relatorio_aula_42.json"

MODO_OPERACIONAL = "SIMULACAO"

TABELA_DECISOES = "soc_incident_decisions"
TABELA_EVIDENCIAS = "incident_evidence"
TABELA_TIMELINES = "incident_timelines"
TABELA_CAMPANHAS = "campanhas_ioc"
TABELA_PLAYBOOKS = "incident_response_playbooks"
TABELA_MITRE = "mitre_attack_mapping"
TABELA_CASOS = "soc_incident_cases"


# ================================================================
# FUNCOES AUXILIARES
# ================================================================

def linha():
    print("=" * 72)


def separador():
    print("-" * 72)


def agora_iso():
    return datetime.now(timezone.utc).isoformat()


def gerar_id(prefixo):
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f")
    sufixo = uuid.uuid4().hex[:8].upper()
    return f"{prefixo}-{timestamp}-{sufixo}"


def valor_seguro(valor, padrao=None):
    if valor is None:
        return padrao
    return valor


def numero(valor, padrao=0.0):
    try:
        if valor is None:
            return padrao
        return float(valor)
    except (ValueError, TypeError):
        return padrao


def inteiro(valor, padrao=0):
    try:
        if valor is None:
            return padrao
        return int(valor)
    except (ValueError, TypeError):
        return padrao


def sim_nao(valor):
    return "SIM" if bool(valor) else "NAO"


def salvar_json(caminho, dados):
    caminho.parent.mkdir(parents=True, exist_ok=True)

    with open(caminho, "w", encoding="utf-8") as arquivo:
        json.dump(
            dados,
            arquivo,
            indent=4,
            ensure_ascii=False,
            default=str
        )


# ================================================================
# SQLITE
# ================================================================

def tabela_existe(conexao, tabela):
    cursor = conexao.cursor()

    cursor.execute(
        """
        SELECT name
        FROM sqlite_master
        WHERE type = 'table'
          AND name = ?
        """,
        (tabela,)
    )

    return cursor.fetchone() is not None


def obter_colunas(conexao, tabela):
    cursor = conexao.cursor()

    cursor.execute(f"PRAGMA table_info({tabela})")

    return [registro[1] for registro in cursor.fetchall()]


def carregar_tabela(conexao, tabela):
    if not tabela_existe(conexao, tabela):
        return []

    conexao.row_factory = sqlite3.Row

    cursor = conexao.cursor()
    cursor.execute(f"SELECT * FROM {tabela}")

    return [dict(registro) for registro in cursor.fetchall()]


def criar_tabela_casos(conexao):
    cursor = conexao.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS soc_incident_cases (
            case_id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            ip_origem TEXT NOT NULL,

            decision_id TEXT,
            decision_score REAL,
            prioridade_soc TEXT,
            classificacao_decisao TEXT,
            sla TEXT,

            evidence_id TEXT,
            evidence_score REAL,
            risk_score_maximo REAL,

            campanha_detectada INTEGER DEFAULT 0,
            campaign_score REAL DEFAULT 0,
            nivel_campanha TEXT,

            timeline_id TEXT,
            status_timeline TEXT,
            tendencia_timeline TEXT,

            playbook_id TEXT,
            prioridade_playbook TEXT,
            acao_playbook TEXT,

            mitre_contexto TEXT,
            mitre_tatica TEXT,
            mitre_technique_id TEXT,
            mitre_confianca TEXT,

            status_caso TEXT,
            fase TEXT,
            owner TEXT,

            requer_analista INTEGER DEFAULT 0,
            requer_escalacao INTEGER DEFAULT 0,
            preparar_contencao INTEGER DEFAULT 0,
            bloqueio_automatico INTEGER DEFAULT 0,

            modo_operacional TEXT NOT NULL,
            historico_json TEXT,
            criado_em TEXT
        )
        """
    )

    conexao.commit()


def migrar_tabela_casos(conexao):
    colunas_necessarias = {
        "case_id": "TEXT",
        "timestamp": "TEXT",
        "ip_origem": "TEXT",

        "decision_id": "TEXT",
        "decision_score": "REAL",
        "prioridade_soc": "TEXT",
        "classificacao_decisao": "TEXT",
        "sla": "TEXT",

        "evidence_id": "TEXT",
        "evidence_score": "REAL",
        "risk_score_maximo": "REAL",

        "campanha_detectada": "INTEGER DEFAULT 0",
        "campaign_score": "REAL DEFAULT 0",
        "nivel_campanha": "TEXT",

        "timeline_id": "TEXT",
        "status_timeline": "TEXT",
        "tendencia_timeline": "TEXT",

        "playbook_id": "TEXT",
        "prioridade_playbook": "TEXT",
        "acao_playbook": "TEXT",

        "mitre_contexto": "TEXT",
        "mitre_tatica": "TEXT",
        "mitre_technique_id": "TEXT",
        "mitre_confianca": "TEXT",

        "status_caso": "TEXT",
        "fase": "TEXT",
        "owner": "TEXT",

        "requer_analista": "INTEGER DEFAULT 0",
        "requer_escalacao": "INTEGER DEFAULT 0",
        "preparar_contencao": "INTEGER DEFAULT 0",
        "bloqueio_automatico": "INTEGER DEFAULT 0",

        "modo_operacional": "TEXT",
        "historico_json": "TEXT",
        "criado_em": "TEXT"
    }

    colunas_existentes = obter_colunas(conexao, TABELA_CASOS)

    cursor = conexao.cursor()

    for coluna, tipo in colunas_necessarias.items():
        if coluna not in colunas_existentes:
            cursor.execute(
                f"ALTER TABLE {TABELA_CASOS} "
                f"ADD COLUMN {coluna} {tipo}"
            )

    conexao.commit()


# ================================================================
# BUSCA FLEXIVEL DE CAMPOS
# ================================================================

def campo(registro, nomes, padrao=None):
    if not registro:
        return padrao

    for nome in nomes:
        if nome in registro and registro[nome] is not None:
            return registro[nome]

    return padrao


def obter_ip(registro):
    return str(
        campo(
            registro,
            [
                "ip_origem",
                "ioc",
                "ioc_value",
                "valor_ioc",
                "ip"
            ],
            ""
        )
    ).strip()


# ================================================================
# INDEXACAO
# ================================================================

def indexar_por_ioc(registros):
    indice = {}

    for registro in registros:
        ip = obter_ip(registro)

        if not ip:
            continue

        indice.setdefault(ip, []).append(registro)

    return indice


def escolher_mais_recente(registros):
    if not registros:
        return {}

    def chave(registro):
        return str(
            campo(
                registro,
                [
                    "timestamp",
                    "criado_em",
                    "created_at",
                    "data_criacao"
                ],
                ""
            )
        )

    return sorted(registros, key=chave)[-1]


def escolher_maior_score(registros, campos_score):
    if not registros:
        return {}

    return max(
        registros,
        key=lambda r: numero(campo(r, campos_score, 0))
    )


# ================================================================
# DECISOES
# ================================================================

def deduplicar_decisoes(decisoes):
    por_ioc = indexar_por_ioc(decisoes)

    resultado = []

    for ip, registros in por_ioc.items():
        melhor = escolher_maior_score(
            registros,
            [
                "decision_score",
                "score_decisao",
                "score"
            ]
        )

        resultado.append(melhor)

    resultado.sort(
        key=lambda r: numero(
            campo(
                r,
                ["decision_score", "score_decisao", "score"],
                0
            )
        ),
        reverse=True
    )

    return resultado


# ================================================================
# CAMPANHA
# ================================================================

def extrair_campanha(registros):
    if not registros:
        return {
            "detectada": False,
            "score": 0.0,
            "nivel": "NAO_DISPONIVEL"
        }

    melhor = escolher_maior_score(
        registros,
        [
            "score_campanha",
            "campaign_score",
            "score"
        ]
    )

    status = str(
        campo(
            melhor,
            [
                "status",
                "status_campanha",
                "campaign_status"
            ],
            ""
        )
    ).upper()

    detectada_campo = campo(
        melhor,
        [
            "campanha_detectada",
            "detectada",
            "is_campaign"
        ],
        None
    )

    if detectada_campo is None:
        detectada = "CAMPANHA_DETECTADA" in status
    else:
        detectada = bool(inteiro(detectada_campo, 0))

    return {
        "detectada": detectada,
        "score": numero(
            campo(
                melhor,
                [
                    "score_campanha",
                    "campaign_score",
                    "score"
                ],
                0
            )
        ),
        "nivel": str(
            campo(
                melhor,
                [
                    "nivel",
                    "nivel_campanha",
                    "campaign_level"
                ],
                "BAIXO"
            )
        )
    }


# ================================================================
# EVIDENCIA
# ================================================================

def extrair_evidencia(registros):
    if not registros:
        return {}

    melhor = escolher_maior_score(
        registros,
        [
            "evidence_score",
            "score_evidencia"
        ]
    )

    return {
        "id": campo(
            melhor,
            [
                "evidence_id",
                "id_evidencia"
            ],
            "NAO_DISPONIVEL"
        ),

        "score": numero(
            campo(
                melhor,
                [
                    "evidence_score",
                    "score_evidencia"
                ],
                0
            )
        ),

        "risk_score_maximo": numero(
            campo(
                melhor,
                [
                    "risk_score_maximo",
                    "max_risk_score",
                    "risk_score"
                ],
                0
            )
        )
    }


# ================================================================
# TIMELINE
# ================================================================

def extrair_timeline(registros):
    if not registros:
        return {}

    melhor = escolher_maior_score(
        registros,
        [
            "score_maximo",
            "risk_score_maximo",
            "risk_score_final"
        ]
    )

    return {
        "id": campo(
            melhor,
            [
                "timeline_id",
                "id_timeline"
            ],
            "NAO_DISPONIVEL"
        ),

        "status": campo(
            melhor,
            [
                "status",
                "status_incidente",
                "status_timeline"
            ],
            "NAO_DISPONIVEL"
        ),

        "tendencia": campo(
            melhor,
            [
                "tendencia",
                "tendencia_risco"
            ],
            "NAO_DISPONIVEL"
        )
    }


# ================================================================
# PLAYBOOK
# ================================================================

def extrair_playbook(registros):
    if not registros:
        return {}

    ordem = {
        "BAIXO": 1,
        "MEDIO": 2,
        "ALTO": 3,
        "CRITICO": 4
    }

    melhor = max(
        registros,
        key=lambda r: ordem.get(
            str(
                campo(
                    r,
                    [
                        "prioridade",
                        "prioridade_playbook"
                    ],
                    "BAIXO"
                )
            ).upper(),
            0
        )
    )

    return {
        "id": campo(
            melhor,
            [
                "playbook_id",
                "id_playbook"
            ],
            "NAO_DISPONIVEL"
        ),

        "prioridade": str(
            campo(
                melhor,
                [
                    "prioridade",
                    "prioridade_playbook"
                ],
                "NAO_DISPONIVEL"
            )
        ),

        "acao": str(
            campo(
                melhor,
                [
                    "acao_recomendada",
                    "acao",
                    "action"
                ],
                "NAO_DISPONIVEL"
            )
        )
    }


# ================================================================
# MITRE
# ================================================================

def extrair_mitre(registros):
    if not registros:
        return {}

    ordem_confianca = {
        "INSUFICIENTE": 1,
        "CONTEXTUAL": 2,
        "PROVAVEL": 3,
        "CONFIRMADA": 4,
        "CONFIRMADO": 4
    }

    melhor = max(
        registros,
        key=lambda r: ordem_confianca.get(
            str(
                campo(
                    r,
                    [
                        "confianca",
                        "confianca_mapping",
                        "mapping_confidence"
                    ],
                    "INSUFICIENTE"
                )
            ).upper(),
            0
        )
    )

    return {
        "contexto": campo(
            melhor,
            [
                "contexto",
                "contexto_ataque"
            ],
            "NAO_ATRIBUIDO"
        ),

        "tatica": campo(
            melhor,
            [
                "tatica",
                "tatica_candidata"
            ],
            "NAO_ATRIBUIDA"
        ),

        "technique_id": campo(
            melhor,
            [
                "technique_id",
                "mitre_technique_id"
            ],
            "NAO_ATRIBUIDA"
        ),

        "confianca": campo(
            melhor,
            [
                "confianca",
                "confianca_mapping"
            ],
            "INSUFICIENTE"
        )
    }


# ================================================================
# LOGICA DO CASE MANAGEMENT
# ================================================================

def construir_politica_caso(
    prioridade,
    classificacao,
    timeline_status,
    playbook_prioridade,
    playbook_acao
):
    prioridade = str(prioridade).upper()
    classificacao = str(classificacao).upper()
    timeline_status = str(timeline_status).upper()
    playbook_prioridade = str(playbook_prioridade).upper()
    playbook_acao = str(playbook_acao).upper()

    # ------------------------------------------------------------
    # REGRA PRINCIPAL
    #
    # PREPARAR_CONTENCAO != EXECUTAR_CONTENCAO
    #
    # Um caso critico deve preparar informacoes, evidencias e
    # recomendacoes para eventual contencao APROVADA POR HUMANO.
    #
    # Nenhuma acao automatica e executada.
    # ------------------------------------------------------------

    caso_critico = (
        prioridade == "CRITICO"
        or classificacao == "INCIDENTE_PRIORITARIO"
        or timeline_status == "INCIDENTE_CRITICO"
        or playbook_prioridade == "CRITICO"
    )

    caso_alto = (
        prioridade == "ALTO"
        or playbook_prioridade == "ALTO"
    )

    if caso_critico:
        return {
            "status_caso": "ABERTO_PRIORITARIO",
            "fase": "ESCALACAO",
            "owner": "SOC_ANALYST_ESCALATION",
            "requer_analista": True,
            "requer_escalacao": True,

            # CORRECAO PRINCIPAL DA AULA 42
            "preparar_contencao": True,

            # NUNCA executar automaticamente
            "bloqueio_automatico": False
        }

    if caso_alto:
        return {
            "status_caso": "ABERTO",
            "fase": "INVESTIGACAO",
            "owner": "SOC_ANALYST_QUEUE",
            "requer_analista": True,
            "requer_escalacao": False,
            "preparar_contencao": False,
            "bloqueio_automatico": False
        }

    if prioridade == "MEDIO":
        return {
            "status_caso": "ABERTO",
            "fase": "TRIAGEM",
            "owner": "SOC_TRIAGE_QUEUE",
            "requer_analista": True,
            "requer_escalacao": False,
            "preparar_contencao": False,
            "bloqueio_automatico": False
        }

    return {
        "status_caso": "MONITORAMENTO",
        "fase": "MONITORAMENTO",
        "owner": "SOC_MONITORING_QUEUE",
        "requer_analista": False,
        "requer_escalacao": False,
        "preparar_contencao": False,
        "bloqueio_automatico": False
    }


# ================================================================
# PERSISTENCIA
# ================================================================

def persistir_caso(conexao, caso):
    cursor = conexao.cursor()

    cursor.execute(
        """
        INSERT OR REPLACE INTO soc_incident_cases (
            case_id,
            timestamp,
            ip_origem,

            decision_id,
            decision_score,
            prioridade_soc,
            classificacao_decisao,
            sla,

            evidence_id,
            evidence_score,
            risk_score_maximo,

            campanha_detectada,
            campaign_score,
            nivel_campanha,

            timeline_id,
            status_timeline,
            tendencia_timeline,

            playbook_id,
            prioridade_playbook,
            acao_playbook,

            mitre_contexto,
            mitre_tatica,
            mitre_technique_id,
            mitre_confianca,

            status_caso,
            fase,
            owner,

            requer_analista,
            requer_escalacao,
            preparar_contencao,
            bloqueio_automatico,

            modo_operacional,
            historico_json,
            criado_em
        )
        VALUES (
            ?, ?, ?,
            ?, ?, ?, ?, ?,
            ?, ?, ?,
            ?, ?, ?,
            ?, ?, ?,
            ?, ?, ?,
            ?, ?, ?, ?,
            ?, ?, ?,
            ?, ?, ?, ?,
            ?, ?, ?
        )
        """,
        (
            caso["case_id"],
            caso["timestamp"],
            caso["ip_origem"],

            caso["decision_id"],
            caso["decision_score"],
            caso["prioridade_soc"],
            caso["classificacao_decisao"],
            caso["sla"],

            caso["evidence_id"],
            caso["evidence_score"],
            caso["risk_score_maximo"],

            int(caso["campanha_detectada"]),
            caso["campaign_score"],
            caso["nivel_campanha"],

            caso["timeline_id"],
            caso["status_timeline"],
            caso["tendencia_timeline"],

            caso["playbook_id"],
            caso["prioridade_playbook"],
            caso["acao_playbook"],

            caso["mitre_contexto"],
            caso["mitre_tatica"],
            caso["mitre_technique_id"],
            caso["mitre_confianca"],

            caso["status_caso"],
            caso["fase"],
            caso["owner"],

            int(caso["requer_analista"]),
            int(caso["requer_escalacao"]),
            int(caso["preparar_contencao"]),
            int(caso["bloqueio_automatico"]),

            caso["modo_operacional"],
            json.dumps(
                caso["historico"],
                ensure_ascii=False
            ),
            caso["criado_em"]
        )
    )

    conexao.commit()


# ================================================================
# MAIN
# ================================================================

def main():

    linha()
    print("AULA 42 - SOC CASE MANAGEMENT / INCIDENT CASE BUILDER")
    linha()

    print("CyberSentinel-ML")
    print("Decision Engine + Incident Case Management")
    print("Versao corrigida V2 - Safety Validation Integration")
    print()
    print("Objetivo:")
    print("Transformar decisoes priorizadas do SOC em casos")
    print("estruturados para acompanhamento operacional.")
    print()
    print("IMPORTANTE:")
    print("Nenhuma contencao sera executada.")
    print("Nenhum IP sera bloqueado automaticamente.")
    print("Preparar contencao significa preparar contexto para analise humana.")
    print("O sistema permanece em modo SIMULACAO.")
    print()

    # ============================================================
    # ETAPA 1
    # ============================================================

    linha()
    print("ETAPA 1 - PREPARANDO DIRETORIOS")
    linha()

    for nome, diretorio in [
        ("dados", DADOS_DIR),
        ("casos", CASOS_DIR),
        ("alertas", ALERTAS_DIR)
    ]:
        diretorio.mkdir(parents=True, exist_ok=True)
        print(f"[OK] Diretorio {nome} pronto")

    # ============================================================
    # ETAPA 2
    # ============================================================

    linha()
    print("ETAPA 2 - VALIDANDO SQLITE")
    linha()

    if not BANCO_SQLITE.exists():
        print("[ERRO] Banco SQLite nao encontrado")
        print(f"Banco esperado: {BANCO_SQLITE}")
        return

    print("[OK] Banco SQLite encontrado")
    print(f"Banco: {os.path.relpath(BANCO_SQLITE, BASE_DIR)}")

    conexao = sqlite3.connect(BANCO_SQLITE)
    conexao.row_factory = sqlite3.Row

    # ============================================================
    # ETAPA 3
    # ============================================================

    linha()
    print("ETAPA 3 - VALIDANDO PIPELINE ANTERIOR")
    linha()

    tabelas_necessarias = [
        TABELA_DECISOES,
        TABELA_EVIDENCIAS,
        TABELA_TIMELINES,
        TABELA_CAMPANHAS,
        TABELA_PLAYBOOKS,
        TABELA_MITRE
    ]

    pipeline_ok = True

    for tabela in tabelas_necessarias:
        if tabela_existe(conexao, tabela):
            print(f"[OK] Tabela encontrada: {tabela}")
        else:
            print(f"[ERRO] Tabela ausente: {tabela}")
            pipeline_ok = False

    if not pipeline_ok:
        conexao.close()
        return

    # ============================================================
    # ETAPA 4
    # ============================================================

    linha()
    print("ETAPA 4 - VALIDANDO SCHEMA DA AULA 41")
    linha()

    colunas_decisao = obter_colunas(
        conexao,
        TABELA_DECISOES
    )

    print(f"[OK] Colunas detectadas: {len(colunas_decisao)}")

    obrigatorias = [
        "ip_origem",
        "decision_score",
        "prioridade_soc"
    ]

    schema_decisao_ok = True

    for coluna in obrigatorias:
        if coluna in colunas_decisao:
            print(f"[OK] Coluna encontrada: {coluna}")
        else:
            print(f"[ERRO] Coluna ausente: {coluna}")
            schema_decisao_ok = False

    if not schema_decisao_ok:
        conexao.close()
        return

    # ============================================================
    # ETAPA 5
    # ============================================================

    linha()
    print("ETAPA 5 - PREPARANDO CASE MANAGEMENT")
    linha()

    criar_tabela_casos(conexao)

    print("[OK] Tabela soc_incident_cases localizada/criada")

    migrar_tabela_casos(conexao)

    print("[OK] Schema Case Management compativel")

    colunas_casos = obter_colunas(
        conexao,
        TABELA_CASOS
    )

    print(
        f"[OK] Colunas soc_incident_cases: "
        f"{len(colunas_casos)}"
    )

    # ============================================================
    # ETAPA 6
    # ============================================================

    linha()
    print("ETAPA 6 - CARREGANDO CONTEXTO DO PIPELINE")
    linha()

    decisoes = carregar_tabela(
        conexao,
        TABELA_DECISOES
    )

    evidencias = carregar_tabela(
        conexao,
        TABELA_EVIDENCIAS
    )

    timelines = carregar_tabela(
        conexao,
        TABELA_TIMELINES
    )

    campanhas = carregar_tabela(
        conexao,
        TABELA_CAMPANHAS
    )

    playbooks = carregar_tabela(
        conexao,
        TABELA_PLAYBOOKS
    )

    mitre = carregar_tabela(
        conexao,
        TABELA_MITRE
    )

    print(
        f"[OK] soc_incident_decisions: "
        f"{len(decisoes)} registros"
    )

    print(
        f"[OK] incident_evidence: "
        f"{len(evidencias)} registros"
    )

    print(
        f"[OK] incident_timelines: "
        f"{len(timelines)} registros"
    )

    print(
        f"[OK] campanhas_ioc: "
        f"{len(campanhas)} registros"
    )

    print(
        f"[OK] incident_response_playbooks: "
        f"{len(playbooks)} registros"
    )

    print(
        f"[OK] mitre_attack_mapping: "
        f"{len(mitre)} registros"
    )

    # ============================================================
    # ETAPA 7
    # ============================================================

    linha()
    print("ETAPA 7 - DEDUPLICANDO DECISOES POR IOC")
    linha()

    decisoes_unicas = deduplicar_decisoes(decisoes)

    print(
        f"[OK] IOCs unicos com decisao: "
        f"{len(decisoes_unicas)}"
    )

    for decisao in decisoes_unicas:

        ip = obter_ip(decisao)

        score = numero(
            campo(
                decisao,
                ["decision_score"],
                0
            )
        )

        prioridade = campo(
            decisao,
            ["prioridade_soc"],
            "DESCONHECIDO"
        )

        print(
            f"- {ip} | "
            f"Decision Score: {score:.2f} | "
            f"{prioridade}"
        )

    # ============================================================
    # ETAPA 8
    # ============================================================

    linha()
    print("ETAPA 8 - INDEXANDO CONTEXTO POR IOC")
    linha()

    indice_evidencias = indexar_por_ioc(evidencias)
    indice_timelines = indexar_por_ioc(timelines)
    indice_campanhas = indexar_por_ioc(campanhas)
    indice_playbooks = indexar_por_ioc(playbooks)
    indice_mitre = indexar_por_ioc(mitre)

    print("[OK] Contexto indexado")

    # ============================================================
    # ETAPA 9
    # ============================================================

    linha()
    print("ETAPA 9 - CONSTRUINDO CASOS SOC")
    linha()

    casos = []
    alertas = []

    for indice, decisao in enumerate(
        decisoes_unicas,
        start=1
    ):
        separador()

        print(
            f"CASO {indice}/{len(decisoes_unicas)}"
        )

        separador()

        ip = obter_ip(decisao)

        decision_score = numero(
            campo(
                decisao,
                ["decision_score"],
                0
            )
        )

        prioridade = str(
            campo(
                decisao,
                ["prioridade_soc"],
                "BAIXO"
            )
        ).upper()

        classificacao = str(
            campo(
                decisao,
                [
                    "classificacao",
                    "classificacao_decisao",
                    "decision_class"
                ],
                (
                    "INCIDENTE_PRIORITARIO"
                    if prioridade == "CRITICO"
                    else "MONITORAMENTO"
                )
            )
        )

        sla = str(
            campo(
                decisao,
                ["sla", "sla_recomendado"],
                (
                    "IMEDIATO"
                    if prioridade == "CRITICO"
                    else "ATE_8_HORAS"
                )
            )
        )

        decision_id = str(
            campo(
                decisao,
                [
                    "decision_id",
                    "id_decisao"
                ],
                "NAO_DISPONIVEL"
            )
        )

        evidencia = extrair_evidencia(
            indice_evidencias.get(ip, [])
        )

        campanha = extrair_campanha(
            indice_campanhas.get(ip, [])
        )

        timeline = extrair_timeline(
            indice_timelines.get(ip, [])
        )

        playbook = extrair_playbook(
            indice_playbooks.get(ip, [])
        )

        contexto_mitre = extrair_mitre(
            indice_mitre.get(ip, [])
        )

        politica = construir_politica_caso(
            prioridade=prioridade,
            classificacao=classificacao,
            timeline_status=timeline.get(
                "status",
                ""
            ),
            playbook_prioridade=playbook.get(
                "prioridade",
                ""
            ),
            playbook_acao=playbook.get(
                "acao",
                ""
            )
        )

        case_id = gerar_id("CASE-42")

        historico = [
            {
                "timestamp": agora_iso(),
                "evento": "CASO_CRIADO",
                "status": politica["status_caso"],
                "fase": politica["fase"],
                "modo": MODO_OPERACIONAL
            }
        ]

        caso = {
            "case_id": case_id,
            "timestamp": agora_iso(),
            "ip_origem": ip,

            "decision_id": decision_id,
            "decision_score": round(
                decision_score,
                2
            ),
            "prioridade_soc": prioridade,
            "classificacao_decisao": classificacao,
            "sla": sla,

            "evidence_id": evidencia.get(
                "id",
                "NAO_DISPONIVEL"
            ),
            "evidence_score": round(
                evidencia.get("score", 0),
                2
            ),
            "risk_score_maximo": round(
                evidencia.get(
                    "risk_score_maximo",
                    0
                ),
                2
            ),

            "campanha_detectada":
                campanha["detectada"],

            "campaign_score": round(
                campanha["score"],
                2
            ),

            "nivel_campanha":
                campanha["nivel"],

            "timeline_id": timeline.get(
                "id",
                "NAO_DISPONIVEL"
            ),

            "status_timeline": timeline.get(
                "status",
                "NAO_DISPONIVEL"
            ),

            "tendencia_timeline": timeline.get(
                "tendencia",
                "NAO_DISPONIVEL"
            ),

            "playbook_id": playbook.get(
                "id",
                "NAO_DISPONIVEL"
            ),

            "prioridade_playbook": playbook.get(
                "prioridade",
                "NAO_DISPONIVEL"
            ),

            "acao_playbook": playbook.get(
                "acao",
                "NAO_DISPONIVEL"
            ),

            "mitre_contexto":
                contexto_mitre.get(
                    "contexto",
                    "NAO_ATRIBUIDO"
                ),

            "mitre_tatica":
                contexto_mitre.get(
                    "tatica",
                    "NAO_ATRIBUIDA"
                ),

            "mitre_technique_id":
                contexto_mitre.get(
                    "technique_id",
                    "NAO_ATRIBUIDA"
                ),

            "mitre_confianca":
                contexto_mitre.get(
                    "confianca",
                    "INSUFICIENTE"
                ),

            "status_caso":
                politica["status_caso"],

            "fase":
                politica["fase"],

            "owner":
                politica["owner"],

            "requer_analista":
                politica["requer_analista"],

            "requer_escalacao":
                politica["requer_escalacao"],

            "preparar_contencao":
                politica["preparar_contencao"],

            "bloqueio_automatico":
                False,

            "modo_operacional":
                MODO_OPERACIONAL,

            "historico":
                historico,

            "criado_em":
                agora_iso()
        }

        persistir_caso(
            conexao,
            caso
        )

        casos.append(caso)

        print(f"Case ID: {case_id}")
        print(f"IOC: {ip}")
        print()

        print("DECISAO SOC:")
        print(
            f"Decision Score: "
            f"{decision_score:.2f}/100"
        )
        print(f"Prioridade: {prioridade}")
        print(f"Classificacao: {classificacao}")
        print(f"SLA: {sla}")
        print()

        print("EVIDENCIA:")
        print(
            f"Evidence ID: "
            f"{caso['evidence_id']}"
        )
        print(
            f"Evidence Score: "
            f"{caso['evidence_score']:.2f}/100"
        )
        print(
            f"Risk Score maximo: "
            f"{caso['risk_score_maximo']:.2f}/100"
        )
        print()

        print("CAMPANHA:")
        print(
            f"Detectada: "
            f"{sim_nao(caso['campanha_detectada'])}"
        )
        print(
            f"Campaign Score: "
            f"{caso['campaign_score']:.2f}/100"
        )
        print()

        print("TIMELINE:")
        print(
            f"Timeline ID: "
            f"{caso['timeline_id']}"
        )
        print(
            f"Status: "
            f"{caso['status_timeline']}"
        )
        print()

        print("INCIDENT RESPONSE:")
        print(
            f"Playbook: "
            f"{caso['playbook_id']}"
        )
        print(
            f"Prioridade Playbook: "
            f"{caso['prioridade_playbook']}"
        )
        print()

        print("MITRE ATT&CK:")
        print(
            f"Contexto: "
            f"{caso['mitre_contexto']}"
        )
        print(
            f"Tatica: "
            f"{caso['mitre_tatica']}"
        )
        print(
            f"Technique ID: "
            f"{caso['mitre_technique_id']}"
        )
        print(
            f"Confianca: "
            f"{caso['mitre_confianca']}"
        )
        print()

        print("CASE MANAGEMENT:")
        print(
            f"Status caso: "
            f"{caso['status_caso']}"
        )
        print(
            f"Fase: "
            f"{caso['fase']}"
        )
        print(
            f"Owner: "
            f"{caso['owner']}"
        )
        print(
            f"Requer analista: "
            f"{sim_nao(caso['requer_analista'])}"
        )
        print(
            f"Requer escalacao: "
            f"{sim_nao(caso['requer_escalacao'])}"
        )
        print(
            f"Preparar contencao: "
            f"{sim_nao(caso['preparar_contencao'])}"
        )
        print(
            f"Bloqueio automatico: "
            f"{sim_nao(caso['bloqueio_automatico'])}"
        )
        print(
            f"Modo: "
            f"{caso['modo_operacional']}"
        )
        print()

        if prioridade in ("ALTO", "CRITICO"):
            alerta_id = gerar_id("CASE-ALT-42")

            alerta = {
                "alerta_id": alerta_id,
                "timestamp": agora_iso(),
                "case_id": case_id,
                "ip_origem": ip,
                "prioridade": prioridade,
                "decision_score": decision_score,
                "status_caso":
                    caso["status_caso"],
                "requer_analista":
                    caso["requer_analista"],
                "requer_escalacao":
                    caso["requer_escalacao"],
                "preparar_contencao":
                    caso["preparar_contencao"],
                "bloqueio_automatico": False,
                "modo": MODO_OPERACIONAL
            }

            alertas.append(alerta)

            print(
                "[ALERTA] Caso SOC requer priorizacao"
            )
            print(
                f"[OK] Alerta: {alerta_id}"
            )

        else:
            print(
                "[OK] Caso registrado sem "
                "escalacao critica"
            )

    # ============================================================
    # ETAPA 10
    # ============================================================

    linha()
    print("ETAPA 10 - FILA DE CASOS SOC")
    linha()

    fila = sorted(
        casos,
        key=lambda c: c["decision_score"],
        reverse=True
    )

    print(f"Casos na fila: {len(fila)}")
    print()

    for indice, caso in enumerate(
        fila,
        start=1
    ):
        print(
            f"{indice:02d} | "
            f"{caso['ip_origem']} | "
            f"{caso['prioridade_soc']} | "
            f"Decision Score "
            f"{caso['decision_score']:.2f} | "
            f"{caso['status_caso']}"
        )

    # ============================================================
    # ETAPA 11
    # ============================================================

    linha()
    print("ETAPA 11 - VALIDANDO SEGURANCA")
    linha()

    validacoes_seguranca = []

    def validar_seguranca(condicao, descricao):
        validacoes_seguranca.append(
            (descricao, bool(condicao))
        )

        if condicao:
            print(f"[OK] {descricao}")
        else:
            print(f"[ERRO] {descricao}")

    validar_seguranca(
        len(casos) > 0,
        "Casos SOC gerados"
    )

    validar_seguranca(
        all(c["ip_origem"] for c in casos),
        "Todos os casos possuem IOC"
    )

    validar_seguranca(
        all(c["case_id"] for c in casos),
        "Todos os casos possuem Case ID"
    )

    validar_seguranca(
        all(
            0 <= c["decision_score"] <= 100
            for c in casos
        ),
        "Decision Scores entre 0 e 100"
    )

    validar_seguranca(
        all(
            0 <= c["evidence_score"] <= 100
            for c in casos
        ),
        "Evidence Scores entre 0 e 100"
    )

    validar_seguranca(
        all(
            not c["bloqueio_automatico"]
            for c in casos
        ),
        "Nenhum bloqueio automatico habilitado"
    )

    validar_seguranca(
        all(
            c["modo_operacional"]
            == "SIMULACAO"
            for c in casos
        ),
        "Modo operacional permanece SIMULACAO"
    )

    casos_criticos = [
        c for c in casos
        if c["prioridade_soc"] == "CRITICO"
    ]

    validar_seguranca(
        all(
            c["requer_analista"]
            for c in casos_criticos
        ),
        "Casos criticos exigem analista"
    )

    validar_seguranca(
        all(
            c["requer_escalacao"]
            for c in casos_criticos
        ),
        "Casos criticos exigem escalacao"
    )

    validar_seguranca(
        all(
            c["preparar_contencao"]
            for c in casos_criticos
        ),
        "Casos criticos preparam contencao"
    )

    seguranca_ok = all(
        resultado
        for _, resultado
        in validacoes_seguranca
    )

    # ============================================================
    # ETAPA 12
    # ============================================================

    linha()
    print("ETAPA 12 - PERSISTINDO RESULTADOS")
    linha()

    salvar_json(
        ARQUIVO_CASOS,
        casos
    )

    print("[OK] Casos SOC salvos")
    print(
        "Arquivo: "
        "casos\\casos_soc_aula_42.json"
    )

    salvar_json(
        ARQUIVO_ALERTAS,
        alertas
    )

    print(
        "[OK] Alertas Case Management salvos"
    )
    print(
        "Arquivo: "
        "alertas\\alertas_case_management_aula_42.json"
    )

    # ============================================================
    # ETAPA 13
    # ============================================================

    linha()
    print("ETAPA 13 - VALIDACAO FINAL")
    linha()

    validacoes_finais = []

    def validar_final(condicao, descricao):
        validacoes_finais.append(
            (descricao, bool(condicao))
        )

        if condicao:
            print(f"[OK] {descricao}")
        else:
            print(f"[ERRO] {descricao}")

    validar_final(
        DADOS_DIR.exists(),
        "Diretorio dados disponivel"
    )

    validar_final(
        CASOS_DIR.exists(),
        "Diretorio casos disponivel"
    )

    validar_final(
        ALERTAS_DIR.exists(),
        "Diretorio alertas disponivel"
    )

    validar_final(
        BANCO_SQLITE.exists(),
        "Banco SQLite encontrado"
    )

    validar_final(
        tabela_existe(
            conexao,
            TABELA_DECISOES
        ),
        "Tabela Decision Engine disponivel"
    )

    validar_final(
        schema_decisao_ok,
        "Schema Aula 41 compativel"
    )

    validar_final(
        tabela_existe(
            conexao,
            TABELA_CASOS
        ),
        "Tabela Case Management disponivel"
    )

    validar_final(
        len(decisoes) > 0,
        "Decisoes carregadas"
    )

    validar_final(
        len(decisoes_unicas) > 0,
        "Decisoes deduplicadas"
    )

    validar_final(
        len(casos) > 0,
        "Casos SOC gerados"
    )

    validar_final(
        len(casos)
        == len(decisoes_unicas),
        "Todos os IOCs possuem caso"
    )

    validar_final(
        len(fila) == len(casos),
        "Fila SOC criada"
    )

    validar_final(
        all(
            c["decision_score"] is not None
            for c in casos
        ),
        "Todos os casos possuem Decision Score"
    )

    validar_final(
        all(
            c["prioridade_soc"]
            for c in casos
        ),
        "Todos os casos possuem prioridade"
    )

    validar_final(
        all(
            c["status_caso"]
            for c in casos
        ),
        "Todos os casos possuem status"
    )

    validar_final(
        all(
            c["fase"]
            for c in casos
        ),
        "Todos os casos possuem fase"
    )

    validar_final(
        all(
            c["owner"]
            for c in casos
        ),
        "Todos os casos possuem owner"
    )

    validar_final(
        all(
            len(c["historico"]) > 0
            for c in casos
        ),
        "Historico inicial criado"
    )

    validar_final(
        all(
            not c["bloqueio_automatico"]
            for c in casos
        ),
        "Nenhum bloqueio automatico habilitado"
    )

    validar_final(
        all(
            c["modo_operacional"]
            == "SIMULACAO"
            for c in casos
        ),
        "Modo SIMULACAO preservado"
    )

    # ------------------------------------------------------------
    # CORRECAO IMPORTANTE
    # A validacao final agora incorpora a seguranca.
    # ------------------------------------------------------------

    validar_final(
        seguranca_ok,
        "Validacoes de seguranca aprovadas"
    )

    validar_final(
        all(
            c["preparar_contencao"]
            for c in casos_criticos
        ),
        "Casos criticos preparados para contencao humana"
    )

    validar_final(
        ARQUIVO_CASOS.exists(),
        "Arquivo de casos criado"
    )

    validar_final(
        ARQUIVO_ALERTAS.exists(),
        "Arquivo de alertas criado"
    )

    total_validacoes = len(validacoes_finais)

    aprovadas = sum(
        1
        for _, resultado
        in validacoes_finais
        if resultado
    )

    saude = (
        aprovadas / total_validacoes * 100
        if total_validacoes
        else 0
    )

    print()
    print(
        f"Validacoes: "
        f"{aprovadas}/{total_validacoes}"
    )

    print(
        f"Saude: "
        f"{saude:.2f}%"
    )

    # ============================================================
    # RELATORIO
    # ============================================================

    distribuicao = {
        "BAIXO": 0,
        "MEDIO": 0,
        "ALTO": 0,
        "CRITICO": 0
    }

    status_casos = {}

    for caso in casos:
        prioridade = caso["prioridade_soc"]

        if prioridade in distribuicao:
            distribuicao[prioridade] += 1

        status = caso["status_caso"]

        status_casos[status] = (
            status_casos.get(status, 0) + 1
        )

    relatorio = {
        "aula": 42,
        "projeto": "CyberSentinel-ML",
        "componente":
            "SOC Case Management / Incident Case Builder",

        "timestamp": agora_iso(),

        "decisoes_historicas":
            len(decisoes),

        "decisoes_processadas":
            len(decisoes_unicas),

        "casos_soc":
            len(casos),

        "alertas_soc":
            len(alertas),

        "distribuicao_prioridade":
            distribuicao,

        "status_casos":
            status_casos,

        "requer_analista":
            sum(
                1 for c in casos
                if c["requer_analista"]
            ),

        "requer_escalacao":
            sum(
                1 for c in casos
                if c["requer_escalacao"]
            ),

        "preparar_contencao":
            sum(
                1 for c in casos
                if c["preparar_contencao"]
            ),

        "bloqueios_automaticos":
            sum(
                1 for c in casos
                if c["bloqueio_automatico"]
            ),

        "validacoes_seguranca": {
            descricao: resultado
            for descricao, resultado
            in validacoes_seguranca
        },

        "seguranca_ok":
            seguranca_ok,

        "validacoes_finais": {
            descricao: resultado
            for descricao, resultado
            in validacoes_finais
        },

        "validacoes_aprovadas":
            aprovadas,

        "validacoes_total":
            total_validacoes,

        "saude":
            round(saude, 2),

        "modo_operacional":
            MODO_OPERACIONAL,

        "status":
            (
                "AULA 42 CONCLUIDA"
                if saude == 100
                else "AULA 42 REQUER AJUSTES"
            )
    }

    salvar_json(
        ARQUIVO_RELATORIO,
        relatorio
    )

    print("[OK] Relatorio salvo")
    print(
        "Arquivo: "
        "alertas\\relatorio_aula_42.json"
    )

    # ============================================================
    # RESUMO
    # ============================================================

    linha()
    print("RESUMO FINAL DA AULA 42")
    linha()

    print(
        f"Decisoes historicas: "
        f"{len(decisoes)}"
    )

    print(
        f"Decisoes processadas: "
        f"{len(decisoes_unicas)}"
    )

    print(
        f"Casos SOC criados: "
        f"{len(casos)}"
    )

    print(
        f"Alertas SOC: "
        f"{len(alertas)}"
    )

    print()
    print("Distribuicao de prioridade:")

    for nivel in [
        "BAIXO",
        "MEDIO",
        "ALTO",
        "CRITICO"
    ]:
        print(
            f"{nivel}: "
            f"{distribuicao[nivel]}"
        )

    print()
    print("Status dos casos:")

    for status, quantidade in status_casos.items():
        print(
            f"{status}: {quantidade}"
        )

    print()

    print(
        "Requer analista: "
        f"{sum(1 for c in casos if c['requer_analista'])}"
    )

    print(
        "Requer escalacao: "
        f"{sum(1 for c in casos if c['requer_escalacao'])}"
    )

    print(
        "Preparar contencao: "
        f"{sum(1 for c in casos if c['preparar_contencao'])}"
    )

    print(
        "Bloqueios automaticos: "
        f"{sum(1 for c in casos if c['bloqueio_automatico'])}"
    )

    print()

    print(
        f"Validacoes: "
        f"{aprovadas}/{total_validacoes}"
    )

    print(
        f"Saude: "
        f"{saude:.2f}%"
    )

    print(
        f"Modo operacional: "
        f"{MODO_OPERACIONAL}"
    )

    status_final = (
        "AULA 42 CONCLUIDA"
        if saude == 100
        else "AULA 42 REQUER AJUSTES"
    )

    print(
        f"Status: {status_final}"
    )

    # ============================================================
    # ARQUITETURA
    # ============================================================

    linha()
    print("ARQUITETURA DA AULA 42")
    linha()

    print(
r"""
               CYBERSENTINEL-ML
                      |
                      v
               INCIDENT EVIDENCE
                   AULA 40
                      |
                      v
               SOC DECISION ENGINE
                   AULA 41
                      |
                      v
               DECISAO PRIORIZADA
                      |
          +-----------+-----------+
          |           |           |
          v           v           v
      EVIDENCIA    TIMELINE    CAMPANHA
          |           |           |
          +-----------+-----------+
                      |
          +-----------+-----------+
          |                       |
          v                       v
      PLAYBOOK                MITRE CONTEXT
          |                       |
          +-----------+-----------+
                      |
                      v
               INCIDENT CASE BUILDER
                      |
                      v
                   CASE ID
                      |
          +-----------+-----------+
          |           |           |
          v           v           v
       STATUS       FASE        OWNER
          |           |           |
          +-----------+-----------+
                      |
                      v
                  SLA / ACAO
                      |
                      v
               HISTORICO DO CASO
                      |
                      v
                FILA DE CASOS SOC
                      |
          +-----------+-----------+
          |                       |
          v                       v
     MONITORAMENTO          CASO PRIORITARIO
                                  |
                                  v
                            ANALISE HUMANA
                                  |
                                  v
                         PREPARAR CONTENCAO
                                  |
                                  v
                          APROVACAO HUMANA
                                  |
                                  v
                       ACAO FORA DESTA AULA


IMPORTANTE:

CASE MANAGEMENT != CONTENCAO AUTOMATICA.

PREPARAR CONTENCAO != EXECUTAR CONTENCAO.

Nenhum IP e bloqueado automaticamente.

Nenhuma regra de firewall e alterada.

Nenhuma acao destrutiva e executada.

O Case Builder apenas organiza o contexto
necessario para o tratamento do incidente.

O analista humano permanece no fluxo.

Modo operacional: SIMULACAO.
"""
    )

    linha()
    print("CYBERSENTINEL-ML")
    linha()
    print("AULA 42 - SOC CASE MANAGEMENT")

    if saude == 100:
        print("AULA 42 CONCLUIDA")
    else:
        print("AULA 42 REQUER AJUSTES")

    conexao.close()


# ================================================================
# EXECUCAO
# ================================================================

if __name__ == "__main__":
    main()