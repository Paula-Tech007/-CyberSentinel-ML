# ================================================================
# AULA 45 V2 - SOC METRICS & OBSERVABILITY
# CyberSentinel-ML
#
# CORRECOES V2:
#
# 1. Separa HISTORICO de ESTADO ATUAL
# 2. Valida IOCs usando ipaddress
# 3. Ignora placeholders/valores legados
# 4. Deduplica Evidence por IOC
# 5. Deduplica Decisions por IOC
# 6. Deduplica Cases por IOC
# 7. Diferencia IOCs historicos validos de IOCs ativos
# 8. Valida consistencia entre Evidence, Decision e Cases
#
# IMPORTANTE:
# - Nenhuma nova decisao e criada
# - Nenhum Risk Score e recalculado
# - Nenhuma resposta e executada
# - Nenhum IP e bloqueado
# - Nenhum firewall e modificado
# - Modo operacional: SIMULACAO
# ================================================================

import ipaddress
import json
import sqlite3
import uuid

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


# ================================================================
# CONFIGURACOES
# ================================================================

PROJETO = "CyberSentinel-ML"
AULA = 45
VERSAO = "2.0"

BASE_DIR = Path(__file__).resolve().parent

DADOS_DIR = BASE_DIR / "dados"
METRICAS_DIR = BASE_DIR / "metricas"
ALERTAS_DIR = BASE_DIR / "alertas"

DB_PATH = DADOS_DIR / "cybersentinel.db"

ARQUIVO_METRICAS_JSON = (
    METRICAS_DIR / "soc_metrics_aula_45.json"
)

ARQUIVO_METRICAS_PROM = (
    METRICAS_DIR / "soc_metrics_aula_45.prom"
)

ARQUIVO_RELATORIO = (
    ALERTAS_DIR / "relatorio_aula_45.json"
)

TABELA_SNAPSHOTS = (
    "soc_observability_snapshots"
)

MODO_OPERACIONAL = "SIMULACAO"

LARGURA = 76


# ================================================================
# COMPONENTES
# ================================================================

COMPONENTES = {
    "correlacao_ioc_eventos":
        "IOC Historical Correlation",

    "campanhas_ioc":
        "Campaign Detection",

    "incident_timelines":
        "Incident Timeline",

    "incident_response_playbooks":
        "Incident Response",

    "mitre_attack_mapping":
        "MITRE ATT&CK Context",

    "incident_evidence":
        "Incident Evidence",

    "soc_incident_decisions":
        "SOC Decision Engine",

    "soc_incident_cases":
        "SOC Case Management",

    "soc_case_transitions":
        "SOC Case Lifecycle",

    "soc_human_approvals":
        "Human Approval Gate"
}


# ================================================================
# VISUAL
# ================================================================

def linha():
    print("=" * LARGURA)


def separador():
    print("-" * LARGURA)


def titulo(texto):
    linha()
    print(texto)
    linha()


def ok(texto):
    print(f"[OK] {texto}")


def info(texto):
    print(f"[INFO] {texto}")


def aviso(texto):
    print(f"[AVISO] {texto}")


def erro(texto):
    print(f"[ERRO] {texto}")


# ================================================================
# AUXILIARES
# ================================================================

def agora_iso():
    return datetime.now(
        timezone.utc
    ).isoformat()


def gerar_id(prefixo):
    data = datetime.now(
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
        f"{data}-"
        f"{sufixo}"
    )


def texto(
    valor,
    padrao=""
):
    if valor is None:
        return padrao

    valor = str(valor).strip()

    if not valor:
        return padrao

    return valor


def numero(
    valor,
    padrao=0.0
):
    try:
        if valor is None:
            return padrao

        return float(valor)

    except (
        TypeError,
        ValueError
    ):
        return padrao


def inteiro(
    valor,
    padrao=0
):
    try:
        if valor is None:
            return padrao

        return int(valor)

    except (
        TypeError,
        ValueError
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
            "VERDADEIRO"
        }
    )


def primeiro_valor(
    registro,
    nomes,
    padrao=None
):
    if not registro:
        return padrao

    for nome in nomes:

        if nome not in registro:
            continue

        valor = registro.get(
            nome
        )

        if valor is not None:
            return valor

    return padrao


def media(valores):
    validos = [
        numero(valor)
        for valor in valores
        if valor is not None
    ]

    if not validos:
        return 0.0

    return (
        sum(validos)
        / len(validos)
    )


def minimo(valores):
    validos = [
        numero(valor)
        for valor in valores
        if valor is not None
    ]

    if not validos:
        return 0.0

    return min(validos)


def maximo(valores):
    validos = [
        numero(valor)
        for valor in valores
        if valor is not None
    ]

    if not validos:
        return 0.0

    return max(validos)


def percentual(
    parte,
    total
):
    if total <= 0:
        return 0.0

    return (
        parte
        / total
        * 100
    )


def salvar_json(
    caminho,
    dados
):
    caminho.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with open(
        caminho,
        "w",
        encoding="utf-8"
    ) as arquivo:

        json.dump(
            dados,
            arquivo,
            indent=4,
            ensure_ascii=False,
            default=str
        )


# ================================================================
# VALIDACAO DE IOC
# ================================================================

PLACEHOLDERS_IOC = {
    "",
    "NAO_DISPONIVEL",
    "NAO_ATRIBUIDO",
    "NAO_ATRIBUIDA",
    "DESCONHECIDO",
    "UNKNOWN",
    "NONE",
    "NULL",
    "N/A"
}


def normalizar_ioc(valor):
    valor = texto(
        valor,
        ""
    ).strip()

    if (
        not valor
        or valor.upper()
        in PLACEHOLDERS_IOC
    ):
        return None

    try:

        endereco = (
            ipaddress.ip_address(
                valor
            )
        )

        return str(
            endereco
        )

    except ValueError:
        return None


def obter_ioc(
    registro
):
    valor = primeiro_valor(
        registro,
        [
            "ip_origem",
            "ioc",
            "ioc_valor",
            "ioc_value",
            "valor_ioc",
            "ip"
        ],
        None
    )

    return normalizar_ioc(
        valor
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
        (tabela,)
    )

    return (
        cursor.fetchone()
        is not None
    )


def obter_colunas(
    conexao,
    tabela
):
    if not tabela_existe(
        conexao,
        tabela
    ):
        return []

    cursor = conexao.cursor()

    cursor.execute(
        f"""
        PRAGMA table_info(
            {tabela}
        )
        """
    )

    return [
        linha["name"]
        for linha
        in cursor.fetchall()
    ]


def carregar_tabela(
    conexao,
    tabela
):
    if not tabela_existe(
        conexao,
        tabela
    ):
        return []

    cursor = conexao.cursor()

    cursor.execute(
        f"""
        SELECT *
        FROM {tabela}
        """
    )

    return [
        dict(linha)
        for linha
        in cursor.fetchall()
    ]


def contar_registros(
    conexao,
    tabela
):
    if not tabela_existe(
        conexao,
        tabela
    ):
        return 0

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

    return inteiro(
        resultado[0]
        if resultado
        else 0
    )


# ================================================================
# TIMESTAMP FLEXIVEL
# ================================================================

def obter_timestamp(
    registro
):
    candidatos = [
        "timestamp_atualizacao",
        "timestamp",
        "criado_em",
        "timestamp_criacao",
        "created_at",
        "updated_at"
    ]

    valores = []

    for campo in candidatos:

        valor = registro.get(
            campo
        )

        if valor:
            valores.append(
                str(valor)
            )

    if not valores:
        return ""

    return max(
        valores
    )


# ================================================================
# DEDUPLICACAO GENERICA POR IOC
# ================================================================

def deduplicar_por_ioc(
    registros
):
    """
    Mantem o registro mais recente para cada IOC valido.

    Em empate ou ausencia de timestamp,
    preserva o ultimo registro encontrado.
    """

    resultado = {}

    for indice, registro in enumerate(
        registros
    ):

        ioc = obter_ioc(
            registro
        )

        if not ioc:
            continue

        timestamp = obter_timestamp(
            registro
        )

        chave = (
            timestamp,
            indice
        )

        atual = resultado.get(
            ioc
        )

        if atual is None:

            resultado[ioc] = {
                "registro":
                    registro,

                "chave":
                    chave
            }

            continue

        if chave >= atual["chave"]:

            resultado[ioc] = {
                "registro":
                    registro,

                "chave":
                    chave
            }

    return {
        ioc: item["registro"]
        for ioc, item
        in resultado.items()
    }


# ================================================================
# IOC HISTORICO
# ================================================================

def coletar_iocs_historicos(
    tabelas
):
    validos = set()
    invalidos = set()

    for registros in tabelas.values():

        for registro in registros:

            valor_original = primeiro_valor(
                registro,
                [
                    "ip_origem",
                    "ioc",
                    "ioc_valor",
                    "ioc_value",
                    "valor_ioc",
                    "ip"
                ],
                None
            )

            if valor_original is None:
                continue

            ioc = normalizar_ioc(
                valor_original
            )

            if ioc:

                validos.add(
                    ioc
                )

            else:

                bruto = texto(
                    valor_original,
                    ""
                )

                if bruto:

                    invalidos.add(
                        bruto
                    )

    return (
        validos,
        invalidos
    )


# ================================================================
# EVIDENCE ATUAL
# ================================================================

def metricas_evidence_atual(
    registros
):
    atuais = deduplicar_por_ioc(
        registros
    )

    scores = []
    niveis = Counter()
    confiancas = Counter()

    itens = []

    for ioc, registro in atuais.items():

        score = numero(
            primeiro_valor(
                registro,
                [
                    "evidence_score"
                ],
                0
            )
        )

        nivel = texto(
            primeiro_valor(
                registro,
                [
                    "nivel_evidencia"
                ],
                "NAO_DISPONIVEL"
            ),
            "NAO_DISPONIVEL"
        ).upper()

        confianca = texto(
            primeiro_valor(
                registro,
                [
                    "confianca_evidencia"
                ],
                "NAO_DISPONIVEL"
            ),
            "NAO_DISPONIVEL"
        ).upper()

        scores.append(
            score
        )

        niveis[nivel] += 1
        confiancas[confianca] += 1

        itens.append(
            {
                "ioc":
                    ioc,

                "evidence_id":
                    texto(
                        primeiro_valor(
                            registro,
                            [
                                "evidence_id"
                            ],
                            ""
                        )
                    ),

                "evidence_score":
                    round(
                        score,
                        2
                    ),

                "nivel":
                    nivel,

                "confianca":
                    confianca
            }
        )

    itens.sort(
        key=lambda item:
            item[
                "evidence_score"
            ],
        reverse=True
    )

    return {
        "historicos":
            len(registros),

        "atuais":
            len(atuais),

        "iocs":
            sorted(
                atuais.keys()
            ),

        "score_medio":
            round(
                media(scores),
                2
            ),

        "score_minimo":
            round(
                minimo(scores),
                2
            ),

        "score_maximo":
            round(
                maximo(scores),
                2
            ),

        "niveis":
            dict(niveis),

        "confiancas":
            dict(confiancas),

        "registros_atuais":
            itens
    }


# ================================================================
# DECISOES ATUAIS
# ================================================================

def metricas_decisoes_atual(
    registros
):
    atuais = deduplicar_por_ioc(
        registros
    )

    scores = []
    prioridades = Counter()
    classificacoes = Counter()
    slas = Counter()

    analista = 0
    escalacao = 0
    contencao = 0
    auto_block = 0

    itens = []

    for ioc, registro in atuais.items():

        score = numero(
            primeiro_valor(
                registro,
                [
                    "decision_score"
                ],
                0
            )
        )

        prioridade = texto(
            primeiro_valor(
                registro,
                [
                    "prioridade_soc"
                ],
                "NAO_DISPONIVEL"
            ),
            "NAO_DISPONIVEL"
        ).upper()

        classificacao = texto(
            primeiro_valor(
                registro,
                [
                    "classificacao_decisao",
                    "classificacao"
                ],
                "NAO_DISPONIVEL"
            ),
            "NAO_DISPONIVEL"
        ).upper()

        sla = texto(
            primeiro_valor(
                registro,
                [
                    "sla_recomendado",
                    "sla"
                ],
                "NAO_DISPONIVEL"
            ),
            "NAO_DISPONIVEL"
        ).upper()

        scores.append(
            score
        )

        prioridades[
            prioridade
        ] += 1

        classificacoes[
            classificacao
        ] += 1

        slas[
            sla
        ] += 1

        if booleano(
            primeiro_valor(
                registro,
                ["requer_analista"],
                False
            )
        ):
            analista += 1

        if booleano(
            primeiro_valor(
                registro,
                ["requer_escalacao"],
                False
            )
        ):
            escalacao += 1

        if booleano(
            primeiro_valor(
                registro,
                [
                    "requer_contencao",
                    "preparar_contencao"
                ],
                False
            )
        ):
            contencao += 1

        if booleano(
            primeiro_valor(
                registro,
                [
                    "auto_block",
                    "bloqueio_automatico"
                ],
                False
            )
        ):
            auto_block += 1

        itens.append(
            {
                "ioc":
                    ioc,

                "decision_id":
                    texto(
                        primeiro_valor(
                            registro,
                            [
                                "decision_id"
                            ],
                            ""
                        )
                    ),

                "decision_score":
                    round(
                        score,
                        2
                    ),

                "prioridade":
                    prioridade,

                "classificacao":
                    classificacao,

                "sla":
                    sla
            }
        )

    itens.sort(
        key=lambda item:
            item[
                "decision_score"
            ],
        reverse=True
    )

    return {
        "historicos":
            len(registros),

        "atuais":
            len(atuais),

        "iocs":
            sorted(
                atuais.keys()
            ),

        "score_medio":
            round(
                media(scores),
                2
            ),

        "score_minimo":
            round(
                minimo(scores),
                2
            ),

        "score_maximo":
            round(
                maximo(scores),
                2
            ),

        "prioridades":
            dict(prioridades),

        "classificacoes":
            dict(classificacoes),

        "sla":
            dict(slas),

        "requer_analista":
            analista,

        "requer_escalacao":
            escalacao,

        "requer_contencao":
            contencao,

        "auto_block":
            auto_block,

        "registros_atuais":
            itens
    }


# ================================================================
# CASE MANAGEMENT ATUAL
# ================================================================

def metricas_casos_atual(
    registros
):
    atuais = deduplicar_por_ioc(
        registros
    )

    prioridades = Counter()
    status = Counter()
    fases = Counter()
    owners = Counter()
    slas = Counter()

    decision_scores = []
    evidence_scores = []

    itens = []

    for ioc, registro in atuais.items():

        prioridade = texto(
            primeiro_valor(
                registro,
                [
                    "prioridade_soc",
                    "prioridade"
                ],
                "NAO_DISPONIVEL"
            ),
            "NAO_DISPONIVEL"
        ).upper()

        status_caso = texto(
            primeiro_valor(
                registro,
                [
                    "status_caso",
                    "status"
                ],
                "NAO_DISPONIVEL"
            ),
            "NAO_DISPONIVEL"
        ).upper()

        fase = texto(
            primeiro_valor(
                registro,
                [
                    "fase",
                    "fase_caso"
                ],
                "NAO_DISPONIVEL"
            ),
            "NAO_DISPONIVEL"
        ).upper()

        owner = texto(
            primeiro_valor(
                registro,
                [
                    "owner"
                ],
                "NAO_DISPONIVEL"
            ),
            "NAO_DISPONIVEL"
        )

        sla = texto(
            primeiro_valor(
                registro,
                [
                    "sla",
                    "sla_recomendado"
                ],
                "NAO_DISPONIVEL"
            ),
            "NAO_DISPONIVEL"
        ).upper()

        decision_score = numero(
            primeiro_valor(
                registro,
                [
                    "decision_score"
                ],
                0
            )
        )

        evidence_score = numero(
            primeiro_valor(
                registro,
                [
                    "evidence_score"
                ],
                0
            )
        )

        prioridades[
            prioridade
        ] += 1

        status[
            status_caso
        ] += 1

        fases[
            fase
        ] += 1

        owners[
            owner
        ] += 1

        slas[
            sla
        ] += 1

        decision_scores.append(
            decision_score
        )

        evidence_scores.append(
            evidence_score
        )

        itens.append(
            {
                "case_id":
                    texto(
                        primeiro_valor(
                            registro,
                            ["case_id"],
                            ""
                        )
                    ),

                "ioc":
                    ioc,

                "prioridade":
                    prioridade,

                "decision_score":
                    round(
                        decision_score,
                        2
                    ),

                "evidence_score":
                    round(
                        evidence_score,
                        2
                    ),

                "status":
                    status_caso,

                "fase":
                    fase,

                "owner":
                    owner,

                "sla":
                    sla
            }
        )

    itens.sort(
        key=lambda item:
            item[
                "decision_score"
            ],
        reverse=True
    )

    return {
        "historicos":
            len(registros),

        "atuais":
            len(atuais),

        "iocs":
            sorted(
                atuais.keys()
            ),

        "criticos":
            prioridades.get(
                "CRITICO",
                0
            ),

        "prioridades":
            dict(prioridades),

        "status":
            dict(status),

        "fases":
            dict(fases),

        "owners":
            dict(owners),

        "sla":
            dict(slas),

        "decision_score_medio":
            round(
                media(
                    decision_scores
                ),
                2
            ),

        "evidence_score_medio":
            round(
                media(
                    evidence_scores
                ),
                2
            ),

        "fila":
            itens
    }


# ================================================================
# CAMPANHAS
# ================================================================

def metricas_campanhas(
    registros
):
    detectadas = 0
    niveis = Counter()

    for registro in registros:

        status = texto(
            primeiro_valor(
                registro,
                [
                    "status",
                    "status_campanha"
                ],
                ""
            )
        ).upper()

        campo_detectada = booleano(
            primeiro_valor(
                registro,
                [
                    "campanha_detectada"
                ],
                False
            )
        )

        if (
            campo_detectada
            or status
            == "CAMPANHA_DETECTADA"
        ):
            detectadas += 1

        nivel = texto(
            primeiro_valor(
                registro,
                [
                    "nivel",
                    "nivel_campanha"
                ],
                "NAO_DISPONIVEL"
            ),
            "NAO_DISPONIVEL"
        ).upper()

        niveis[
            nivel
        ] += 1

    return {
        "registros":
            len(registros),

        "detectadas":
            detectadas,

        "niveis":
            dict(niveis)
    }


# ================================================================
# TIMELINES
# ================================================================

def metricas_timelines(
    registros
):
    status = Counter()
    tendencias = Counter()

    criticas = 0

    for registro in registros:

        status_valor = texto(
            primeiro_valor(
                registro,
                [
                    "status",
                    "status_incidente",
                    "status_timeline"
                ],
                "NAO_DISPONIVEL"
            ),
            "NAO_DISPONIVEL"
        ).upper()

        tendencia = texto(
            primeiro_valor(
                registro,
                [
                    "tendencia",
                    "tendencia_risco"
                ],
                "NAO_DISPONIVEL"
            ),
            "NAO_DISPONIVEL"
        ).upper()

        status[
            status_valor
        ] += 1

        tendencias[
            tendencia
        ] += 1

        if (
            status_valor
            == "INCIDENTE_CRITICO"
        ):
            criticas += 1

    return {
        "registros":
            len(registros),

        "criticas":
            criticas,

        "status":
            dict(status),

        "tendencias":
            dict(tendencias)
    }


# ================================================================
# LIFECYCLE
# ================================================================

def metricas_lifecycle(
    registros
):
    permitidas = 0
    bloqueadas = 0
    aprovacao_humana = 0
    auto_block = 0

    origens = Counter()
    destinos = Counter()

    for registro in registros:

        origem = texto(
            primeiro_valor(
                registro,
                ["status_anterior"],
                "NAO_DISPONIVEL"
            ),
            "NAO_DISPONIVEL"
        ).upper()

        destino = texto(
            primeiro_valor(
                registro,
                ["status_novo"],
                "NAO_DISPONIVEL"
            ),
            "NAO_DISPONIVEL"
        ).upper()

        origens[origem] += 1
        destinos[destino] += 1

        if booleano(
            primeiro_valor(
                registro,
                [
                    "transicao_permitida"
                ],
                False
            )
        ):
            permitidas += 1

        else:
            bloqueadas += 1

        if booleano(
            primeiro_valor(
                registro,
                [
                    "requer_aprovacao_humana"
                ],
                False
            )
        ):
            aprovacao_humana += 1

        if booleano(
            primeiro_valor(
                registro,
                [
                    "bloqueio_automatico"
                ],
                False
            )
        ):
            auto_block += 1

    return {
        "transicoes":
            len(registros),

        "permitidas":
            permitidas,

        "bloqueadas":
            bloqueadas,

        "requerem_aprovacao_humana":
            aprovacao_humana,

        "bloqueios_automaticos":
            auto_block,

        "status_origem":
            dict(origens),

        "status_destino":
            dict(destinos)
    }


# ================================================================
# HUMAN APPROVAL
# ================================================================

def metricas_aprovacoes(
    registros
):
    decisoes = Counter()

    autorizadas = 0
    execucoes = 0
    bloqueios = 0

    modos = Counter()

    for registro in registros:

        decisao = texto(
            primeiro_valor(
                registro,
                ["decisao"],
                "NAO_DISPONIVEL"
            ),
            "NAO_DISPONIVEL"
        ).upper()

        decisoes[
            decisao
        ] += 1

        if booleano(
            primeiro_valor(
                registro,
                [
                    "acao_autorizada"
                ],
                False
            )
        ):
            autorizadas += 1

        if booleano(
            primeiro_valor(
                registro,
                [
                    "execucao_real"
                ],
                False
            )
        ):
            execucoes += 1

        if booleano(
            primeiro_valor(
                registro,
                [
                    "bloqueio_automatico"
                ],
                False
            )
        ):
            bloqueios += 1

        modo = texto(
            primeiro_valor(
                registro,
                [
                    "modo_operacional"
                ],
                "NAO_DISPONIVEL"
            ),
            "NAO_DISPONIVEL"
        ).upper()

        modos[
            modo
        ] += 1

    return {
        "registros":
            len(registros),

        "decisoes":
            dict(decisoes),

        "acoes_autorizadas":
            autorizadas,

        "execucoes_reais":
            execucoes,

        "bloqueios_automaticos":
            bloqueios,

        "modos":
            dict(modos)
    }


# ================================================================
# SNAPSHOT TABLE
# ================================================================

def criar_tabela_snapshot(
    conexao
):
    cursor = conexao.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS soc_observability_snapshots (
            snapshot_id TEXT PRIMARY KEY,
            timestamp TEXT,

            componentes_esperados INTEGER,
            componentes_disponiveis INTEGER,
            cobertura_componentes REAL,

            registros_pipeline INTEGER,

            iocs_unicos INTEGER,
            iocs_historicos INTEGER,
            iocs_ativos INTEGER,

            evidence_score_medio REAL,
            decision_score_medio REAL,

            casos_soc INTEGER,
            casos_criticos INTEGER,

            transicoes_lifecycle INTEGER,
            aprovacoes_humanas INTEGER,

            acoes_autorizadas INTEGER,
            execucoes_reais INTEGER,
            bloqueios_automaticos INTEGER,

            validacoes_total INTEGER,
            validacoes_ok INTEGER,

            saude_pipeline REAL,

            modo_operacional TEXT
        )
        """
    )

    conexao.commit()


def migrar_snapshot(
    conexao
):
    necessarias = {
        "iocs_historicos":
            "INTEGER",

        "iocs_ativos":
            "INTEGER"
    }

    atuais = obter_colunas(
        conexao,
        TABELA_SNAPSHOTS
    )

    cursor = conexao.cursor()
    adicionadas = []

    for coluna, tipo in (
        necessarias.items()
    ):

        if coluna in atuais:
            continue

        cursor.execute(
            f"""
            ALTER TABLE {TABELA_SNAPSHOTS}
            ADD COLUMN {coluna} {tipo}
            """
        )

        adicionadas.append(
            coluna
        )

    conexao.commit()

    return adicionadas


def persistir_snapshot(
    conexao,
    snapshot
):
    cursor = conexao.cursor()

    cursor.execute(
        """
        INSERT INTO soc_observability_snapshots (
            snapshot_id,
            timestamp,

            componentes_esperados,
            componentes_disponiveis,
            cobertura_componentes,

            registros_pipeline,

            iocs_unicos,
            iocs_historicos,
            iocs_ativos,

            evidence_score_medio,
            decision_score_medio,

            casos_soc,
            casos_criticos,

            transicoes_lifecycle,
            aprovacoes_humanas,

            acoes_autorizadas,
            execucoes_reais,
            bloqueios_automaticos,

            validacoes_total,
            validacoes_ok,

            saude_pipeline,

            modo_operacional
        )
        VALUES (
            ?, ?,
            ?, ?, ?,
            ?,
            ?, ?, ?,
            ?, ?,
            ?, ?,
            ?, ?,
            ?, ?, ?,
            ?, ?,
            ?,
            ?
        )
        """,
        (
            snapshot[
                "snapshot_id"
            ],

            snapshot[
                "timestamp"
            ],

            snapshot[
                "componentes_esperados"
            ],

            snapshot[
                "componentes_disponiveis"
            ],

            snapshot[
                "cobertura_componentes"
            ],

            snapshot[
                "registros_pipeline"
            ],

            snapshot[
                "iocs_unicos"
            ],

            snapshot[
                "iocs_historicos"
            ],

            snapshot[
                "iocs_ativos"
            ],

            snapshot[
                "evidence_score_medio"
            ],

            snapshot[
                "decision_score_medio"
            ],

            snapshot[
                "casos_soc"
            ],

            snapshot[
                "casos_criticos"
            ],

            snapshot[
                "transicoes_lifecycle"
            ],

            snapshot[
                "aprovacoes_humanas"
            ],

            snapshot[
                "acoes_autorizadas"
            ],

            snapshot[
                "execucoes_reais"
            ],

            snapshot[
                "bloqueios_automaticos"
            ],

            snapshot[
                "validacoes_total"
            ],

            snapshot[
                "validacoes_ok"
            ],

            snapshot[
                "saude_pipeline"
            ],

            MODO_OPERACIONAL
        )
    )

    conexao.commit()


# ================================================================
# PROMETHEUS-LIKE
# ================================================================

def salvar_prometheus(
    caminho,
    metricas
):
    linhas = [
        "# CyberSentinel-ML",
        "# Aula 45 V2 - SOC Metrics & Observability",
        "",

        "cybersentinel_pipeline_components "
        f"{metricas['pipeline']['componentes_disponiveis']}",

        "cybersentinel_pipeline_coverage_percent "
        f"{metricas['pipeline']['cobertura_percentual']:.2f}",

        "cybersentinel_pipeline_records_historical "
        f"{metricas['pipeline']['registros_historicos']}",

        "cybersentinel_iocs_historical "
        f"{metricas['pipeline']['iocs_historicos']}",

        "cybersentinel_iocs_active "
        f"{metricas['pipeline']['iocs_ativos']}",

        "cybersentinel_evidence_records_historical "
        f"{metricas['evidence']['historicos']}",

        "cybersentinel_evidence_records_current "
        f"{metricas['evidence']['atuais']}",

        "cybersentinel_evidence_score_current_average "
        f"{metricas['evidence']['score_medio']:.2f}",

        "cybersentinel_decision_records_historical "
        f"{metricas['decisoes']['historicos']}",

        "cybersentinel_decision_records_current "
        f"{metricas['decisoes']['atuais']}",

        "cybersentinel_decision_score_current_average "
        f"{metricas['decisoes']['score_medio']:.2f}",

        "cybersentinel_soc_cases_historical "
        f"{metricas['casos']['historicos']}",

        "cybersentinel_soc_cases_current "
        f"{metricas['casos']['atuais']}",

        "cybersentinel_soc_cases_critical "
        f"{metricas['casos']['criticos']}",

        "cybersentinel_lifecycle_transitions "
        f"{metricas['lifecycle']['transicoes']}",

        "cybersentinel_human_approvals "
        f"{metricas['aprovacoes']['registros']}",

        "cybersentinel_authorized_actions "
        f"{metricas['aprovacoes']['acoes_autorizadas']}",

        "cybersentinel_real_executions "
        f"{metricas['seguranca']['execucoes_reais']}",

        "cybersentinel_automatic_blocks "
        f"{metricas['seguranca']['bloqueios_automaticos']}",

        "cybersentinel_pipeline_health_percent "
        f"{metricas['saude']['percentual']:.2f}"
    ]

    caminho.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with open(
        caminho,
        "w",
        encoding="utf-8"
    ) as arquivo:

        arquivo.write(
            "\n".join(
                linhas
            )
        )


# ================================================================
# MAIN
# ================================================================

def main():

    titulo(
        "AULA 45 V2 - SOC METRICS & OBSERVABILITY"
    )

    print(PROJETO)
    print(
        "Historical Metrics + Current State Observability"
    )

    print()

    print("Objetivo:")

    print(
        "Separar metricas historicas do estado atual "
        "e remover contaminacao por IOCs invalidos."
    )

    print()

    print("IMPORTANTE:")

    print(
        "Historico != estado atual."
    )

    print(
        "Somente enderecos IP validos sao considerados IOCs."
    )

    print(
        "Nenhuma decisao sera criada."
    )

    print(
        "Nenhuma contencao sera executada."
    )

    print(
        "Nenhum IP sera bloqueado."
    )

    print(
        "Modo operacional: SIMULACAO."
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
            ("dados", DADOS_DIR),
            ("metricas", METRICAS_DIR),
            ("alertas", ALERTAS_DIR)
        ]:

            diretorio.mkdir(
                parents=True,
                exist_ok=True
            )

            ok(
                f"Diretorio {nome} pronto"
            )

            validacoes.append(
                (
                    f"Diretorio {nome} disponivel",
                    diretorio.exists()
                )
            )

        # ========================================================
        # ETAPA 2
        # ========================================================

        titulo(
            "ETAPA 2 - VALIDANDO SQLITE"
        )

        if not DB_PATH.exists():

            erro(
                "Banco SQLite nao encontrado"
            )

            return

        ok(
            "Banco SQLite encontrado"
        )

        print(
            f"Banco: "
            f"{DB_PATH.relative_to(BASE_DIR)}"
        )

        conexao = conectar_banco()

        validacoes.append(
            (
                "Banco SQLite encontrado",
                True
            )
        )

        # ========================================================
        # ETAPA 3
        # ========================================================

        titulo(
            "ETAPA 3 - INVENTARIO DE COMPONENTES"
        )

        componentes_status = {}

        disponiveis = 0

        for tabela, nome in (
            COMPONENTES.items()
        ):

            existe = tabela_existe(
                conexao,
                tabela
            )

            quantidade = (
                contar_registros(
                    conexao,
                    tabela
                )
                if existe
                else 0
            )

            componentes_status[
                tabela
            ] = {
                "nome":
                    nome,

                "disponivel":
                    existe,

                "registros":
                    quantidade
            }

            if existe:

                disponiveis += 1

                ok(
                    f"{nome}: "
                    f"{quantidade} registros"
                )

            else:

                erro(
                    f"{nome}: tabela ausente"
                )

        esperados = len(
            COMPONENTES
        )

        cobertura = percentual(
            disponiveis,
            esperados
        )

        print()

        print(
            f"Componentes: "
            f"{disponiveis}/{esperados}"
        )

        print(
            f"Cobertura: "
            f"{cobertura:.2f}%"
        )

        validacoes.append(
            (
                "Todos os componentes principais disponiveis",
                disponiveis
                == esperados
            )
        )

        # ========================================================
        # ETAPA 4
        # ========================================================

        titulo(
            "ETAPA 4 - CARREGANDO HISTORICO DO PIPELINE"
        )

        tabelas = {}

        registros_historicos = 0

        for tabela in COMPONENTES:

            registros = carregar_tabela(
                conexao,
                tabela
            )

            tabelas[
                tabela
            ] = registros

            registros_historicos += (
                len(registros)
            )

            print(
                f"{tabela}: "
                f"{len(registros)} registros"
            )

        print()

        ok(
            f"Registros historicos monitorados: "
            f"{registros_historicos}"
        )

        validacoes.append(
            (
                "Pipeline possui historico",
                registros_historicos > 0
            )
        )

        # ========================================================
        # ETAPA 5
        # ========================================================

        titulo(
            "ETAPA 5 - HIGIENE DOS IOCS"
        )

        (
            iocs_historicos,
            valores_invalidos
        ) = coletar_iocs_historicos(
            tabelas
        )

        print(
            f"IOCs historicos validos: "
            f"{len(iocs_historicos)}"
        )

        for ioc in sorted(
            iocs_historicos
        ):

            print(
                f"- {ioc}"
            )

        print()

        print(
            "Valores ignorados por nao serem "
            "enderecos IP validos:"
        )

        if valores_invalidos:

            for valor in sorted(
                valores_invalidos
            ):

                aviso(
                    f"Ignorado: {valor}"
                )

        else:

            print(
                "- nenhum"
            )

        validacoes.append(
            (
                "IOCs historicos validos encontrados",
                len(iocs_historicos) > 0
            )
        )

        # ========================================================
        # ETAPA 6
        # ========================================================

        titulo(
            "ETAPA 6 - ESTADO ATUAL DE EVIDENCE"
        )

        evidence = (
            metricas_evidence_atual(
                tabelas[
                    "incident_evidence"
                ]
            )
        )

        print(
            f"Registros historicos: "
            f"{evidence['historicos']}"
        )

        print(
            f"Registros atuais: "
            f"{evidence['atuais']}"
        )

        print()

        for item in (
            evidence[
                "registros_atuais"
            ]
        ):

            print(
                f"- {item['ioc']} | "
                f"Evidence Score "
                f"{item['evidence_score']:.2f} | "
                f"{item['nivel']} | "
                f"{item['confianca']}"
            )

        print()

        print(
            "Evidence Score atual medio: "
            f"{evidence['score_medio']:.2f}"
        )

        print(
            "Evidence Score atual minimo: "
            f"{evidence['score_minimo']:.2f}"
        )

        print(
            "Evidence Score atual maximo: "
            f"{evidence['score_maximo']:.2f}"
        )

        validacoes.append(
            (
                "Evidence atual deduplicado",
                evidence[
                    "atuais"
                ] > 0
            )
        )

        # ========================================================
        # ETAPA 7
        # ========================================================

        titulo(
            "ETAPA 7 - ESTADO ATUAL DO DECISION ENGINE"
        )

        decisoes = (
            metricas_decisoes_atual(
                tabelas[
                    "soc_incident_decisions"
                ]
            )
        )

        print(
            f"Decisoes historicas: "
            f"{decisoes['historicos']}"
        )

        print(
            f"Decisoes atuais: "
            f"{decisoes['atuais']}"
        )

        print()

        for item in (
            decisoes[
                "registros_atuais"
            ]
        ):

            print(
                f"- {item['ioc']} | "
                f"Decision Score "
                f"{item['decision_score']:.2f} | "
                f"{item['prioridade']} | "
                f"{item['classificacao']}"
            )

        print()

        print(
            "Decision Score atual medio: "
            f"{decisoes['score_medio']:.2f}"
        )

        validacoes.append(
            (
                "Decision Engine atual deduplicado",
                decisoes[
                    "atuais"
                ] > 0
            )
        )

        # ========================================================
        # ETAPA 8
        # ========================================================

        titulo(
            "ETAPA 8 - ESTADO ATUAL DO CASE MANAGEMENT"
        )

        casos = (
            metricas_casos_atual(
                tabelas[
                    "soc_incident_cases"
                ]
            )
        )

        print(
            f"Casos historicos: "
            f"{casos['historicos']}"
        )

        print(
            f"Casos atuais: "
            f"{casos['atuais']}"
        )

        print(
            f"Casos criticos: "
            f"{casos['criticos']}"
        )

        print()

        for item in (
            casos["fila"]
        ):

            print(
                f"- {item['ioc']} | "
                f"{item['prioridade']} | "
                f"Decision Score "
                f"{item['decision_score']:.2f} | "
                f"{item['status']} | "
                f"{item['fase']}"
            )

        iocs_ativos = set(
            casos[
                "iocs"
            ]
        )

        print()

        print(
            f"IOCs ativos: "
            f"{len(iocs_ativos)}"
        )

        for ioc in sorted(
            iocs_ativos
        ):

            print(
                f"- {ioc}"
            )

        validacoes.append(
            (
                "Case Management atual deduplicado",
                casos[
                    "atuais"
                ] > 0
            )
        )

        # ========================================================
        # ETAPA 9
        # ========================================================

        titulo(
            "ETAPA 9 - CONSISTENCIA ENTRE CAMADAS"
        )

        iocs_evidence = set(
            evidence[
                "iocs"
            ]
        )

        iocs_decisoes = set(
            decisoes[
                "iocs"
            ]
        )

        print(
            "IOCs Evidence:"
        )

        print(
            sorted(
                iocs_evidence
            )
        )

        print()

        print(
            "IOCs Decision Engine:"
        )

        print(
            sorted(
                iocs_decisoes
            )
        )

        print()

        print(
            "IOCs Case Management:"
        )

        print(
            sorted(
                iocs_ativos
            )
        )

        evidence_decision_ok = (
            iocs_evidence
            == iocs_decisoes
        )

        decision_cases_ok = (
            iocs_decisoes
            == iocs_ativos
        )

        evidence_cases_ok = (
            iocs_evidence
            == iocs_ativos
        )

        if evidence_decision_ok:
            ok(
                "Evidence e Decision possuem os mesmos IOCs"
            )
        else:
            erro(
                "Evidence e Decision divergem nos IOCs"
            )

        if decision_cases_ok:
            ok(
                "Decision e Cases possuem os mesmos IOCs"
            )
        else:
            erro(
                "Decision e Cases divergem nos IOCs"
            )

        if evidence_cases_ok:
            ok(
                "Evidence e Cases possuem os mesmos IOCs"
            )
        else:
            erro(
                "Evidence e Cases divergem nos IOCs"
            )

        validacoes.extend(
            [
                (
                    "Evidence e Decision consistentes",
                    evidence_decision_ok
                ),

                (
                    "Decision e Cases consistentes",
                    decision_cases_ok
                ),

                (
                    "Evidence e Cases consistentes",
                    evidence_cases_ok
                )
            ]
        )

        # ========================================================
        # ETAPA 10
        # ========================================================

        titulo(
            "ETAPA 10 - CAMPAIGN E TIMELINE"
        )

        campanhas = metricas_campanhas(
            tabelas[
                "campanhas_ioc"
            ]
        )

        timelines = metricas_timelines(
            tabelas[
                "incident_timelines"
            ]
        )

        print(
            f"Campanhas analisadas: "
            f"{campanhas['registros']}"
        )

        print(
            f"Campanhas detectadas: "
            f"{campanhas['detectadas']}"
        )

        print()

        print(
            f"Timelines: "
            f"{timelines['registros']}"
        )

        print(
            f"Timelines criticas: "
            f"{timelines['criticas']}"
        )

        validacoes.extend(
            [
                (
                    "Campaign Detection observavel",
                    campanhas[
                        "registros"
                    ] > 0
                ),

                (
                    "Incident Timeline observavel",
                    timelines[
                        "registros"
                    ] > 0
                )
            ]
        )

        # ========================================================
        # ETAPA 11
        # ========================================================

        titulo(
            "ETAPA 11 - LIFECYCLE E HUMAN APPROVAL"
        )

        lifecycle = metricas_lifecycle(
            tabelas[
                "soc_case_transitions"
            ]
        )

        aprovacoes = metricas_aprovacoes(
            tabelas[
                "soc_human_approvals"
            ]
        )

        print(
            f"Transicoes Lifecycle: "
            f"{lifecycle['transicoes']}"
        )

        print(
            f"Permitidas: "
            f"{lifecycle['permitidas']}"
        )

        print(
            f"Bloqueadas: "
            f"{lifecycle['bloqueadas']}"
        )

        print()

        print(
            f"Aprovacoes humanas: "
            f"{aprovacoes['registros']}"
        )

        print(
            f"Acoes autorizadas: "
            f"{aprovacoes['acoes_autorizadas']}"
        )

        print(
            f"Execucoes reais: "
            f"{aprovacoes['execucoes_reais']}"
        )

        print(
            f"Bloqueios automaticos: "
            f"{aprovacoes['bloqueios_automaticos']}"
        )

        validacoes.extend(
            [
                (
                    "Lifecycle observavel",
                    lifecycle[
                        "transicoes"
                    ] > 0
                ),

                (
                    "Human Approval observavel",
                    aprovacoes[
                        "registros"
                    ] > 0
                )
            ]
        )

        # ========================================================
        # ETAPA 12
        # ========================================================

        titulo(
            "ETAPA 12 - SEGURANCA OPERACIONAL"
        )

        bloqueios = (
            decisoes[
                "auto_block"
            ]
            + lifecycle[
                "bloqueios_automaticos"
            ]
            + aprovacoes[
                "bloqueios_automaticos"
            ]
        )

        execucoes = (
            aprovacoes[
                "execucoes_reais"
            ]
        )

        modos_validos = all(
            modo
            == MODO_OPERACIONAL
            for modo
            in aprovacoes[
                "modos"
            ]
        )

        checks_seguranca = [
            (
                "Nenhuma execucao real detectada",
                execucoes == 0
            ),

            (
                "Nenhum bloqueio automatico detectado",
                bloqueios == 0
            ),

            (
                "Human Approval permanece em SIMULACAO",
                modos_validos
            ),

            (
                "Evidence Scores atuais entre 0 e 100",
                (
                    evidence[
                        "score_minimo"
                    ] >= 0
                    and
                    evidence[
                        "score_maximo"
                    ] <= 100
                )
            ),

            (
                "Decision Scores atuais entre 0 e 100",
                (
                    decisoes[
                        "score_minimo"
                    ] >= 0
                    and
                    decisoes[
                        "score_maximo"
                    ] <= 100
                )
            )
        ]

        seguranca_ok = True

        for descricao, resultado in (
            checks_seguranca
        ):

            if resultado:

                ok(
                    descricao
                )

            else:

                erro(
                    descricao
                )

                seguranca_ok = False

        validacoes.append(
            (
                "Seguranca operacional aprovada",
                seguranca_ok
            )
        )

        # ========================================================
        # ETAPA 13
        # ========================================================

        titulo(
            "ETAPA 13 - PREPARANDO SNAPSHOT"
        )

        criar_tabela_snapshot(
            conexao
        )

        adicionadas = migrar_snapshot(
            conexao
        )

        ok(
            "Tabela soc_observability_snapshots pronta"
        )

        if adicionadas:

            for coluna in adicionadas:

                ok(
                    f"Coluna adicionada: "
                    f"{coluna}"
                )

        else:

            ok(
                "Schema Observability V2 compativel"
            )

        validacoes.append(
            (
                "Tabela Observability disponivel",
                tabela_existe(
                    conexao,
                    TABELA_SNAPSHOTS
                )
            )
        )

        # ========================================================
        # ETAPA 14
        # ========================================================

        titulo(
            "ETAPA 14 - VALIDACAO FINAL"
        )

        validacoes.extend(
            [
                (
                    "Cobertura completa dos componentes",
                    disponiveis
                    == esperados
                ),

                (
                    "Historico do pipeline disponivel",
                    registros_historicos > 0
                ),

                (
                    "IOCs ativos encontrados",
                    len(iocs_ativos) > 0
                ),

                (
                    "IOCs ativos sao IPs validos",
                    all(
                        normalizar_ioc(
                            ioc
                        )
                        is not None
                        for ioc
                        in iocs_ativos
                    )
                ),

                (
                    "Quantidade atual de Evidence bate com Cases",
                    evidence[
                        "atuais"
                    ]
                    == casos[
                        "atuais"
                    ]
                ),

                (
                    "Quantidade atual de Decisions bate com Cases",
                    decisoes[
                        "atuais"
                    ]
                    == casos[
                        "atuais"
                    ]
                ),

                (
                    "Zero execucoes reais",
                    execucoes == 0
                ),

                (
                    "Zero bloqueios automaticos",
                    bloqueios == 0
                )
            ]
        )

        # Remove descricoes repetidas
        unicas = []
        vistos = set()

        for descricao, resultado in validacoes:

            if descricao in vistos:
                continue

            vistos.add(
                descricao
            )

            unicas.append(
                (
                    descricao,
                    bool(resultado)
                )
            )

        aprovadas = 0

        for descricao, resultado in unicas:

            if resultado:

                ok(
                    descricao
                )

                aprovadas += 1

            else:

                erro(
                    descricao
                )

        total = len(
            unicas
        )

        saude = percentual(
            aprovadas,
            total
        )

        print()

        print(
            f"Validacoes: "
            f"{aprovadas}/{total}"
        )

        print(
            f"Saude do pipeline: "
            f"{saude:.2f}%"
        )

        # ========================================================
        # ETAPA 15
        # ========================================================

        titulo(
            "ETAPA 15 - CONSOLIDANDO METRICAS V2"
        )

        metricas = {
            "projeto":
                PROJETO,

            "aula":
                AULA,

            "versao":
                VERSAO,

            "timestamp":
                agora_iso(),

            "pipeline": {
                "componentes_esperados":
                    esperados,

                "componentes_disponiveis":
                    disponiveis,

                "cobertura_percentual":
                    round(
                        cobertura,
                        2
                    ),

                "registros_historicos":
                    registros_historicos,

                "iocs_historicos":
                    len(
                        iocs_historicos
                    ),

                "iocs_ativos":
                    len(
                        iocs_ativos
                    ),

                "lista_iocs_historicos":
                    sorted(
                        iocs_historicos
                    ),

                "lista_iocs_ativos":
                    sorted(
                        iocs_ativos
                    ),

                "valores_ioc_ignorados":
                    sorted(
                        valores_invalidos
                    ),

                "componentes":
                    componentes_status
            },

            "evidence":
                evidence,

            "decisoes":
                decisoes,

            "casos":
                casos,

            "campanhas":
                campanhas,

            "timelines":
                timelines,

            "lifecycle":
                lifecycle,

            "aprovacoes":
                aprovacoes,

            "consistencia": {
                "evidence_decision":
                    evidence_decision_ok,

                "decision_cases":
                    decision_cases_ok,

                "evidence_cases":
                    evidence_cases_ok
            },

            "seguranca": {
                "execucoes_reais":
                    execucoes,

                "bloqueios_automaticos":
                    bloqueios,

                "modo_operacional":
                    MODO_OPERACIONAL,

                "ok":
                    seguranca_ok
            },

            "saude": {
                "validacoes":
                    total,

                "aprovadas":
                    aprovadas,

                "percentual":
                    round(
                        saude,
                        2
                    )
            }
        }

        ok(
            "Metricas V2 consolidadas"
        )

        # ========================================================
        # ETAPA 16
        # ========================================================

        titulo(
            "ETAPA 16 - PERSISTINDO SNAPSHOT"
        )

        snapshot = {
            "snapshot_id":
                gerar_id(
                    "OBS-45-V2"
                ),

            "timestamp":
                agora_iso(),

            "componentes_esperados":
                esperados,

            "componentes_disponiveis":
                disponiveis,

            "cobertura_componentes":
                round(
                    cobertura,
                    2
                ),

            "registros_pipeline":
                registros_historicos,

            # Compatibilidade
            "iocs_unicos":
                len(
                    iocs_ativos
                ),

            "iocs_historicos":
                len(
                    iocs_historicos
                ),

            "iocs_ativos":
                len(
                    iocs_ativos
                ),

            "evidence_score_medio":
                evidence[
                    "score_medio"
                ],

            "decision_score_medio":
                decisoes[
                    "score_medio"
                ],

            "casos_soc":
                casos[
                    "atuais"
                ],

            "casos_criticos":
                casos[
                    "criticos"
                ],

            "transicoes_lifecycle":
                lifecycle[
                    "transicoes"
                ],

            "aprovacoes_humanas":
                aprovacoes[
                    "registros"
                ],

            "acoes_autorizadas":
                aprovacoes[
                    "acoes_autorizadas"
                ],

            "execucoes_reais":
                execucoes,

            "bloqueios_automaticos":
                bloqueios,

            "validacoes_total":
                total,

            "validacoes_ok":
                aprovadas,

            "saude_pipeline":
                round(
                    saude,
                    2
                )
        }

        persistir_snapshot(
            conexao,
            snapshot
        )

        ok(
            f"Snapshot V2 persistido: "
            f"{snapshot['snapshot_id']}"
        )

        # ========================================================
        # ETAPA 17
        # ========================================================

        titulo(
            "ETAPA 17 - EXPORTANDO METRICAS"
        )

        salvar_json(
            ARQUIVO_METRICAS_JSON,
            metricas
        )

        ok(
            "Metricas JSON V2 salvas"
        )

        print(
            "Arquivo: "
            "metricas\\soc_metrics_aula_45.json"
        )

        salvar_prometheus(
            ARQUIVO_METRICAS_PROM,
            metricas
        )

        ok(
            "Metricas Prometheus-like V2 salvas"
        )

        print(
            "Arquivo: "
            "metricas\\soc_metrics_aula_45.prom"
        )

        # ========================================================
        # ETAPA 18
        # ========================================================

        titulo(
            "ETAPA 18 - FILA SOC ATUAL"
        )

        for posicao, caso in enumerate(
            casos[
                "fila"
            ],
            start=1
        ):

            print(
                f"{posicao:02d} | "
                f"{caso['ioc']} | "
                f"{caso['prioridade']} | "
                f"Decision Score "
                f"{caso['decision_score']:.2f} | "
                f"{caso['status']} | "
                f"{caso['fase']}"
            )

        # ========================================================
        # ETAPA 19
        # ========================================================

        titulo(
            "ETAPA 19 - RELATORIO FINAL"
        )

        relatorio = {
            "projeto":
                PROJETO,

            "aula":
                AULA,

            "versao":
                VERSAO,

            "titulo":
                "SOC Metrics & Observability V2",

            "timestamp":
                agora_iso(),

            "componentes":
                f"{disponiveis}/{esperados}",

            "cobertura":
                round(
                    cobertura,
                    2
                ),

            "registros_historicos":
                registros_historicos,

            "iocs_historicos":
                len(
                    iocs_historicos
                ),

            "iocs_ativos":
                len(
                    iocs_ativos
                ),

            "evidence_historicos":
                evidence[
                    "historicos"
                ],

            "evidence_atuais":
                evidence[
                    "atuais"
                ],

            "evidence_score_atual_medio":
                evidence[
                    "score_medio"
                ],

            "decisoes_historicas":
                decisoes[
                    "historicos"
                ],

            "decisoes_atuais":
                decisoes[
                    "atuais"
                ],

            "decision_score_atual_medio":
                decisoes[
                    "score_medio"
                ],

            "casos_historicos":
                casos[
                    "historicos"
                ],

            "casos_atuais":
                casos[
                    "atuais"
                ],

            "casos_criticos":
                casos[
                    "criticos"
                ],

            "campanhas_detectadas":
                campanhas[
                    "detectadas"
                ],

            "timelines_criticas":
                timelines[
                    "criticas"
                ],

            "transicoes_lifecycle":
                lifecycle[
                    "transicoes"
                ],

            "aprovacoes_humanas":
                aprovacoes[
                    "registros"
                ],

            "acoes_autorizadas":
                aprovacoes[
                    "acoes_autorizadas"
                ],

            "execucoes_reais":
                execucoes,

            "bloqueios_automaticos":
                bloqueios,

            "consistencia_iocs":
                (
                    evidence_decision_ok
                    and
                    decision_cases_ok
                    and
                    evidence_cases_ok
                ),

            "validacoes": {
                "total":
                    total,

                "aprovadas":
                    aprovadas,

                "saude":
                    round(
                        saude,
                        2
                    )
            },

            "modo_operacional":
                MODO_OPERACIONAL,

            "status": (
                "AULA 45 V2 CONCLUIDA"
                if aprovadas
                == total
                else
                "AULA 45 V2 COM PENDENCIAS"
            )
        }

        salvar_json(
            ARQUIVO_RELATORIO,
            relatorio
        )

        ok(
            "Relatorio V2 salvo"
        )

        print(
            "Arquivo: "
            "alertas\\relatorio_aula_45.json"
        )

        # ========================================================
        # RESUMO FINAL
        # ========================================================

        titulo(
            "RESUMO FINAL DA AULA 45 V2"
        )

        print(
            f"Componentes: "
            f"{disponiveis}/{esperados}"
        )

        print(
            f"Cobertura: "
            f"{cobertura:.2f}%"
        )

        print()

        print(
            f"Registros historicos: "
            f"{registros_historicos}"
        )

        print()

        print(
            f"IOCs historicos validos: "
            f"{len(iocs_historicos)}"
        )

        print(
            f"IOCs ativos: "
            f"{len(iocs_ativos)}"
        )

        print()

        print(
            "Evidence:"
        )

        print(
            f"Historico: "
            f"{evidence['historicos']}"
        )

        print(
            f"Atual: "
            f"{evidence['atuais']}"
        )

        print(
            "Score atual medio: "
            f"{evidence['score_medio']:.2f}"
        )

        print()

        print(
            "Decision Engine:"
        )

        print(
            f"Historico: "
            f"{decisoes['historicos']}"
        )

        print(
            f"Atual: "
            f"{decisoes['atuais']}"
        )

        print(
            "Score atual medio: "
            f"{decisoes['score_medio']:.2f}"
        )

        print()

        print(
            "Case Management:"
        )

        print(
            f"Historico: "
            f"{casos['historicos']}"
        )

        print(
            f"Atual: "
            f"{casos['atuais']}"
        )

        print(
            f"Criticos: "
            f"{casos['criticos']}"
        )

        print()

        print(
            "Consistencia:"
        )

        print(
            "Evidence = Decision: "
            f"{'SIM' if evidence_decision_ok else 'NAO'}"
        )

        print(
            "Decision = Cases: "
            f"{'SIM' if decision_cases_ok else 'NAO'}"
        )

        print(
            "Evidence = Cases: "
            f"{'SIM' if evidence_cases_ok else 'NAO'}"
        )

        print()

        print(
            f"Campanhas detectadas: "
            f"{campanhas['detectadas']}"
        )

        print(
            f"Timelines criticas: "
            f"{timelines['criticas']}"
        )

        print(
            f"Transicoes Lifecycle: "
            f"{lifecycle['transicoes']}"
        )

        print(
            f"Aprovacoes humanas: "
            f"{aprovacoes['registros']}"
        )

        print()

        print(
            f"Execucoes reais: "
            f"{execucoes}"
        )

        print(
            f"Bloqueios automaticos: "
            f"{bloqueios}"
        )

        print()

        print(
            f"Validacoes: "
            f"{aprovadas}/{total}"
        )

        print(
            f"Saude do pipeline: "
            f"{saude:.2f}%"
        )

        print(
            f"Modo operacional: "
            f"{MODO_OPERACIONAL}"
        )

        print()

        if aprovadas == total:

            print(
                "Status: AULA 45 V2 CONCLUIDA"
            )

        else:

            print(
                "Status: AULA 45 V2 COM PENDENCIAS"
            )

        # ========================================================
        # ARQUITETURA
        # ========================================================

        titulo(
            "ARQUITETURA DE OBSERVABILIDADE V2"
        )

        print(
r"""
                 CYBERSENTINEL-ML
                        |
                        v
                HISTORICO SQLITE
                        |
             +----------+----------+
             |                     |
             v                     v
       REGISTROS BRUTOS       VALIDACAO IOC
             |                     |
             |                IP VALIDO?
             |                     |
             |              +------+------+
             |              |             |
             |             SIM           NAO
             |              |             |
             |              v             v
             |         IOC HISTORICO    IGNORA
             |
             v
       DEDUPLICACAO POR IOC
             |
             +------------------------------+
             |              |               |
             v              v               v
         EVIDENCE        DECISION          CASE
          ATUAL           ATUAL           ATUAL
             |              |               |
             +--------------+---------------+
                            |
                            v
                    VALIDAR CONSISTENCIA
                            |
                   +--------+--------+
                   |                 |
                   v                 v
                  OK              DIVERGENCIA
                   |
                   v
                    IOCs ATIVOS
                            |
                            v
                 METRICS & OBSERVABILITY
                            |
              +-------------+-------------+
              |             |             |
              v             v             v
          HISTORICO       ATUAL        HEALTH
              |             |             |
              +-------------+-------------+
                            |
                            v
                       SNAPSHOT
                            |
                            v
                   JSON / PROMETHEUS


REGRAS V2:

HISTORICO != ESTADO ATUAL

REGISTRO != IOC

IOC DEVE SER IP VALIDO

PLACEHOLDER != IOC

Evidence historico != Evidence atual

Decision historica != Decision atual

Cases historicos != Cases atuais


OBSERVABILIDADE NAO:

- classifica ataques
- altera Risk Score
- altera Decision Score
- toma nova decisao
- executa playbook
- executa contencao
- bloqueia IP
- altera firewall


Modo operacional: SIMULACAO.
"""
        )

        linha()
        print(PROJETO)
        linha()

        print(
            "AULA 45 V2 - SOC METRICS & OBSERVABILITY"
        )

        if aprovadas == total:

            print(
                "AULA 45 V2 CONCLUIDA"
            )

        else:

            print(
                "AULA 45 V2 COM PENDENCIAS"
            )

    except sqlite3.Error as excecao:

        titulo(
            "ERRO SQLITE - AULA 45 V2"
        )

        erro(
            str(excecao)
        )

        print(
            "AULA 45 V2 COM PENDENCIAS"
        )

    except Exception as excecao:

        titulo(
            "ERRO INESPERADO - AULA 45 V2"
        )

        erro(
            f"{type(excecao).__name__}: "
            f"{excecao}"
        )

        print(
            "AULA 45 V2 COM PENDENCIAS"
        )

    finally:

        if conexao is not None:
            conexao.close()


# ================================================================
# EXECUCAO
# ================================================================

if __name__ == "__main__":
    main()