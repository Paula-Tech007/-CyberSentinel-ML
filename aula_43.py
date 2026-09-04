# ================================================================
# AULA 43 - SOC CASE LIFECYCLE & STATE MANAGEMENT
# CyberSentinel-ML
#
# Objetivo:
# Gerenciar o ciclo de vida dos casos SOC criados na Aula 42,
# controlando status, fases, transicoes, historico e SLA.
#
# IMPORTANTE:
# - Nenhuma contencao sera executada.
# - Nenhum IP sera bloqueado automaticamente.
# - Nenhuma regra de firewall sera alterada.
# - O sistema permanece em modo SIMULACAO.
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
AULA = 43
VERSAO = "1.0"

BASE_DIR = Path(__file__).resolve().parent

DADOS_DIR = BASE_DIR / "dados"
CASOS_DIR = BASE_DIR / "casos"
ALERTAS_DIR = BASE_DIR / "alertas"

DB_PATH = DADOS_DIR / "cybersentinel.db"

ARQUIVO_LIFECYCLE = (
    CASOS_DIR / "case_lifecycle_aula_43.json"
)

ARQUIVO_ALERTAS = (
    ALERTAS_DIR / "alertas_case_lifecycle_aula_43.json"
)

ARQUIVO_RELATORIO = (
    ALERTAS_DIR / "relatorio_aula_43.json"
)

TABELA_CASOS = "soc_incident_cases"
TABELA_TRANSICOES = "soc_case_transitions"

MODO_OPERACIONAL = "SIMULACAO"

LARGURA = 72


# ================================================================
# FUNCOES VISUAIS
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


def alerta(texto):
    print(f"[ALERTA] {texto}")


def erro(texto):
    print(f"[ERRO] {texto}")


# ================================================================
# FUNCOES AUXILIARES
# ================================================================

def agora_iso():
    return datetime.now(timezone.utc).isoformat()


def gerar_id(prefixo):
    timestamp = datetime.now(
        timezone.utc
    ).strftime("%Y%m%d%H%M%S%f")

    sufixo = uuid.uuid4().hex[:8].upper()

    return (
        f"{prefixo}-"
        f"{timestamp}-"
        f"{sufixo}"
    )


def salvar_json(caminho, dados):
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


def texto(valor, padrao="NAO_DISPONIVEL"):
    if valor is None:
        return padrao

    valor = str(valor).strip()

    if not valor:
        return padrao

    return valor


def numero(valor, padrao=0.0):
    try:
        if valor is None:
            return padrao

        return float(valor)

    except (TypeError, ValueError):
        return padrao


def inteiro(valor, padrao=0):
    try:
        if valor is None:
            return padrao

        return int(valor)

    except (TypeError, ValueError):
        return padrao


def booleano(valor):
    if isinstance(valor, bool):
        return valor

    if valor is None:
        return False

    if isinstance(valor, (int, float)):
        return valor != 0

    return str(valor).strip().upper() in {
        "SIM",
        "TRUE",
        "1",
        "YES",
        "VERDADEIRO"
    }


def sim_nao(valor):
    return "SIM" if booleano(valor) else "NAO"


def primeiro_valor(
    registro,
    nomes,
    padrao=None
):
    if not registro:
        return padrao

    for nome in nomes:

        if nome in registro:

            valor = registro.get(nome)

            if valor is not None:
                return valor

    return padrao


# ================================================================
# SQLITE
# ================================================================

def conectar_banco():
    conexao = sqlite3.connect(DB_PATH)
    conexao.row_factory = sqlite3.Row

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

    return cursor.fetchone() is not None


def obter_colunas(
    conexao,
    tabela
):
    cursor = conexao.cursor()

    cursor.execute(
        f"PRAGMA table_info({tabela})"
    )

    return [
        registro["name"]
        for registro in cursor.fetchall()
    ]


def carregar_casos(
    conexao
):
    cursor = conexao.cursor()

    cursor.execute(
        f"""
        SELECT *
        FROM {TABELA_CASOS}
        ORDER BY
            COALESCE(
                timestamp,
                timestamp_criacao,
                criado_em
            ) ASC
        """
    )

    return [
        dict(registro)
        for registro in cursor.fetchall()
    ]


# ================================================================
# TABELA DE TRANSICOES
# ================================================================

def criar_tabela_transicoes(
    conexao
):
    cursor = conexao.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS soc_case_transitions (
            transition_id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,

            case_id TEXT NOT NULL,
            ip_origem TEXT,

            status_anterior TEXT,
            status_novo TEXT,

            fase_anterior TEXT,
            fase_nova TEXT,

            owner_anterior TEXT,
            owner_novo TEXT,

            motivo TEXT,

            prioridade_soc TEXT,
            decision_score REAL,

            sla TEXT,

            transicao_permitida INTEGER,
            requer_aprovacao_humana INTEGER,

            bloqueio_automatico INTEGER,

            modo_operacional TEXT
        )
        """
    )

    conexao.commit()


def migrar_tabela_transicoes(
    conexao
):
    necessarias = {
        "transition_id": "TEXT",
        "timestamp": "TEXT",

        "case_id": "TEXT",
        "ip_origem": "TEXT",

        "status_anterior": "TEXT",
        "status_novo": "TEXT",

        "fase_anterior": "TEXT",
        "fase_nova": "TEXT",

        "owner_anterior": "TEXT",
        "owner_novo": "TEXT",

        "motivo": "TEXT",

        "prioridade_soc": "TEXT",
        "decision_score": "REAL",

        "sla": "TEXT",

        "transicao_permitida": "INTEGER",
        "requer_aprovacao_humana": "INTEGER",

        "bloqueio_automatico": "INTEGER",

        "modo_operacional": "TEXT"
    }

    atuais = obter_colunas(
        conexao,
        TABELA_TRANSICOES
    )

    cursor = conexao.cursor()
    adicionadas = []

    for coluna, tipo in necessarias.items():

        if coluna not in atuais:

            cursor.execute(
                f"""
                ALTER TABLE {TABELA_TRANSICOES}
                ADD COLUMN {coluna} {tipo}
                """
            )

            adicionadas.append(
                coluna
            )

    conexao.commit()

    return adicionadas


# ================================================================
# NORMALIZACAO DOS CASOS
# ================================================================

def normalizar_caso(
    registro
):
    return {
        "case_id": texto(
            primeiro_valor(
                registro,
                ["case_id"]
            )
        ),

        "ip_origem": texto(
            primeiro_valor(
                registro,
                [
                    "ip_origem",
                    "ioc",
                    "ip"
                ]
            )
        ),

        "prioridade_soc": texto(
            primeiro_valor(
                registro,
                [
                    "prioridade_soc",
                    "prioridade"
                ],
                "BAIXO"
            ),
            "BAIXO"
        ).upper(),

        "decision_score": numero(
            primeiro_valor(
                registro,
                ["decision_score"],
                0
            )
        ),

        "status_caso": texto(
            primeiro_valor(
                registro,
                [
                    "status_caso",
                    "status"
                ],
                "MONITORAMENTO"
            ),
            "MONITORAMENTO"
        ).upper(),

        "fase": texto(
            primeiro_valor(
                registro,
                [
                    "fase",
                    "fase_caso"
                ],
                "MONITORAMENTO"
            ),
            "MONITORAMENTO"
        ).upper(),

        "owner": texto(
            primeiro_valor(
                registro,
                ["owner"],
                "SOC_MONITORING_QUEUE"
            )
        ),

        "sla": texto(
            primeiro_valor(
                registro,
                [
                    "sla",
                    "sla_recomendado"
                ],
                "NAO_DISPONIVEL"
            )
        ),

        "requer_analista": booleano(
            primeiro_valor(
                registro,
                ["requer_analista"],
                False
            )
        ),

        "requer_escalacao": booleano(
            primeiro_valor(
                registro,
                ["requer_escalacao"],
                False
            )
        ),

        "preparar_contencao": booleano(
            primeiro_valor(
                registro,
                ["preparar_contencao"],
                False
            )
        ),

        "bloqueio_automatico": booleano(
            primeiro_valor(
                registro,
                ["bloqueio_automatico"],
                False
            )
        ),

        "modo_operacional": texto(
            primeiro_valor(
                registro,
                ["modo_operacional"],
                MODO_OPERACIONAL
            ),
            MODO_OPERACIONAL
        )
    }


# ================================================================
# DEDUPLICACAO
# ================================================================

def deduplicar_casos(
    registros
):
    indice = {}

    for registro in registros:

        caso = normalizar_caso(
            registro
        )

        ip = caso[
            "ip_origem"
        ]

        if ip == "NAO_DISPONIVEL":
            continue

        atual = indice.get(ip)

        if atual is None:
            indice[ip] = caso
            continue

        if (
            caso["decision_score"]
            > atual["decision_score"]
        ):
            indice[ip] = caso

    casos = list(
        indice.values()
    )

    casos.sort(
        key=lambda x: (
            x["decision_score"]
        ),
        reverse=True
    )

    return casos


# ================================================================
# MAPA DE TRANSICOES
# ================================================================

TRANSICOES_PERMITIDAS = {
    "MONITORAMENTO": {
        "MONITORAMENTO",
        "ABERTO",
        "EM_TRIAGEM"
    },

    "ABERTO": {
        "EM_TRIAGEM",
        "EM_INVESTIGACAO",
        "ESCALADO"
    },

    "ABERTO_PRIORITARIO": {
        "EM_INVESTIGACAO",
        "ESCALADO",
        "AGUARDANDO_APROVACAO"
    },

    "EM_TRIAGEM": {
        "EM_INVESTIGACAO",
        "ESCALADO",
        "MONITORAMENTO",
        "RESOLVIDO"
    },

    "EM_INVESTIGACAO": {
        "ESCALADO",
        "AGUARDANDO_APROVACAO",
        "RESOLVIDO"
    },

    "ESCALADO": {
        "AGUARDANDO_APROVACAO",
        "EM_INVESTIGACAO",
        "RESOLVIDO"
    },

    "AGUARDANDO_APROVACAO": {
        "EM_INVESTIGACAO",
        "RESOLVIDO"
    },

    "RESOLVIDO": {
        "ENCERRADO",
        "EM_INVESTIGACAO"
    },

    "ENCERRADO": {
        "ENCERRADO"
    }
}


# ================================================================
# POLITICA DE EVOLUCAO
# ================================================================

def determinar_proxima_etapa(
    caso
):
    prioridade = caso[
        "prioridade_soc"
    ]

    status_atual = caso[
        "status_caso"
    ]

    # ============================================================
    # CRITICO
    # ============================================================

    if prioridade == "CRITICO":

        if status_atual in {
            "ABERTO_PRIORITARIO",
            "ABERTO"
        }:

            return {
                "status_novo":
                    "ESCALADO",

                "fase_nova":
                    "ESCALACAO",

                "owner_novo":
                    "SOC_ANALYST_ESCALATION",

                "motivo":
                    "Caso critico priorizado pelo "
                    "SOC Decision Engine.",

                "requer_aprovacao_humana":
                    True
            }

        if status_atual == "ESCALADO":

            return {
                "status_novo":
                    "AGUARDANDO_APROVACAO",

                "fase_nova":
                    "PREPARACAO_CONTENCAO",

                "owner_novo":
                    "SOC_ANALYST_ESCALATION",

                "motivo":
                    "Contexto de contencao preparado "
                    "e aguardando aprovacao humana.",

                "requer_aprovacao_humana":
                    True
            }

        return {
            "status_novo":
                status_atual,

            "fase_nova":
                caso["fase"],

            "owner_novo":
                caso["owner"],

            "motivo":
                "Caso critico permanece sob "
                "acompanhamento humano.",

            "requer_aprovacao_humana":
                True
        }

    # ============================================================
    # ALTO
    # ============================================================

    if prioridade == "ALTO":

        if status_atual in {
            "ABERTO",
            "EM_TRIAGEM"
        }:

            return {
                "status_novo":
                    "EM_INVESTIGACAO",

                "fase_nova":
                    "INVESTIGACAO",

                "owner_novo":
                    "SOC_ANALYST_QUEUE",

                "motivo":
                    "Caso de alta prioridade "
                    "encaminhado para investigacao.",

                "requer_aprovacao_humana":
                    True
            }

    # ============================================================
    # MEDIO
    # ============================================================

    if prioridade == "MEDIO":

        if status_atual == "ABERTO":

            return {
                "status_novo":
                    "EM_TRIAGEM",

                "fase_nova":
                    "TRIAGEM",

                "owner_novo":
                    "SOC_TRIAGE_QUEUE",

                "motivo":
                    "Caso medio encaminhado para triagem.",

                "requer_aprovacao_humana":
                    True
            }

    # ============================================================
    # BAIXO
    # ============================================================

    return {
        "status_novo":
            "MONITORAMENTO",

        "fase_nova":
            "MONITORAMENTO",

        "owner_novo":
            "SOC_MONITORING_QUEUE",

        "motivo":
            "Caso de baixa prioridade permanece "
            "em monitoramento.",

        "requer_aprovacao_humana":
            False
    }


# ================================================================
# VALIDACAO DE TRANSICAO
# ================================================================

def transicao_permitida(
    status_anterior,
    status_novo
):
    permitidas = TRANSICOES_PERMITIDAS.get(
        status_anterior,
        set()
    )

    return (
        status_novo
        in permitidas
    )


# ================================================================
# SLA
# ================================================================

def classificar_sla(
    caso
):
    prioridade = caso[
        "prioridade_soc"
    ]

    if prioridade == "CRITICO":
        return {
            "classe": "IMEDIATO",
            "prioridade": 4
        }

    if prioridade == "ALTO":
        return {
            "classe": "ATE_30_MINUTOS",
            "prioridade": 3
        }

    if prioridade == "MEDIO":
        return {
            "classe": "ATE_2_HORAS",
            "prioridade": 2
        }

    return {
        "classe": "ATE_8_HORAS",
        "prioridade": 1
    }


# ================================================================
# PERSISTENCIA DA TRANSICAO
# ================================================================

def persistir_transicao(
    conexao,
    transicao
):
    cursor = conexao.cursor()

    cursor.execute(
        """
        INSERT INTO soc_case_transitions (
            transition_id,
            timestamp,

            case_id,
            ip_origem,

            status_anterior,
            status_novo,

            fase_anterior,
            fase_nova,

            owner_anterior,
            owner_novo,

            motivo,

            prioridade_soc,
            decision_score,

            sla,

            transicao_permitida,
            requer_aprovacao_humana,

            bloqueio_automatico,

            modo_operacional
        )
        VALUES (
            ?, ?,
            ?, ?,
            ?, ?,
            ?, ?,
            ?, ?,
            ?,
            ?, ?,
            ?,
            ?, ?,
            ?,
            ?
        )
        """,
        (
            transicao[
                "transition_id"
            ],

            transicao[
                "timestamp"
            ],

            transicao[
                "case_id"
            ],

            transicao[
                "ip_origem"
            ],

            transicao[
                "status_anterior"
            ],

            transicao[
                "status_novo"
            ],

            transicao[
                "fase_anterior"
            ],

            transicao[
                "fase_nova"
            ],

            transicao[
                "owner_anterior"
            ],

            transicao[
                "owner_novo"
            ],

            transicao[
                "motivo"
            ],

            transicao[
                "prioridade_soc"
            ],

            transicao[
                "decision_score"
            ],

            transicao[
                "sla"
            ],

            int(
                transicao[
                    "transicao_permitida"
                ]
            ),

            int(
                transicao[
                    "requer_aprovacao_humana"
                ]
            ),

            0,

            MODO_OPERACIONAL
        )
    )

    conexao.commit()


# ================================================================
# ATUALIZACAO DO CASO
# ================================================================

def atualizar_caso(
    conexao,
    transicao
):
    """
    Atualiza somente estado operacional do caso.

    Nenhuma acao de contencao e executada.
    """

    colunas = obter_colunas(
        conexao,
        TABELA_CASOS
    )

    cursor = conexao.cursor()

    atualizacoes = []
    parametros = []

    # Status
    if "status_caso" in colunas:

        atualizacoes.append(
            "status_caso = ?"
        )

        parametros.append(
            transicao["status_novo"]
        )

    # Fase
    if "fase" in colunas:

        atualizacoes.append(
            "fase = ?"
        )

        parametros.append(
            transicao["fase_nova"]
        )

    elif "fase_caso" in colunas:

        atualizacoes.append(
            "fase_caso = ?"
        )

        parametros.append(
            transicao["fase_nova"]
        )

    # Owner
    if "owner" in colunas:

        atualizacoes.append(
            "owner = ?"
        )

        parametros.append(
            transicao["owner_novo"]
        )

    # Timestamp atualizacao
    if "timestamp_atualizacao" in colunas:

        atualizacoes.append(
            "timestamp_atualizacao = ?"
        )

        parametros.append(
            agora_iso()
        )

    if not atualizacoes:
        return False

    parametros.append(
        transicao["case_id"]
    )

    sql = (
        f"""
        UPDATE {TABELA_CASOS}
        SET
            {", ".join(atualizacoes)}
        WHERE case_id = ?
        """
    )

    cursor.execute(
        sql,
        parametros
    )

    conexao.commit()

    return True


# ================================================================
# MAIN
# ================================================================

def main():

    titulo(
        "AULA 43 - SOC CASE LIFECYCLE & STATE MANAGEMENT"
    )

    print(PROJETO)
    print(
        "SOC Case Lifecycle + State Management"
    )
    print()

    print("Objetivo:")
    print(
        "Gerenciar a evolucao operacional dos casos SOC"
    )
    print(
        "criando transicoes controladas de status e fase."
    )
    print()

    print("IMPORTANTE:")
    print(
        "Nenhuma contencao sera executada."
    )
    print(
        "Nenhum IP sera bloqueado automaticamente."
    )
    print(
        "Nenhuma regra de firewall sera alterada."
    )
    print(
        "O sistema permanece em modo SIMULACAO."
    )
    print()

    validacoes = []

    conexao = None

    try:

        # ========================================================
        # ETAPA 1
        # ========================================================

        titulo(
            "ETAPA 1 - PREPARANDO DIRETORIOS"
        )

        for nome, diretorio in [
            ("dados", DADOS_DIR),
            ("casos", CASOS_DIR),
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
                f"Banco SQLite nao encontrado: "
                f"{DB_PATH}"
            )

            return

        ok(
            "Banco SQLite encontrado"
        )

        print(
            f"Banco: "
            f"{DB_PATH.relative_to(BASE_DIR)}"
        )

        validacoes.append(
            (
                "Banco SQLite encontrado",
                True
            )
        )

        conexao = conectar_banco()

        # ========================================================
        # ETAPA 3
        # ========================================================

        titulo(
            "ETAPA 3 - VALIDANDO AULA 42"
        )

        casos_existem = tabela_existe(
            conexao,
            TABELA_CASOS
        )

        if casos_existem:

            ok(
                "Tabela soc_incident_cases encontrada"
            )

        else:

            erro(
                "Tabela soc_incident_cases nao encontrada"
            )

            return

        colunas_casos = obter_colunas(
            conexao,
            TABELA_CASOS
        )

        ok(
            f"Colunas soc_incident_cases: "
            f"{len(colunas_casos)}"
        )

        obrigatorias = [
            "case_id",
            "ip_origem",
            "prioridade_soc",
            "decision_score",
            "status_caso",
            "owner"
        ]

        schema_ok = True

        for coluna in obrigatorias:

            if coluna in colunas_casos:

                ok(
                    f"Coluna encontrada: {coluna}"
                )

            else:

                erro(
                    f"Coluna ausente: {coluna}"
                )

                schema_ok = False

        validacoes.append(
            (
                "Tabela Case Management disponivel",
                casos_existem
            )
        )

        validacoes.append(
            (
                "Schema Aula 42 compativel",
                schema_ok
            )
        )

        if not schema_ok:
            return

        # ========================================================
        # ETAPA 4
        # ========================================================

        titulo(
            "ETAPA 4 - PREPARANDO CASE LIFECYCLE"
        )

        criar_tabela_transicoes(
            conexao
        )

        ok(
            "Tabela soc_case_transitions pronta"
        )

        adicionadas = (
            migrar_tabela_transicoes(
                conexao
            )
        )

        if adicionadas:

            info(
                "Schema anterior detectado"
            )

            for coluna in adicionadas:

                ok(
                    f"Coluna adicionada: {coluna}"
                )

        else:

            ok(
                "Schema de transicoes compativel"
            )

        validacoes.append(
            (
                "Tabela de transicoes disponivel",
                tabela_existe(
                    conexao,
                    TABELA_TRANSICOES
                )
            )
        )

        # ========================================================
        # ETAPA 5
        # ========================================================

        titulo(
            "ETAPA 5 - CARREGANDO CASOS SOC"
        )

        casos_brutos = carregar_casos(
            conexao
        )

        ok(
            f"Casos historicos carregados: "
            f"{len(casos_brutos)}"
        )

        casos = deduplicar_casos(
            casos_brutos
        )

        ok(
            f"Casos deduplicados por IOC: "
            f"{len(casos)}"
        )

        for caso in casos:

            print(
                f"- {caso['ip_origem']} | "
                f"{caso['prioridade_soc']} | "
                f"Decision Score "
                f"{caso['decision_score']:.2f} | "
                f"{caso['status_caso']}"
            )

        validacoes.append(
            (
                "Casos SOC carregados",
                len(casos) > 0
            )
        )

        validacoes.append(
            (
                "Casos deduplicados",
                len(casos)
                <= len(casos_brutos)
            )
        )

        # ========================================================
        # ETAPA 6
        # ========================================================

        titulo(
            "ETAPA 6 - EXECUTANDO CASE LIFECYCLE ENGINE"
        )

        transicoes = []
        alertas = []

        for indice, caso in enumerate(
            casos,
            start=1
        ):

            separador()

            print(
                f"CASO {indice}/{len(casos)}"
            )

            separador()

            print(
                f"Case ID: {caso['case_id']}"
            )

            print(
                f"IOC: {caso['ip_origem']}"
            )

            print(
                f"Prioridade SOC: "
                f"{caso['prioridade_soc']}"
            )

            print(
                f"Decision Score: "
                f"{caso['decision_score']:.2f}/100"
            )

            print()

            print(
                "ESTADO ATUAL:"
            )

            print(
                f"Status: "
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

            print()

            proxima = (
                determinar_proxima_etapa(
                    caso
                )
            )

            permitido = (
                transicao_permitida(
                    caso["status_caso"],
                    proxima["status_novo"]
                )
            )

            sla = classificar_sla(
                caso
            )

            transition_id = gerar_id(
                "TRN-43"
            )

            transicao = {
                "transition_id":
                    transition_id,

                "timestamp":
                    agora_iso(),

                "case_id":
                    caso["case_id"],

                "ip_origem":
                    caso["ip_origem"],

                "status_anterior":
                    caso["status_caso"],

                "status_novo":
                    proxima["status_novo"],

                "fase_anterior":
                    caso["fase"],

                "fase_nova":
                    proxima["fase_nova"],

                "owner_anterior":
                    caso["owner"],

                "owner_novo":
                    proxima["owner_novo"],

                "motivo":
                    proxima["motivo"],

                "prioridade_soc":
                    caso["prioridade_soc"],

                "decision_score":
                    caso["decision_score"],

                "sla":
                    sla["classe"],

                "transicao_permitida":
                    permitido,

                "requer_aprovacao_humana":
                    proxima[
                        "requer_aprovacao_humana"
                    ],

                # REGRA DE SEGURANCA
                "bloqueio_automatico":
                    False,

                "modo_operacional":
                    MODO_OPERACIONAL
            }

            print(
                "TRANSICAO PROPOSTA:"
            )

            print(
                f"{transicao['status_anterior']} "
                f"-> "
                f"{transicao['status_novo']}"
            )

            print(
                f"Fase: "
                f"{transicao['fase_anterior']} "
                f"-> "
                f"{transicao['fase_nova']}"
            )

            print(
                f"Owner: "
                f"{transicao['owner_anterior']} "
                f"-> "
                f"{transicao['owner_novo']}"
            )

            print(
                f"SLA: "
                f"{transicao['sla']}"
            )

            print(
                f"Motivo: "
                f"{transicao['motivo']}"
            )

            print(
                "Requer aprovacao humana: "
                f"{sim_nao(
                    transicao[
                        'requer_aprovacao_humana'
                    ]
                )}"
            )

            print(
                "Bloqueio automatico: NAO"
            )

            print(
                f"Modo: "
                f"{MODO_OPERACIONAL}"
            )

            print()

            if permitido:

                ok(
                    "Transicao permitida"
                )

                persistir_transicao(
                    conexao,
                    transicao
                )

                atualizado = atualizar_caso(
                    conexao,
                    transicao
                )

                if atualizado:

                    ok(
                        "Caso atualizado no SQLite"
                    )

                else:

                    info(
                        "Nenhuma coluna de estado "
                        "precisou ser atualizada"
                    )

            else:

                erro(
                    "Transicao bloqueada pela "
                    "politica de lifecycle"
                )

            transicoes.append(
                transicao
            )

            if (
                caso["prioridade_soc"]
                == "CRITICO"
            ):

                alerta_id = gerar_id(
                    "LIFE-ALT-43"
                )

                alerta_lifecycle = {
                    "alerta_id":
                        alerta_id,

                    "timestamp":
                        agora_iso(),

                    "case_id":
                        caso["case_id"],

                    "ip_origem":
                        caso["ip_origem"],

                    "prioridade":
                        caso["prioridade_soc"],

                    "decision_score":
                        caso["decision_score"],

                    "status_anterior":
                        transicao[
                            "status_anterior"
                        ],

                    "status_novo":
                        transicao[
                            "status_novo"
                        ],

                    "fase_nova":
                        transicao[
                            "fase_nova"
                        ],

                    "requer_aprovacao_humana":
                        True,

                    "bloqueio_automatico":
                        False,

                    "modo":
                        MODO_OPERACIONAL
                }

                alertas.append(
                    alerta_lifecycle
                )

                alerta(
                    "Caso critico atualizado "
                    "no lifecycle"
                )

                ok(
                    f"Alerta: {alerta_id}"
                )

        # ========================================================
        # ETAPA 7
        # ========================================================

        titulo(
            "ETAPA 7 - ANALISANDO TRANSICOES"
        )

        permitidas = sum(
            1
            for t in transicoes
            if t["transicao_permitida"]
        )

        bloqueadas = (
            len(transicoes)
            - permitidas
        )

        humanas = sum(
            1
            for t in transicoes
            if t[
                "requer_aprovacao_humana"
            ]
        )

        print(
            f"Transicoes geradas: "
            f"{len(transicoes)}"
        )

        print(
            f"Transicoes permitidas: "
            f"{permitidas}"
        )

        print(
            f"Transicoes bloqueadas: "
            f"{bloqueadas}"
        )

        print(
            f"Requerem aprovacao humana: "
            f"{humanas}"
        )

        print(
            "Bloqueios automaticos: 0"
        )

        # ========================================================
        # ETAPA 8
        # ========================================================

        titulo(
            "ETAPA 8 - FILA DE CASOS ATUALIZADA"
        )

        casos_atualizados_brutos = (
            carregar_casos(
                conexao
            )
        )

        casos_atualizados = (
            deduplicar_casos(
                casos_atualizados_brutos
            )
        )

        fila = sorted(
            casos_atualizados,
            key=lambda x: (
                x["decision_score"]
            ),
            reverse=True
        )

        print(
            f"Casos na fila: "
            f"{len(fila)}"
        )

        print()

        for posicao, caso in enumerate(
            fila,
            start=1
        ):

            print(
                f"{posicao:02d} | "
                f"{caso['ip_origem']} | "
                f"{caso['prioridade_soc']} | "
                f"Decision Score "
                f"{caso['decision_score']:.2f} | "
                f"{caso['status_caso']} | "
                f"{caso['fase']}"
            )

        # ========================================================
        # ETAPA 9
        # ========================================================

        titulo(
            "ETAPA 9 - VALIDANDO SEGURANCA E CONSISTENCIA"
        )

        validacoes_lifecycle = []

        def validar(
            condicao,
            descricao
        ):
            resultado = bool(
                condicao
            )

            validacoes_lifecycle.append(
                (
                    descricao,
                    resultado
                )
            )

            if resultado:
                ok(descricao)
            else:
                erro(descricao)

        validar(
            len(transicoes) > 0,
            "Transicoes de lifecycle geradas"
        )

        validar(
            all(
                t["case_id"]
                for t in transicoes
            ),
            "Todas as transicoes possuem Case ID"
        )

        validar(
            all(
                t["ip_origem"]
                for t in transicoes
            ),
            "Todas as transicoes possuem IOC"
        )

        validar(
            all(
                t["transicao_permitida"]
                for t in transicoes
            ),
            "Todas as transicoes propostas sao permitidas"
        )

        validar(
            all(
                not t[
                    "bloqueio_automatico"
                ]
                for t in transicoes
            ),
            "Nenhum bloqueio automatico habilitado"
        )

        validar(
            all(
                t["modo_operacional"]
                == "SIMULACAO"
                for t in transicoes
            ),
            "Modo operacional permanece SIMULACAO"
        )

        criticas = [
            t
            for t in transicoes
            if t["prioridade_soc"]
            == "CRITICO"
        ]

        validar(
            all(
                t[
                    "requer_aprovacao_humana"
                ]
                for t in criticas
            ),
            "Transicoes criticas exigem aprovacao humana"
        )

        validar(
            all(
                t["status_novo"]
                != "ENCERRADO"
                for t in criticas
            ),
            "Casos criticos nao sao encerrados automaticamente"
        )

        seguranca_ok = all(
            resultado
            for _, resultado
            in validacoes_lifecycle
        )

        # ========================================================
        # ETAPA 10
        # ========================================================

        titulo(
            "ETAPA 10 - PERSISTINDO RESULTADOS"
        )

        salvar_json(
            ARQUIVO_LIFECYCLE,
            transicoes
        )

        ok(
            "Lifecycle salvo"
        )

        print(
            "Arquivo: "
            "casos\\case_lifecycle_aula_43.json"
        )

        salvar_json(
            ARQUIVO_ALERTAS,
            alertas
        )

        ok(
            "Alertas Lifecycle salvos"
        )

        print(
            "Arquivo: "
            "alertas\\alertas_case_lifecycle_aula_43.json"
        )

        # ========================================================
        # ETAPA 11
        # ========================================================

        titulo(
            "ETAPA 11 - VALIDACAO FINAL"
        )

        validacoes.extend(
            [
                (
                    "Tabela Case Management disponivel",
                    tabela_existe(
                        conexao,
                        TABELA_CASOS
                    )
                ),

                (
                    "Tabela Lifecycle disponivel",
                    tabela_existe(
                        conexao,
                        TABELA_TRANSICOES
                    )
                ),

                (
                    "Casos carregados",
                    len(casos) > 0
                ),

                (
                    "Casos deduplicados",
                    len(casos)
                    <= len(casos_brutos)
                ),

                (
                    "Transicoes geradas",
                    len(transicoes) > 0
                ),

                (
                    "Todas as transicoes permitidas",
                    all(
                        t[
                            "transicao_permitida"
                        ]
                        for t in transicoes
                    )
                ),

                (
                    "Casos atualizados",
                    len(casos_atualizados) > 0
                ),

                (
                    "Fila SOC atualizada",
                    len(fila)
                    == len(casos_atualizados)
                ),

                (
                    "Validacoes de seguranca aprovadas",
                    seguranca_ok
                ),

                (
                    "Nenhum bloqueio automatico",
                    all(
                        not t[
                            "bloqueio_automatico"
                        ]
                        for t in transicoes
                    )
                ),

                (
                    "Modo SIMULACAO preservado",
                    all(
                        t[
                            "modo_operacional"
                        ]
                        == MODO_OPERACIONAL
                        for t in transicoes
                    )
                ),

                (
                    "Arquivo Lifecycle criado",
                    ARQUIVO_LIFECYCLE.exists()
                ),

                (
                    "Arquivo de alertas criado",
                    ARQUIVO_ALERTAS.exists()
                )
            ]
        )

        # Remove duplicadas
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
                    resultado
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

        total_validacoes = len(
            unicas
        )

        saude = (
            aprovadas
            / total_validacoes
            * 100
            if total_validacoes
            else 0
        )

        print()

        print(
            f"Validacoes: "
            f"{aprovadas}/"
            f"{total_validacoes}"
        )

        print(
            f"Saude: "
            f"{saude:.2f}%"
        )

        # ========================================================
        # RELATORIO
        # ========================================================

        status_distribuicao = {}

        for caso in fila:

            status = caso[
                "status_caso"
            ]

            status_distribuicao[
                status
            ] = (
                status_distribuicao.get(
                    status,
                    0
                )
                + 1
            )

        relatorio = {
            "projeto":
                PROJETO,

            "aula":
                AULA,

            "versao":
                VERSAO,

            "timestamp":
                agora_iso(),

            "casos_historicos":
                len(casos_brutos),

            "casos_processados":
                len(casos),

            "transicoes":
                len(transicoes),

            "transicoes_permitidas":
                permitidas,

            "transicoes_bloqueadas":
                bloqueadas,

            "requerem_aprovacao_humana":
                humanas,

            "alertas":
                len(alertas),

            "status_casos":
                status_distribuicao,

            "bloqueios_automaticos":
                0,

            "modo_operacional":
                MODO_OPERACIONAL,

            "validacoes": {
                "total":
                    total_validacoes,

                "ok":
                    aprovadas,

                "saude":
                    round(
                        saude,
                        2
                    )
            },

            "status": (
                "AULA 43 CONCLUIDA"
                if aprovadas
                == total_validacoes
                else
                "AULA 43 COM PENDENCIAS"
            )
        }

        salvar_json(
            ARQUIVO_RELATORIO,
            relatorio
        )

        ok(
            "Relatorio salvo"
        )

        print(
            "Arquivo: "
            "alertas\\relatorio_aula_43.json"
        )

        # ========================================================
        # RESUMO FINAL
        # ========================================================

        titulo(
            "RESUMO FINAL DA AULA 43"
        )

        print(
            f"Casos historicos: "
            f"{len(casos_brutos)}"
        )

        print(
            f"Casos processados: "
            f"{len(casos)}"
        )

        print(
            f"Transicoes geradas: "
            f"{len(transicoes)}"
        )

        print(
            f"Transicoes permitidas: "
            f"{permitidas}"
        )

        print(
            f"Transicoes bloqueadas: "
            f"{bloqueadas}"
        )

        print(
            f"Requerem aprovacao humana: "
            f"{humanas}"
        )

        print(
            f"Alertas SOC: "
            f"{len(alertas)}"
        )

        print(
            "Bloqueios automaticos: 0"
        )

        print()
        print(
            "Status dos casos:"
        )

        for status, quantidade in (
            status_distribuicao.items()
        ):

            print(
                f"{status}: "
                f"{quantidade}"
            )

        print()

        print(
            f"Validacoes: "
            f"{aprovadas}/"
            f"{total_validacoes}"
        )

        print(
            f"Saude: "
            f"{saude:.2f}%"
        )

        print(
            f"Modo operacional: "
            f"{MODO_OPERACIONAL}"
        )

        if (
            aprovadas
            == total_validacoes
        ):

            print(
                "Status: AULA 43 CONCLUIDA"
            )

        else:

            print(
                "Status: "
                "AULA 43 COM PENDENCIAS"
            )

        # ========================================================
        # ARQUITETURA
        # ========================================================

        titulo(
            "ARQUITETURA DA AULA 43"
        )

        print(
r"""
               CYBERSENTINEL-ML
                      |
                      v
                 CASE MANAGEMENT
                    AULA 42
                      |
                      v
               CASE LIFECYCLE ENGINE
                      |
          +-----------+-----------+
          |                       |
          v                       v
       STATUS                    FASE
          |                       |
          +-----------+-----------+
                      |
                      v
              VALIDAR TRANSICAO
                      |
          +-----------+-----------+
          |                       |
          v                       v
     PERMITIDA                BLOQUEADA
          |                       |
          v                       v
    ATUALIZA CASO           MANTEM ESTADO
          |
          v
      HISTORICO DE TRANSICOES
          |
          +---- STATUS ANTERIOR
          +---- STATUS NOVO
          +---- FASE
          +---- OWNER
          +---- MOTIVO
          +---- TIMESTAMP
          |
          v
       SLA / PRIORIDADE
          |
          v
       FILA SOC ATUALIZADA
          |
          +-------------------------------+
          |                               |
          v                               v
     MONITORAMENTO                    CRITICO
                                          |
                                          v
                                     ESCALACAO
                                          |
                                          v
                              PREPARACAO CONTENCAO
                                          |
                                          v
                              AGUARDA APROVACAO HUMANA


TRANSICOES POSSIVEIS:

MONITORAMENTO
      |
      v
ABERTO
      |
      v
EM_TRIAGEM
      |
      v
EM_INVESTIGACAO
      |
      v
ESCALADO
      |
      v
AGUARDANDO_APROVACAO
      |
      v
RESOLVIDO
      |
      v
ENCERRADO


IMPORTANTE:

CASE LIFECYCLE != CONTENCAO AUTOMATICA.

PREPARAR CONTENCAO != EXECUTAR CONTENCAO.

AGUARDANDO_APROVACAO significa que o sistema
parou antes de qualquer acao operacional real.

Nenhum IP e bloqueado automaticamente.

Nenhuma regra de firewall e modificada.

Nenhuma acao destrutiva e executada.

O analista humano permanece no fluxo.

Modo operacional: SIMULACAO.
"""
        )

        linha()
        print(
            "CYBERSENTINEL-ML"
        )
        linha()

        print(
            "AULA 43 - SOC CASE LIFECYCLE"
        )

        if (
            aprovadas
            == total_validacoes
        ):

            print(
                "AULA 43 CONCLUIDA"
            )

        else:

            print(
                "AULA 43 COM PENDENCIAS"
            )

    except sqlite3.Error as excecao:

        titulo(
            "ERRO SQLITE - AULA 43"
        )

        print(
            f"[ERRO] {excecao}"
        )

        print()

        print(
            "Status: "
            "AULA 43 COM PENDENCIAS"
        )

    except Exception as excecao:

        titulo(
            "ERRO INESPERADO - AULA 43"
        )

        print(
            f"[ERRO] "
            f"{type(excecao).__name__}: "
            f"{excecao}"
        )

        print()

        print(
            "Status: "
            "AULA 43 COM PENDENCIAS"
        )

    finally:

        if conexao is not None:
            conexao.close()


# ================================================================
# EXECUCAO
# ================================================================

if __name__ == "__main__":
    main()