# ================================================================
# AULA 44 - HUMAN APPROVAL GATE
# CyberSentinel-ML
#
# Objetivo:
# Implementar o ponto de aprovacao humana do pipeline SOC.
#
# O sistema:
# - identifica casos que exigem aprovacao humana
# - registra a decisao do analista
# - registra justificativa
# - preserva audit trail
# - atualiza o lifecycle do caso
#
# IMPORTANTE:
# - Nenhuma contencao sera executada.
# - Nenhum IP sera bloqueado automaticamente.
# - Nenhuma regra de firewall sera alterada.
# - Aprovacao humana != execucao automatica.
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
AULA = 44
VERSAO = "1.0"

BASE_DIR = Path(__file__).resolve().parent

DADOS_DIR = BASE_DIR / "dados"
APROVACOES_DIR = BASE_DIR / "aprovacoes"
ALERTAS_DIR = BASE_DIR / "alertas"

DB_PATH = DADOS_DIR / "cybersentinel.db"

ARQUIVO_APROVACOES = (
    APROVACOES_DIR / "human_approvals_aula_44.json"
)

ARQUIVO_ALERTAS = (
    ALERTAS_DIR / "alertas_human_approval_aula_44.json"
)

ARQUIVO_RELATORIO = (
    ALERTAS_DIR / "relatorio_aula_44.json"
)

TABELA_CASOS = "soc_incident_cases"
TABELA_TRANSICOES = "soc_case_transitions"
TABELA_APROVACOES = "soc_human_approvals"

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


def carregar_tabela(
    conexao,
    tabela
):
    cursor = conexao.cursor()

    cursor.execute(
        f"""
        SELECT *
        FROM {tabela}
        """
    )

    return [
        dict(registro)
        for registro in cursor.fetchall()
    ]


# ================================================================
# TABELA DE APROVACOES
# ================================================================

def criar_tabela_aprovacoes(
    conexao
):
    cursor = conexao.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS soc_human_approvals (
            approval_id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,

            case_id TEXT NOT NULL,
            ip_origem TEXT,

            analista TEXT,

            decisao TEXT,
            justificativa TEXT,

            status_anterior TEXT,
            status_resultante TEXT,

            fase_anterior TEXT,
            fase_resultante TEXT,

            prioridade_soc TEXT,
            decision_score REAL,

            acao_recomendada TEXT,

            requer_acao INTEGER,
            acao_autorizada INTEGER,

            execucao_real INTEGER,
            bloqueio_automatico INTEGER,

            modo_operacional TEXT
        )
        """
    )

    conexao.commit()


def migrar_tabela_aprovacoes(
    conexao
):
    necessarias = {
        "approval_id": "TEXT",
        "timestamp": "TEXT",

        "case_id": "TEXT",
        "ip_origem": "TEXT",

        "analista": "TEXT",

        "decisao": "TEXT",
        "justificativa": "TEXT",

        "status_anterior": "TEXT",
        "status_resultante": "TEXT",

        "fase_anterior": "TEXT",
        "fase_resultante": "TEXT",

        "prioridade_soc": "TEXT",
        "decision_score": "REAL",

        "acao_recomendada": "TEXT",

        "requer_acao": "INTEGER",
        "acao_autorizada": "INTEGER",

        "execucao_real": "INTEGER",
        "bloqueio_automatico": "INTEGER",

        "modo_operacional": "TEXT"
    }

    atuais = obter_colunas(
        conexao,
        TABELA_APROVACOES
    )

    cursor = conexao.cursor()
    adicionadas = []

    for coluna, tipo in necessarias.items():

        if coluna not in atuais:

            cursor.execute(
                f"""
                ALTER TABLE {TABELA_APROVACOES}
                ADD COLUMN {coluna} {tipo}
                """
            )

            adicionadas.append(
                coluna
            )

    conexao.commit()

    return adicionadas


# ================================================================
# NORMALIZACAO DO CASO
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
                [
                    "decision_score"
                ],
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

        "acao_recomendada": texto(
            primeiro_valor(
                registro,
                [
                    "acao_recomendada",
                    "acao_playbook"
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

        atual = indice.get(
            ip
        )

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
        key=lambda x:
            x["decision_score"],
        reverse=True
    )

    return casos


# ================================================================
# CASOS QUE EXIGEM APROVACAO
# ================================================================

def requer_aprovacao(
    caso
):
    if (
        caso["prioridade_soc"]
        == "CRITICO"
    ):
        return True

    if (
        caso["status_caso"]
        in {
            "ESCALADO",
            "AGUARDANDO_APROVACAO"
        }
    ):
        return True

    if (
        caso["preparar_contencao"]
    ):
        return True

    return False


# ================================================================
# POLITICA DE DECISAO HUMANA
# ================================================================

DECISOES_VALIDAS = {
    "APROVADO",
    "REJEITADO",
    "ADIADO",
    "SOLICITAR_MAIS_EVIDENCIAS"
}


def aplicar_decisao_humana(
    caso,
    decisao
):
    decisao = (
        decisao
        .strip()
        .upper()
    )

    if decisao not in DECISOES_VALIDAS:

        raise ValueError(
            "Decisao humana invalida"
        )

    # ============================================================
    # APROVADO
    # ============================================================

    if decisao == "APROVADO":

        return {
            "status_resultante":
                "APROVADO_PARA_ACAO",

            "fase_resultante":
                "AGUARDANDO_EXECUCAO_EXTERNA",

            "requer_acao":
                True,

            "acao_autorizada":
                True
        }

    # ============================================================
    # REJEITADO
    # ============================================================

    if decisao == "REJEITADO":

        return {
            "status_resultante":
                "EM_INVESTIGACAO",

            "fase_resultante":
                "INVESTIGACAO",

            "requer_acao":
                False,

            "acao_autorizada":
                False
        }

    # ============================================================
    # ADIADO
    # ============================================================

    if decisao == "ADIADO":

        return {
            "status_resultante":
                "AGUARDANDO_APROVACAO",

            "fase_resultante":
                "APROVACAO_HUMANA",

            "requer_acao":
                False,

            "acao_autorizada":
                False
        }

    # ============================================================
    # MAIS EVIDENCIAS
    # ============================================================

    return {
        "status_resultante":
            "EM_INVESTIGACAO",

        "fase_resultante":
            "COLETA_EVIDENCIAS",

        "requer_acao":
            False,

        "acao_autorizada":
            False
    }


# ================================================================
# DECISAO SIMULADA DO LABORATORIO
# ================================================================

def obter_decisao_simulada(
    caso
):
    """
    Aula 44 continua sendo um laboratorio.

    O sistema nao se passa por um analista humano real.
    A decisao abaixo e explicitamente uma entrada simulada
    para testar o Approval Gate.

    Casos CRITICOS:
        APROVADO

    Demais casos:
        nenhuma aprovacao necessaria.
    """

    if (
        caso["prioridade_soc"]
        == "CRITICO"
    ):
        return {
            "analista":
                "ANALISTA_SOC_SIMULADO",

            "decisao":
                "APROVADO",

            "justificativa":
                (
                    "Aprovacao simulada para validar "
                    "o fluxo Human Approval Gate. "
                    "Nenhuma acao operacional real "
                    "sera executada."
                )
        }

    return None


# ================================================================
# PERSISTENCIA DA APROVACAO
# ================================================================

def persistir_aprovacao(
    conexao,
    aprovacao
):
    cursor = conexao.cursor()

    cursor.execute(
        """
        INSERT INTO soc_human_approvals (
            approval_id,
            timestamp,

            case_id,
            ip_origem,

            analista,

            decisao,
            justificativa,

            status_anterior,
            status_resultante,

            fase_anterior,
            fase_resultante,

            prioridade_soc,
            decision_score,

            acao_recomendada,

            requer_acao,
            acao_autorizada,

            execucao_real,
            bloqueio_automatico,

            modo_operacional
        )
        VALUES (
            ?, ?,
            ?, ?,
            ?,
            ?, ?,
            ?, ?,
            ?, ?,
            ?, ?,
            ?,
            ?, ?,
            ?, ?,
            ?
        )
        """,
        (
            aprovacao[
                "approval_id"
            ],

            aprovacao[
                "timestamp"
            ],

            aprovacao[
                "case_id"
            ],

            aprovacao[
                "ip_origem"
            ],

            aprovacao[
                "analista"
            ],

            aprovacao[
                "decisao"
            ],

            aprovacao[
                "justificativa"
            ],

            aprovacao[
                "status_anterior"
            ],

            aprovacao[
                "status_resultante"
            ],

            aprovacao[
                "fase_anterior"
            ],

            aprovacao[
                "fase_resultante"
            ],

            aprovacao[
                "prioridade_soc"
            ],

            aprovacao[
                "decision_score"
            ],

            aprovacao[
                "acao_recomendada"
            ],

            int(
                aprovacao[
                    "requer_acao"
                ]
            ),

            int(
                aprovacao[
                    "acao_autorizada"
                ]
            ),

            0,

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
    aprovacao
):
    colunas = obter_colunas(
        conexao,
        TABELA_CASOS
    )

    cursor = conexao.cursor()

    atualizacoes = []
    parametros = []

    if (
        "status_caso"
        in colunas
    ):
        atualizacoes.append(
            "status_caso = ?"
        )

        parametros.append(
            aprovacao[
                "status_resultante"
            ]
        )

    if "fase" in colunas:

        atualizacoes.append(
            "fase = ?"
        )

        parametros.append(
            aprovacao[
                "fase_resultante"
            ]
        )

    elif (
        "fase_caso"
        in colunas
    ):

        atualizacoes.append(
            "fase_caso = ?"
        )

        parametros.append(
            aprovacao[
                "fase_resultante"
            ]
        )

    if (
        "timestamp_atualizacao"
        in colunas
    ):

        atualizacoes.append(
            "timestamp_atualizacao = ?"
        )

        parametros.append(
            agora_iso()
        )

    if not atualizacoes:
        return False

    parametros.append(
        aprovacao[
            "case_id"
        ]
    )

    cursor.execute(
        f"""
        UPDATE {TABELA_CASOS}
        SET
            {", ".join(atualizacoes)}
        WHERE case_id = ?
        """,
        parametros
    )

    conexao.commit()

    return True


# ================================================================
# MAIN
# ================================================================

def main():

    titulo(
        "AULA 44 - HUMAN APPROVAL GATE"
    )

    print(PROJETO)
    print(
        "Human-in-the-Loop + Approval Audit"
    )
    print()

    print("Objetivo:")
    print(
        "Implementar o ponto de aprovacao humana "
        "do pipeline SOC."
    )
    print()

    print("IMPORTANTE:")
    print(
        "A aprovacao humana desta aula e simulada."
    )
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
        "Aprovacao != execucao."
    )
    print(
        "Modo operacional: SIMULACAO."
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
            (
                "aprovacoes",
                APROVACOES_DIR
            ),
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

            print(
                f"Esperado: {DB_PATH}"
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
            "ETAPA 3 - VALIDANDO PIPELINE ANTERIOR"
        )

        casos_existem = tabela_existe(
            conexao,
            TABELA_CASOS
        )

        transicoes_existem = tabela_existe(
            conexao,
            TABELA_TRANSICOES
        )

        if casos_existem:
            ok(
                "Tabela soc_incident_cases encontrada"
            )
        else:
            erro(
                "Tabela soc_incident_cases ausente"
            )

        if transicoes_existem:
            ok(
                "Tabela soc_case_transitions encontrada"
            )
        else:
            erro(
                "Tabela soc_case_transitions ausente"
            )

        validacoes.extend(
            [
                (
                    "Case Management disponivel",
                    casos_existem
                ),
                (
                    "Case Lifecycle disponivel",
                    transicoes_existem
                )
            ]
        )

        if (
            not casos_existem
            or not transicoes_existem
        ):
            return

        # ========================================================
        # ETAPA 4
        # ========================================================

        titulo(
            "ETAPA 4 - PREPARANDO HUMAN APPROVAL"
        )

        criar_tabela_aprovacoes(
            conexao
        )

        ok(
            "Tabela soc_human_approvals pronta"
        )

        adicionadas = (
            migrar_tabela_aprovacoes(
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
                "Schema Human Approval compativel"
            )

        validacoes.append(
            (
                "Tabela Human Approval disponivel",
                tabela_existe(
                    conexao,
                    TABELA_APROVACOES
                )
            )
        )

        # ========================================================
        # ETAPA 5
        # ========================================================

        titulo(
            "ETAPA 5 - CARREGANDO CASOS SOC"
        )

        casos_brutos = carregar_tabela(
            conexao,
            TABELA_CASOS
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
                f"{caso['status_caso']} | "
                f"Decision Score "
                f"{caso['decision_score']:.2f}"
            )

        validacoes.append(
            (
                "Casos SOC carregados",
                len(casos) > 0
            )
        )

        # ========================================================
        # ETAPA 6
        # ========================================================

        titulo(
            "ETAPA 6 - IDENTIFICANDO CASOS QUE EXIGEM APROVACAO"
        )

        casos_aprovacao = [
            caso
            for caso in casos
            if requer_aprovacao(
                caso
            )
        ]

        ok(
            f"Casos aguardando processo humano: "
            f"{len(casos_aprovacao)}"
        )

        for caso in casos_aprovacao:

            print(
                f"- {caso['case_id']} | "
                f"{caso['ip_origem']} | "
                f"{caso['prioridade_soc']} | "
                f"{caso['status_caso']}"
            )

        validacoes.append(
            (
                "Casos de aprovacao identificados",
                len(
                    casos_aprovacao
                ) > 0
            )
        )

        # ========================================================
        # ETAPA 7
        # ========================================================

        titulo(
            "ETAPA 7 - EXECUTANDO HUMAN APPROVAL GATE"
        )

        aprovacoes = []
        alertas = []

        for indice, caso in enumerate(
            casos_aprovacao,
            start=1
        ):

            separador()

            print(
                f"CASO {indice}/"
                f"{len(casos_aprovacao)}"
            )

            separador()

            print(
                f"Case ID: "
                f"{caso['case_id']}"
            )

            print(
                f"IOC: "
                f"{caso['ip_origem']}"
            )

            print(
                f"Prioridade: "
                f"{caso['prioridade_soc']}"
            )

            print(
                f"Decision Score: "
                f"{caso['decision_score']:.2f}/100"
            )

            print(
                f"Status atual: "
                f"{caso['status_caso']}"
            )

            print(
                f"Fase atual: "
                f"{caso['fase']}"
            )

            print(
                f"Acao recomendada: "
                f"{caso['acao_recomendada']}"
            )

            print()

            entrada_humana = (
                obter_decisao_simulada(
                    caso
                )
            )

            if not entrada_humana:

                info(
                    "Caso nao requer decisao "
                    "humana nesta execucao"
                )

                continue

            resultado = (
                aplicar_decisao_humana(
                    caso,
                    entrada_humana[
                        "decisao"
                    ]
                )
            )

            approval_id = gerar_id(
                "APR-44"
            )

            aprovacao = {
                "approval_id":
                    approval_id,

                "timestamp":
                    agora_iso(),

                "case_id":
                    caso["case_id"],

                "ip_origem":
                    caso["ip_origem"],

                "analista":
                    entrada_humana[
                        "analista"
                    ],

                "decisao":
                    entrada_humana[
                        "decisao"
                    ],

                "justificativa":
                    entrada_humana[
                        "justificativa"
                    ],

                "status_anterior":
                    caso["status_caso"],

                "status_resultante":
                    resultado[
                        "status_resultante"
                    ],

                "fase_anterior":
                    caso["fase"],

                "fase_resultante":
                    resultado[
                        "fase_resultante"
                    ],

                "prioridade_soc":
                    caso["prioridade_soc"],

                "decision_score":
                    caso["decision_score"],

                "acao_recomendada":
                    caso["acao_recomendada"],

                "requer_acao":
                    resultado[
                        "requer_acao"
                    ],

                "acao_autorizada":
                    resultado[
                        "acao_autorizada"
                    ],

                # =================================================
                # REGRA DE SEGURANCA
                # =================================================

                "execucao_real":
                    False,

                "bloqueio_automatico":
                    False,

                "modo_operacional":
                    MODO_OPERACIONAL
            }

            print(
                "DECISAO HUMANA SIMULADA:"
            )

            print(
                f"Analista: "
                f"{aprovacao['analista']}"
            )

            print(
                f"Decisao: "
                f"{aprovacao['decisao']}"
            )

            print(
                f"Justificativa: "
                f"{aprovacao['justificativa']}"
            )

            print()

            print(
                "RESULTADO DO APPROVAL GATE:"
            )

            print(
                f"Status: "
                f"{aprovacao['status_anterior']} "
                f"-> "
                f"{aprovacao['status_resultante']}"
            )

            print(
                f"Fase: "
                f"{aprovacao['fase_anterior']} "
                f"-> "
                f"{aprovacao['fase_resultante']}"
            )

            print(
                f"Requer acao: "
                f"{sim_nao(
                    aprovacao[
                        'requer_acao'
                    ]
                )}"
            )

            print(
                f"Acao autorizada: "
                f"{sim_nao(
                    aprovacao[
                        'acao_autorizada'
                    ]
                )}"
            )

            print(
                "Execucao real: NAO"
            )

            print(
                "Bloqueio automatico: NAO"
            )

            print(
                f"Modo: "
                f"{MODO_OPERACIONAL}"
            )

            persistir_aprovacao(
                conexao,
                aprovacao
            )

            atualizar_caso(
                conexao,
                aprovacao
            )

            aprovacoes.append(
                aprovacao
            )

            ok(
                f"Aprovacao registrada: "
                f"{approval_id}"
            )

            alerta_id = gerar_id(
                "APP-ALT-44"
            )

            alerta_aprovacao = {
                "alerta_id":
                    alerta_id,

                "timestamp":
                    agora_iso(),

                "approval_id":
                    approval_id,

                "case_id":
                    caso["case_id"],

                "ip_origem":
                    caso["ip_origem"],

                "decisao":
                    aprovacao[
                        "decisao"
                    ],

                "acao_autorizada":
                    aprovacao[
                        "acao_autorizada"
                    ],

                "execucao_real":
                    False,

                "bloqueio_automatico":
                    False,

                "modo":
                    MODO_OPERACIONAL
            }

            alertas.append(
                alerta_aprovacao
            )

            alerta(
                "Decisao humana registrada"
            )

            ok(
                f"Alerta: "
                f"{alerta_id}"
            )

        # ========================================================
        # ETAPA 8
        # ========================================================

        titulo(
            "ETAPA 8 - ANALISANDO APROVACOES"
        )

        aprovadas = sum(
            1
            for aprovacao in aprovacoes
            if aprovacao[
                "decisao"
            ] == "APROVADO"
        )

        rejeitadas = sum(
            1
            for aprovacao in aprovacoes
            if aprovacao[
                "decisao"
            ] == "REJEITADO"
        )

        adiadas = sum(
            1
            for aprovacao in aprovacoes
            if aprovacao[
                "decisao"
            ] == "ADIADO"
        )

        mais_evidencias = sum(
            1
            for aprovacao in aprovacoes
            if aprovacao[
                "decisao"
            ]
            == "SOLICITAR_MAIS_EVIDENCIAS"
        )

        autorizadas = sum(
            1
            for aprovacao in aprovacoes
            if aprovacao[
                "acao_autorizada"
            ]
        )

        print(
            f"Aprovacoes processadas: "
            f"{len(aprovacoes)}"
        )

        print(
            f"APROVADO: {aprovadas}"
        )

        print(
            f"REJEITADO: {rejeitadas}"
        )

        print(
            f"ADIADO: {adiadas}"
        )

        print(
            f"SOLICITAR_MAIS_EVIDENCIAS: "
            f"{mais_evidencias}"
        )

        print(
            f"Acoes autorizadas: "
            f"{autorizadas}"
        )

        print(
            "Execucoes reais: 0"
        )

        print(
            "Bloqueios automaticos: 0"
        )

        # ========================================================
        # ETAPA 9
        # ========================================================

        titulo(
            "ETAPA 9 - VALIDANDO SEGURANCA E AUDITORIA"
        )

        validacoes_aprovacao = []

        def validar(
            condicao,
            descricao
        ):
            resultado = bool(
                condicao
            )

            validacoes_aprovacao.append(
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
            len(aprovacoes) > 0,
            "Decisoes humanas registradas"
        )

        validar(
            all(
                aprovacao[
                    "approval_id"
                ]
                for aprovacao
                in aprovacoes
            ),
            "Todas as aprovacoes possuem Approval ID"
        )

        validar(
            all(
                aprovacao[
                    "case_id"
                ]
                for aprovacao
                in aprovacoes
            ),
            "Todas as aprovacoes possuem Case ID"
        )

        validar(
            all(
                aprovacao[
                    "analista"
                ]
                for aprovacao
                in aprovacoes
            ),
            "Todas as aprovacoes possuem analista"
        )

        validar(
            all(
                aprovacao[
                    "justificativa"
                ]
                for aprovacao
                in aprovacoes
            ),
            "Todas as aprovacoes possuem justificativa"
        )

        validar(
            all(
                aprovacao[
                    "decisao"
                ]
                in DECISOES_VALIDAS
                for aprovacao
                in aprovacoes
            ),
            "Todas as decisoes humanas sao validas"
        )

        validar(
            all(
                not aprovacao[
                    "execucao_real"
                ]
                for aprovacao
                in aprovacoes
            ),
            "Nenhuma acao real executada"
        )

        validar(
            all(
                not aprovacao[
                    "bloqueio_automatico"
                ]
                for aprovacao
                in aprovacoes
            ),
            "Nenhum bloqueio automatico habilitado"
        )

        validar(
            all(
                aprovacao[
                    "modo_operacional"
                ]
                == MODO_OPERACIONAL
                for aprovacao
                in aprovacoes
            ),
            "Modo operacional permanece SIMULACAO"
        )

        validar(
            all(
                (
                    not aprovacao[
                        "acao_autorizada"
                    ]
                )
                or (
                    aprovacao[
                        "execucao_real"
                    ]
                    is False
                )
                for aprovacao
                in aprovacoes
            ),
            "Autorizacao nao implica execucao automatica"
        )

        seguranca_ok = all(
            resultado
            for _, resultado
            in validacoes_aprovacao
        )

        # ========================================================
        # ETAPA 10
        # ========================================================

        titulo(
            "ETAPA 10 - PERSISTINDO RESULTADOS"
        )

        salvar_json(
            ARQUIVO_APROVACOES,
            aprovacoes
        )

        ok(
            "Aprovacoes humanas salvas"
        )

        print(
            "Arquivo: "
            "aprovacoes\\human_approvals_aula_44.json"
        )

        salvar_json(
            ARQUIVO_ALERTAS,
            alertas
        )

        ok(
            "Alertas Human Approval salvos"
        )

        print(
            "Arquivo: "
            "alertas\\alertas_human_approval_aula_44.json"
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
                    "Tabela Human Approval disponivel",
                    tabela_existe(
                        conexao,
                        TABELA_APROVACOES
                    )
                ),

                (
                    "Casos SOC carregados",
                    len(casos) > 0
                ),

                (
                    "Casos de aprovacao identificados",
                    len(
                        casos_aprovacao
                    ) > 0
                ),

                (
                    "Aprovacoes processadas",
                    len(aprovacoes) > 0
                ),

                (
                    "Validacoes de seguranca aprovadas",
                    seguranca_ok
                ),

                (
                    "Nenhuma execucao real",
                    all(
                        not aprovacao[
                            "execucao_real"
                        ]
                        for aprovacao
                        in aprovacoes
                    )
                ),

                (
                    "Nenhum bloqueio automatico",
                    all(
                        not aprovacao[
                            "bloqueio_automatico"
                        ]
                        for aprovacao
                        in aprovacoes
                    )
                ),

                (
                    "Modo SIMULACAO preservado",
                    all(
                        aprovacao[
                            "modo_operacional"
                        ]
                        == MODO_OPERACIONAL
                        for aprovacao
                        in aprovacoes
                    )
                ),

                (
                    "Arquivo de aprovacoes criado",
                    ARQUIVO_APROVACOES.exists()
                ),

                (
                    "Arquivo de alertas criado",
                    ARQUIVO_ALERTAS.exists()
                )
            ]
        )

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

        total_validacoes = len(
            unicas
        )

        validacoes_ok = 0

        for descricao, resultado in unicas:

            if resultado:

                ok(descricao)

                validacoes_ok += 1

            else:

                erro(descricao)

        saude = (
            validacoes_ok
            / total_validacoes
            * 100
            if total_validacoes
            else 0
        )

        print()

        print(
            f"Validacoes: "
            f"{validacoes_ok}/"
            f"{total_validacoes}"
        )

        print(
            f"Saude: "
            f"{saude:.2f}%"
        )

        # ========================================================
        # RELATORIO
        # ========================================================

        relatorio = {
            "projeto":
                PROJETO,

            "aula":
                AULA,

            "versao":
                VERSAO,

            "timestamp":
                agora_iso(),

            "casos_soc":
                len(casos),

            "casos_aprovacao":
                len(casos_aprovacao),

            "aprovacoes_processadas":
                len(aprovacoes),

            "aprovadas":
                aprovadas,

            "rejeitadas":
                rejeitadas,

            "adiadas":
                adiadas,

            "mais_evidencias":
                mais_evidencias,

            "acoes_autorizadas":
                autorizadas,

            "execucoes_reais":
                0,

            "bloqueios_automaticos":
                0,

            "alertas":
                len(alertas),

            "modo_operacional":
                MODO_OPERACIONAL,

            "validacoes": {
                "total":
                    total_validacoes,

                "ok":
                    validacoes_ok,

                "saude":
                    round(
                        saude,
                        2
                    )
            },

            "status": (
                "AULA 44 CONCLUIDA"
                if validacoes_ok
                == total_validacoes
                else
                "AULA 44 COM PENDENCIAS"
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
            "alertas\\relatorio_aula_44.json"
        )

        # ========================================================
        # RESUMO FINAL
        # ========================================================

        titulo(
            "RESUMO FINAL DA AULA 44"
        )

        print(
            f"Casos SOC: "
            f"{len(casos)}"
        )

        print(
            f"Casos submetidos ao Approval Gate: "
            f"{len(casos_aprovacao)}"
        )

        print(
            f"Aprovacoes processadas: "
            f"{len(aprovacoes)}"
        )

        print()

        print(
            f"APROVADO: "
            f"{aprovadas}"
        )

        print(
            f"REJEITADO: "
            f"{rejeitadas}"
        )

        print(
            f"ADIADO: "
            f"{adiadas}"
        )

        print(
            f"SOLICITAR_MAIS_EVIDENCIAS: "
            f"{mais_evidencias}"
        )

        print()

        print(
            f"Acoes autorizadas: "
            f"{autorizadas}"
        )

        print(
            "Execucoes reais: 0"
        )

        print(
            "Bloqueios automaticos: 0"
        )

        print()

        print(
            f"Validacoes: "
            f"{validacoes_ok}/"
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
            validacoes_ok
            == total_validacoes
        ):

            print(
                "Status: AULA 44 CONCLUIDA"
            )

        else:

            print(
                "Status: "
                "AULA 44 COM PENDENCIAS"
            )

        # ========================================================
        # ARQUITETURA
        # ========================================================

        titulo(
            "ARQUITETURA DA AULA 44"
        )

        print(
r"""
               CYBERSENTINEL-ML
                      |
                      v
                CASE LIFECYCLE
                   AULA 43
                      |
                      v
                   ESCALADO
                      |
                      v
              HUMAN APPROVAL GATE
                      |
          +-----------+-----------+
          |           |           |
          v           v           v
      APROVADO    REJEITADO     ADIADO
          |           |           |
          v           v           v
     ACAO         INVESTIGACAO   AGUARDA
   AUTORIZADA                    DECISAO
          |
          +-------------------------------+
                                          |
                                          v
                               MAIS EVIDENCIAS
                                          |
                                          v
                                    INVESTIGACAO

                      |
                      v
                AUDIT TRAIL
                      |
          +-----------+-----------+
          |           |           |
          v           v           v
       ANALISTA     DECISAO   JUSTIFICATIVA
          |           |           |
          +-----------+-----------+
                      |
                      v
               STATUS RESULTANTE
                      |
                      v
                 CASE UPDATE


REGRA FUNDAMENTAL:

APROVADO
   !=
EXECUTADO


APROVACAO HUMANA:
    SIM

ACAO AUTORIZADA:
    PODE SER SIM

EXECUCAO REAL:
    NAO

BLOQUEIO AUTOMATICO:
    NAO


Nenhuma regra de firewall e alterada.

Nenhum IP e bloqueado.

Nenhuma acao destrutiva e executada.

A Aula 44 apenas registra e audita
a decisao humana simulada.

Modo operacional: SIMULACAO.
"""
        )

        linha()
        print(
            "CYBERSENTINEL-ML"
        )
        linha()

        print(
            "AULA 44 - HUMAN APPROVAL GATE"
        )

        if (
            validacoes_ok
            == total_validacoes
        ):

            print(
                "AULA 44 CONCLUIDA"
            )

        else:

            print(
                "AULA 44 COM PENDENCIAS"
            )

    except sqlite3.Error as excecao:

        titulo(
            "ERRO SQLITE - AULA 44"
        )

        print(
            f"[ERRO] {excecao}"
        )

        print()

        print(
            "Status: "
            "AULA 44 COM PENDENCIAS"
        )

    except Exception as excecao:

        titulo(
            "ERRO INESPERADO - AULA 44"
        )

        print(
            f"[ERRO] "
            f"{type(excecao).__name__}: "
            f"{excecao}"
        )

        print()

        print(
            "Status: "
            "AULA 44 COM PENDENCIAS"
        )

    finally:

        if conexao is not None:
            conexao.close()


# ================================================================
# EXECUCAO
# ================================================================

if __name__ == "__main__":
    main()