# ================================================================
# AULA 46 V3 - PIPELINE END-TO-END
# CyberSentinel-ML
#
# CORRECAO V3:
#
# - Decision -> Evidence por evidence_id exato
# - Evidence.mitre_* continua sendo a fonte canonica
# - MITRE historico passa por normalizacao flexivel de schema
# - Campos historicos sao descobertos por aliases e nome semantico
# - Historico e usado para auditoria, nunca para substituir Evidence
#
# IMPORTANTE:
#
# Esta aula NAO:
# - retreina ML
# - recalcula Risk Score
# - cria Evidence
# - cria Decision
# - cria Case
# - executa Lifecycle
# - executa Human Approval
# - executa contencao
# - bloqueia IP
# - modifica firewall
#
# Modo operacional: SIMULACAO
# ================================================================

import ipaddress
import json
import re
import sqlite3
import unicodedata
import uuid

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


# ================================================================
# CONFIGURACOES
# ================================================================

PROJETO = "CyberSentinel-ML"
AULA = 46
VERSAO = "3.0"

MODO_OPERACIONAL = "SIMULACAO"

BASE_DIR = Path(__file__).resolve().parent

DADOS_DIR = BASE_DIR / "dados"
MODELOS_DIR = BASE_DIR / "modelos"
PIPELINE_DIR = BASE_DIR / "pipeline"
ALERTAS_DIR = BASE_DIR / "alertas"

DB_PATH = DADOS_DIR / "cybersentinel.db"

ARQUIVO_PIPELINE = (
    PIPELINE_DIR / "end_to_end_aula_46.json"
)

ARQUIVO_RELATORIO = (
    ALERTAS_DIR / "relatorio_aula_46.json"
)

TABELA_RUNS = "soc_end_to_end_runs"

LARGURA = 78


# ================================================================
# MACHINE LEARNING
# ================================================================

ARTEFATOS_ML = {
    "modelo_binario":
        MODELOS_DIR / "unsw_decision_tree.joblib",

    "configuracao_binaria":
        MODELOS_DIR / "configuracao_modelo.joblib",

    "modelo_multiclasse":
        MODELOS_DIR / "unsw_attack_multiclass_otimizado.joblib",

    "configuracao_multiclasse":
        MODELOS_DIR /
        "configuracao_multiclasse_otimizada_aula_22.joblib"
}


# ================================================================
# COMPONENTES
# ================================================================

COMPONENTES = {
    "correlacao_ioc_eventos":
        "Historical IOC Correlation",

    "campanhas_ioc":
        "Campaign Detection",

    "incident_timelines":
        "Incident Timeline",

    "incident_response_playbooks":
        "Incident Response",

    "mitre_attack_mapping":
        "MITRE ATT&CK Historical Context",

    "incident_evidence":
        "Incident Evidence",

    "soc_incident_decisions":
        "SOC Decision Engine",

    "soc_incident_cases":
        "SOC Case Management",

    "soc_case_transitions":
        "SOC Case Lifecycle",

    "soc_human_approvals":
        "Human Approval Gate",

    "soc_observability_snapshots":
        "SOC Observability"
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


def info(valor):
    print(f"[INFO] {valor}")


def aviso(valor):
    print(f"[AVISO] {valor}")


def erro(valor):
    print(f"[ERRO] {valor}")


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


def sim_nao(valor):
    return (
        "SIM"
        if booleano(valor)
        else "NAO"
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

        valor = registro.get(nome)

        if valor is not None:
            return valor

    return padrao


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
# NORMALIZACAO DE NOMES
# ================================================================

def normalizar_nome(valor):
    """
    Remove acentos, espacos e caracteres especiais
    para comparar nomes de colunas de schemas antigos.
    """

    valor = texto(
        valor,
        ""
    )

    valor = unicodedata.normalize(
        "NFKD",
        valor
    )

    valor = "".join(
        caractere
        for caractere in valor
        if not unicodedata.combining(
            caractere
        )
    )

    valor = valor.lower()

    valor = re.sub(
        r"[^a-z0-9]+",
        "_",
        valor
    )

    return valor.strip("_")


# ================================================================
# IOC
# ================================================================

def normalizar_ip(valor):
    valor = texto(
        valor,
        ""
    )

    if not valor:
        return None

    try:
        return str(
            ipaddress.ip_address(
                valor
            )
        )

    except ValueError:
        return None


def obter_ioc(registro):
    if not registro:
        return None

    valor = primeiro_valor(
        registro,
        [
            "ip_origem",
            "ioc",
            "ioc_valor",
            "ioc_value",
            "ip"
        ],
        None
    )

    return normalizar_ip(
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
        f"PRAGMA table_info({tabela})"
    )

    return [
        registro["name"]
        for registro
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
        f"SELECT * FROM {tabela}"
    )

    return [
        dict(registro)
        for registro
        in cursor.fetchall()
    ]


def contar_tabela(
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

    resultado = cursor.fetchone()

    return inteiro(
        resultado[0]
        if resultado
        else 0
    )


# ================================================================
# TIMESTAMP
# ================================================================

def timestamp_registro(registro):
    if not registro:
        return ""

    campos = [
        "timestamp_atualizacao",
        "timestamp",
        "updated_at",
        "created_at",
        "criado_em",
        "timestamp_criacao"
    ]

    valores = []

    for campo in campos:

        valor = registro.get(
            campo
        )

        if valor:
            valores.append(
                str(valor)
            )

    if not valores:
        return ""

    return max(valores)


# ================================================================
# SELECAO
# ================================================================

def mais_recente(registros):
    if not registros:
        return None

    melhor = None
    melhor_chave = None

    for indice, registro in enumerate(
        registros
    ):

        chave = (
            timestamp_registro(
                registro
            ),
            indice
        )

        if (
            melhor is None
            or chave >= melhor_chave
        ):
            melhor = registro
            melhor_chave = chave

    return melhor


def registros_do_ioc(
    registros,
    ioc
):
    return [
        registro
        for registro in registros
        if obter_ioc(
            registro
        ) == ioc
    ]


def registro_mais_recente_ioc(
    registros,
    ioc
):
    return mais_recente(
        registros_do_ioc(
            registros,
            ioc
        )
    )


def deduplicar_por_ioc(registros):
    agrupados = {}

    for registro in registros:

        ioc = obter_ioc(
            registro
        )

        if not ioc:
            continue

        agrupados.setdefault(
            ioc,
            []
        ).append(
            registro
        )

    return {
        ioc: mais_recente(
            grupo
        )
        for ioc, grupo
        in agrupados.items()
    }


def buscar_por_id(
    registros,
    coluna,
    valor
):
    valor = texto(
        valor,
        ""
    )

    if not valor:
        return None

    candidatos = [
        registro
        for registro in registros
        if texto(
            registro.get(
                coluna
            ),
            ""
        ) == valor
    ]

    return mais_recente(
        candidatos
    )


# ================================================================
# MITRE
# ================================================================

PLACEHOLDERS_MITRE = {
    "",
    "NAO_DISPONIVEL",
    "NAO_ATRIBUIDA",
    "NAO_ATRIBUIDO",
    "DESCONHECIDO",
    "UNKNOWN",
    "NONE",
    "NULL"
}


def valor_mitre_valido(valor):
    return (
        texto(
            valor,
            ""
        ).upper()
        not in PLACEHOLDERS_MITRE
    )


def valor_por_alias(
    registro,
    aliases
):
    """
    1. procura aliases exatos;
    2. procura aliases apos normalizacao do nome da coluna.
    """

    if not registro:
        return None

    for alias in aliases:

        if alias in registro:

            valor = registro.get(
                alias
            )

            if valor is not None:
                return valor

    aliases_norm = {
        normalizar_nome(
            alias
        )
        for alias in aliases
    }

    for coluna, valor in (
        registro.items()
    ):

        coluna_norm = normalizar_nome(
            coluna
        )

        if (
            coluna_norm
            in aliases_norm
        ):

            return valor

    return None


def valor_por_palavras(
    registro,
    palavras_obrigatorias,
    palavras_excluidas=None
):
    """
    Busca uma coluna pelo significado do nome.

    Exemplo:
    ['tatica'] pode encontrar:
    mitre_tatica
    tatica_mitre
    attack_tactic
    etc.
    """

    if not registro:
        return None

    if palavras_excluidas is None:
        palavras_excluidas = []

    obrigatorias = [
        normalizar_nome(
            palavra
        )
        for palavra in palavras_obrigatorias
    ]

    excluidas = [
        normalizar_nome(
            palavra
        )
        for palavra in palavras_excluidas
    ]

    for coluna, valor in (
        registro.items()
    ):

        nome = normalizar_nome(
            coluna
        )

        if not all(
            palavra in nome
            for palavra
            in obrigatorias
        ):
            continue

        if any(
            palavra in nome
            for palavra
            in excluidas
        ):
            continue

        if valor is not None:
            return valor

    return None


def extrair_mitre_historico(
    registro
):
    """
    Extrator tolerante a schemas legados.
    """

    if not registro:
        return {
            "contexto":
                "NAO_DISPONIVEL",

            "tatica":
                "NAO_DISPONIVEL",

            "confianca":
                "NAO_DISPONIVEL",

            "contexto_disponivel":
                False,

            "tatica_disponivel":
                False,

            "confianca_disponivel":
                False
        }

    contexto = valor_por_alias(
        registro,
        [
            "contexto",
            "mitre_contexto",
            "contexto_mitre",
            "tipo_contexto",
            "classificacao_contexto",
            "contexto_attack",
            "attack_context"
        ]
    )

    if contexto is None:
        contexto = valor_por_palavras(
            registro,
            ["contexto"]
        )

    tatica = valor_por_alias(
        registro,
        [
            "tatica",
            "mitre_tatica",
            "tatica_mitre",
            "tactic",
            "attack_tactic",
            "mitre_tactic",
            "tactic_name"
        ]
    )

    if tatica is None:

        tatica = valor_por_palavras(
            registro,
            ["tatica"]
        )

    if tatica is None:

        tatica = valor_por_palavras(
            registro,
            ["tactic"]
        )

    confianca = valor_por_alias(
        registro,
        [
            "confianca",
            "mitre_confianca",
            "confianca_mitre",
            "confidence",
            "confidence_level",
            "nivel_confianca",
            "confianca_mapeamento",
            "mapping_confidence"
        ]
    )

    if confianca is None:

        confianca = valor_por_palavras(
            registro,
            ["confianca"]
        )

    if confianca is None:

        confianca = valor_por_palavras(
            registro,
            ["confidence"]
        )

    contexto = texto(
        contexto,
        "NAO_DISPONIVEL"
    )

    tatica = texto(
        tatica,
        "NAO_DISPONIVEL"
    )

    confianca = texto(
        confianca,
        "NAO_DISPONIVEL"
    )

    return {
        "contexto":
            contexto,

        "tatica":
            tatica,

        "confianca":
            confianca,

        "contexto_disponivel":
            valor_mitre_valido(
                contexto
            ),

        "tatica_disponivel":
            valor_mitre_valido(
                tatica
            ),

        "confianca_disponivel":
            valor_mitre_valido(
                confianca
            )
    }


def extrair_mitre_canonico(
    evidence
):
    if not evidence:
        return {
            "contexto":
                "NAO_DISPONIVEL",

            "tatica":
                "NAO_DISPONIVEL",

            "confianca":
                "NAO_DISPONIVEL",

            "fonte":
                "NAO_DISPONIVEL",

            "valido":
                False
        }

    contexto = texto(
        primeiro_valor(
            evidence,
            [
                "mitre_contexto",
                "contexto_mitre"
            ],
            "NAO_DISPONIVEL"
        ),
        "NAO_DISPONIVEL"
    )

    tatica = texto(
        primeiro_valor(
            evidence,
            [
                "mitre_tatica",
                "tatica_mitre"
            ],
            "NAO_DISPONIVEL"
        ),
        "NAO_DISPONIVEL"
    )

    confianca = texto(
        primeiro_valor(
            evidence,
            [
                "mitre_confianca",
                "confianca_mitre"
            ],
            "NAO_DISPONIVEL"
        ),
        "NAO_DISPONIVEL"
    )

    valido = (
        valor_mitre_valido(
            contexto
        )
        and
        valor_mitre_valido(
            tatica
        )
        and
        valor_mitre_valido(
            confianca
        )
    )

    return {
        "contexto":
            contexto,

        "tatica":
            tatica,

        "confianca":
            confianca,

        "fonte":
            "INCIDENT_EVIDENCE",

        "valido":
            valido
    }


def campos_mitre_iguais(
    valor_a,
    valor_b
):
    return (
        texto(
            valor_a,
            ""
        ).strip().casefold()
        ==
        texto(
            valor_b,
            ""
        ).strip().casefold()
    )


def comparar_mitre(
    canonico,
    historico_normalizado
):
    """
    Regra V3:

    - Evidence canonico precisa estar completo.
    - Historico e auditoria.
    - Comparamos todos os campos semanticamente
      disponiveis no registro historico.
    - Um campo historico ausente nao invalida
      o Evidence canonico.
    - Um campo historico presente e divergente,
      sim, invalida.
    """

    if not canonico.get(
        "valido",
        False
    ):
        return {
            "consistente":
                False,

            "comparaveis":
                0,

            "iguais":
                0,

            "divergencias":
                [
                    "MITRE_CANONICO_INVALIDO"
                ]
        }

    comparaveis = 0
    iguais = 0
    divergencias = []

    campos = [
        (
            "contexto",
            "contexto_disponivel"
        ),
        (
            "tatica",
            "tatica_disponivel"
        ),
        (
            "confianca",
            "confianca_disponivel"
        )
    ]

    for campo, disponibilidade in campos:

        if not historico_normalizado.get(
            disponibilidade,
            False
        ):
            continue

        comparaveis += 1

        if campos_mitre_iguais(
            canonico.get(
                campo
            ),
            historico_normalizado.get(
                campo
            )
        ):

            iguais += 1

        else:

            divergencias.append(
                campo.upper()
            )

    # Se encontramos o registro historico,
    # mas seu schema antigo nao oferece campos
    # semanticamente comparaveis, ele nao deve
    # derrubar o Evidence canonico.
    if comparaveis == 0:

        return {
            "consistente":
                True,

            "comparaveis":
                0,

            "iguais":
                0,

            "divergencias":
                []
        }

    consistente = (
        comparaveis
        == iguais
        and
        len(
            divergencias
        ) == 0
    )

    return {
        "consistente":
            consistente,

        "comparaveis":
            comparaveis,

        "iguais":
            iguais,

        "divergencias":
            divergencias
    }


def escolher_mitre_historico(
    registros,
    ioc,
    canonico
):
    """
    Seleciona o registro historico que mais
    se aproxima semanticamente do Evidence.
    """

    candidatos = registros_do_ioc(
        registros,
        ioc
    )

    if not candidatos:
        return None

    melhor = None
    melhor_chave = None

    for indice, registro in enumerate(
        candidatos
    ):

        mitre = extrair_mitre_historico(
            registro
        )

        pontos = 0

        if (
            mitre[
                "contexto_disponivel"
            ]
            and campos_mitre_iguais(
                canonico[
                    "contexto"
                ],
                mitre[
                    "contexto"
                ]
            )
        ):
            pontos += 4

        if (
            mitre[
                "tatica_disponivel"
            ]
            and campos_mitre_iguais(
                canonico[
                    "tatica"
                ],
                mitre[
                    "tatica"
                ]
            )
        ):
            pontos += 3

        if (
            mitre[
                "confianca_disponivel"
            ]
            and campos_mitre_iguais(
                canonico[
                    "confianca"
                ],
                mitre[
                    "confianca"
                ]
            )
        ):
            pontos += 2

        chave = (
            pontos,
            timestamp_registro(
                registro
            ),
            indice
        )

        if (
            melhor is None
            or chave > melhor_chave
        ):
            melhor = registro
            melhor_chave = chave

    return melhor


# ================================================================
# RUN TABLE
# ================================================================

def criar_tabela_runs(
    conexao
):
    cursor = conexao.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS soc_end_to_end_runs (
            run_id TEXT PRIMARY KEY,
            timestamp TEXT,

            modelos_esperados INTEGER,
            modelos_disponiveis INTEGER,

            componentes_esperados INTEGER,
            componentes_disponiveis INTEGER,

            iocs_ativos INTEGER,
            iocs_completos INTEGER,

            mitre_consistente INTEGER,

            validacoes_total INTEGER,
            validacoes_ok INTEGER,

            saude_pipeline REAL,

            execucoes_reais INTEGER,
            bloqueios_automaticos INTEGER,

            modo_operacional TEXT
        )
        """
    )

    conexao.commit()


def migrar_tabela_runs(
    conexao
):
    colunas = obter_colunas(
        conexao,
        TABELA_RUNS
    )

    cursor = conexao.cursor()

    adicionadas = []

    if (
        "mitre_consistente"
        not in colunas
    ):
        cursor.execute(
            f"""
            ALTER TABLE {TABELA_RUNS}
            ADD COLUMN mitre_consistente INTEGER
            """
        )

        adicionadas.append(
            "mitre_consistente"
        )

    conexao.commit()

    return adicionadas


def persistir_run(
    conexao,
    run
):
    cursor = conexao.cursor()

    cursor.execute(
        """
        INSERT INTO soc_end_to_end_runs (
            run_id,
            timestamp,
            modelos_esperados,
            modelos_disponiveis,
            componentes_esperados,
            componentes_disponiveis,
            iocs_ativos,
            iocs_completos,
            mitre_consistente,
            validacoes_total,
            validacoes_ok,
            saude_pipeline,
            execucoes_reais,
            bloqueios_automaticos,
            modo_operacional
        )
        VALUES (
            ?, ?,
            ?, ?,
            ?, ?,
            ?, ?,
            ?,
            ?, ?,
            ?,
            ?, ?,
            ?
        )
        """,
        (
            run["run_id"],
            run["timestamp"],

            run[
                "modelos_esperados"
            ],

            run[
                "modelos_disponiveis"
            ],

            run[
                "componentes_esperados"
            ],

            run[
                "componentes_disponiveis"
            ],

            run[
                "iocs_ativos"
            ],

            run[
                "iocs_completos"
            ],

            int(
                run[
                    "mitre_consistente"
                ]
            ),

            run[
                "validacoes_total"
            ],

            run[
                "validacoes_ok"
            ],

            run[
                "saude_pipeline"
            ],

            run[
                "execucoes_reais"
            ],

            run[
                "bloqueios_automaticos"
            ],

            MODO_OPERACIONAL
        )
    )

    conexao.commit()


# ================================================================
# LINEAGE
# ================================================================

def construir_lineage(
    ioc,
    tabelas
):
    historico = registros_do_ioc(
        tabelas[
            "correlacao_ioc_eventos"
        ],
        ioc
    )

    campanha = registro_mais_recente_ioc(
        tabelas[
            "campanhas_ioc"
        ],
        ioc
    )

    timeline = registro_mais_recente_ioc(
        tabelas[
            "incident_timelines"
        ],
        ioc
    )

    playbook = registro_mais_recente_ioc(
        tabelas[
            "incident_response_playbooks"
        ],
        ioc
    )

    decision = registro_mais_recente_ioc(
        tabelas[
            "soc_incident_decisions"
        ],
        ioc
    )

    # ============================================================
    # DECISION -> EVIDENCE EXATO
    # ============================================================

    evidence_id_decision = texto(
        primeiro_valor(
            decision,
            [
                "evidence_id"
            ],
            ""
        ),
        ""
    )

    evidence = None

    if evidence_id_decision:

        evidence = buscar_por_id(
            tabelas[
                "incident_evidence"
            ],
            "evidence_id",
            evidence_id_decision
        )

    if evidence is None:

        evidence = registro_mais_recente_ioc(
            tabelas[
                "incident_evidence"
            ],
            ioc
        )

    evidence_id_real = texto(
        primeiro_valor(
            evidence,
            [
                "evidence_id"
            ],
            ""
        ),
        ""
    )

    evidence_link_exato = (
        bool(
            evidence_id_decision
        )
        and
        evidence_id_decision
        == evidence_id_real
    )

    # ============================================================
    # MITRE CANONICO
    # ============================================================

    mitre_canonico = (
        extrair_mitre_canonico(
            evidence
        )
    )

    mitre_historico = (
        escolher_mitre_historico(
            tabelas[
                "mitre_attack_mapping"
            ],
            ioc,
            mitre_canonico
        )
    )

    mitre_historico_norm = (
        extrair_mitre_historico(
            mitre_historico
        )
    )

    comparacao_mitre = comparar_mitre(
        mitre_canonico,
        mitre_historico_norm
    )

    mitre_consistente = (
        comparacao_mitre[
            "consistente"
        ]
    )

    # ============================================================
    # CASE
    # ============================================================

    caso = registro_mais_recente_ioc(
        tabelas[
            "soc_incident_cases"
        ],
        ioc
    )

    case_id = texto(
        primeiro_valor(
            caso,
            [
                "case_id"
            ],
            ""
        ),
        ""
    )

    # ============================================================
    # LIFECYCLE
    # ============================================================

    lifecycle = []

    for registro in tabelas[
        "soc_case_transitions"
    ]:

        case_registro = texto(
            primeiro_valor(
                registro,
                [
                    "case_id"
                ],
                ""
            ),
            ""
        )

        ioc_registro = obter_ioc(
            registro
        )

        if (
            (
                case_id
                and
                case_registro
                == case_id
            )
            or
            ioc_registro == ioc
        ):
            lifecycle.append(
                registro
            )

    lifecycle.sort(
        key=timestamp_registro
    )

    # ============================================================
    # APPROVAL
    # ============================================================

    approvals = []

    for registro in tabelas[
        "soc_human_approvals"
    ]:

        case_registro = texto(
            primeiro_valor(
                registro,
                ["case_id"],
                ""
            ),
            ""
        )

        ioc_registro = obter_ioc(
            registro
        )

        if (
            (
                case_id
                and
                case_registro
                == case_id
            )
            or
            ioc_registro == ioc
        ):
            approvals.append(
                registro
            )

    approvals.sort(
        key=timestamp_registro
    )

    approval = (
        approvals[-1]
        if approvals
        else None
    )

    # ============================================================
    # CAMPANHA
    # ============================================================

    campanha_status = texto(
        primeiro_valor(
            campanha,
            [
                "status",
                "status_campanha"
            ],
            ""
        ),
        ""
    ).upper()

    campanha_detectada = (
        booleano(
            primeiro_valor(
                campanha,
                [
                    "campanha_detectada"
                ],
                False
            )
        )
        or
        campanha_status
        == "CAMPANHA_DETECTADA"
    )

    score_campanha = numero(
        primeiro_valor(
            decision,
            [
                "score_campanha"
            ],
            primeiro_valor(
                evidence,
                [
                    "score_campanha"
                ],
                0
            )
        )
    )

    # ============================================================
    # SCORES
    # ============================================================

    evidence_score = numero(
        primeiro_valor(
            evidence,
            [
                "evidence_score"
            ],
            0
        )
    )

    decision_score = numero(
        primeiro_valor(
            decision,
            [
                "decision_score"
            ],
            0
        )
    )

    prioridade = texto(
        primeiro_valor(
            decision,
            [
                "prioridade_soc"
            ],
            primeiro_valor(
                caso,
                [
                    "prioridade_soc"
                ],
                "NAO_DISPONIVEL"
            )
        ),
        "NAO_DISPONIVEL"
    ).upper()

    # ============================================================
    # CASE STATE
    # ============================================================

    status_caso = texto(
        primeiro_valor(
            caso,
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
            caso,
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
            caso,
            [
                "owner"
            ],
            "NAO_DISPONIVEL"
        ),
        "NAO_DISPONIVEL"
    )

    # ============================================================
    # APPROVAL
    # ============================================================

    decisao_aprovacao = texto(
        primeiro_valor(
            approval,
            [
                "decisao"
            ],
            "NAO_APLICAVEL"
        ),
        "NAO_APLICAVEL"
    ).upper()

    acao_autorizada = booleano(
        primeiro_valor(
            approval,
            [
                "acao_autorizada"
            ],
            False
        )
    )

    execucao_real = booleano(
        primeiro_valor(
            approval,
            [
                "execucao_real"
            ],
            False
        )
    )

    bloqueio_automatico = booleano(
        primeiro_valor(
            approval,
            [
                "bloqueio_automatico"
            ],
            False
        )
    )

    lifecycle_esperado = (
        prioridade
        == "CRITICO"
    )

    approval_esperado = (
        prioridade
        == "CRITICO"
        and
        status_caso
        in {
            "ESCALADO",
            "AGUARDANDO_APROVACAO",
            "APROVADO_PARA_ACAO",
            "EM_INVESTIGACAO"
        }
    )

    requisitos = {
        "historico":
            len(
                historico
            ) > 0,

        "campanha_contexto":
            campanha
            is not None,

        "timeline":
            timeline
            is not None,

        "incident_response":
            playbook
            is not None,

        "evidence":
            evidence
            is not None,

        "decision":
            decision
            is not None,

        "decision_evidence_link":
            evidence_link_exato,

        "mitre_canonico":
            mitre_canonico[
                "valido"
            ],

        "mitre_historico_auditavel":
            mitre_historico
            is not None,

        "mitre_semantico":
            mitre_consistente,

        "case":
            caso
            is not None,

        "lifecycle":
            (
                len(
                    lifecycle
                ) > 0
                if lifecycle_esperado
                else True
            ),

        "human_approval":
            (
                approval
                is not None
                if approval_esperado
                else True
            )
    }

    lineage_completo = all(
        requisitos.values()
    )

    return {
        "ioc":
            ioc,

        "prioridade_soc":
            prioridade,

        "historico_eventos":
            len(
                historico
            ),

        "campanha": {
            "registro_encontrado":
                campanha
                is not None,

            "detectada":
                campanha_detectada,

            "score":
                round(
                    score_campanha,
                    2
                )
        },

        "timeline": {
            "registro_encontrado":
                timeline
                is not None,

            "status":
                texto(
                    primeiro_valor(
                        timeline,
                        [
                            "status",
                            "status_incidente",
                            "status_timeline"
                        ],
                        "NAO_DISPONIVEL"
                    ),
                    "NAO_DISPONIVEL"
                )
        },

        "incident_response": {
            "registro_encontrado":
                playbook
                is not None,

            "prioridade":
                texto(
                    primeiro_valor(
                        playbook,
                        [
                            "prioridade",
                            "prioridade_playbook"
                        ],
                        "NAO_DISPONIVEL"
                    ),
                    "NAO_DISPONIVEL"
                )
        },

        "evidence": {
            "registro_encontrado":
                evidence
                is not None,

            "evidence_id":
                evidence_id_real,

            "evidence_id_decision":
                evidence_id_decision,

            "linked_by_decision":
                evidence_link_exato,

            "score":
                round(
                    evidence_score,
                    2
                )
        },

        "mitre": {
            "fonte_canonica":
                mitre_canonico[
                    "fonte"
                ],

            "contexto":
                mitre_canonico[
                    "contexto"
                ],

            "tatica":
                mitre_canonico[
                    "tatica"
                ],

            "confianca":
                mitre_canonico[
                    "confianca"
                ],

            "canonico_valido":
                mitre_canonico[
                    "valido"
                ],

            "historico_encontrado":
                mitre_historico
                is not None,

            "historico_contexto":
                mitre_historico_norm[
                    "contexto"
                ],

            "historico_tatica":
                mitre_historico_norm[
                    "tatica"
                ],

            "historico_confianca":
                mitre_historico_norm[
                    "confianca"
                ],

            "campos_comparaveis":
                comparacao_mitre[
                    "comparaveis"
                ],

            "campos_iguais":
                comparacao_mitre[
                    "iguais"
                ],

            "divergencias":
                comparacao_mitre[
                    "divergencias"
                ],

            "historico_consistente":
                mitre_consistente
        },

        "decision": {
            "registro_encontrado":
                decision
                is not None,

            "decision_id":
                texto(
                    primeiro_valor(
                        decision,
                        [
                            "decision_id"
                        ],
                        ""
                    )
                ),

            "score":
                round(
                    decision_score,
                    2
                ),

            "classificacao":
                texto(
                    primeiro_valor(
                        decision,
                        [
                            "classificacao_decisao",
                            "classificacao"
                        ],
                        "NAO_DISPONIVEL"
                    ),
                    "NAO_DISPONIVEL"
                )
        },

        "case": {
            "registro_encontrado":
                caso
                is not None,

            "case_id":
                case_id,

            "status":
                status_caso,

            "fase":
                fase,

            "owner":
                owner
        },

        "lifecycle": {
            "esperado":
                lifecycle_esperado,

            "transicoes":
                len(
                    lifecycle
                )
        },

        "human_approval": {
            "esperado":
                approval_esperado,

            "registro_encontrado":
                approval
                is not None,

            "decisao":
                decisao_aprovacao,

            "acao_autorizada":
                acao_autorizada,

            "execucao_real":
                execucao_real,

            "bloqueio_automatico":
                bloqueio_automatico
        },

        "requisitos":
            requisitos,

        "lineage_completo":
            lineage_completo
    }


# ================================================================
# MAIN
# ================================================================

def main():
    titulo(
        "AULA 46 V3 - PIPELINE END-TO-END"
    )

    print(PROJETO)

    print(
        "Pipeline Orchestration + "
        "Legacy Schema Semantic Validation"
    )

    print()

    print("Objetivo:")

    print(
        "Validar o lineage completo usando "
        "Evidence como fonte canonica e a tabela "
        "MITRE historica como auditoria."
    )

    print()

    print("REGRA V3:")

    print(
        "Decision.evidence_id -> Evidence exato"
    )

    print(
        "Evidence.mitre_* -> MITRE canonico"
    )

    print(
        "MITRE historico -> auditoria com schema flexivel"
    )

    print()

    print(
        "Nenhuma camada anterior sera reexecutada."
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
            ("modelos", MODELOS_DIR),
            ("pipeline", PIPELINE_DIR),
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
            "ETAPA 2 - VALIDANDO MACHINE LEARNING"
        )

        modelos_status = {}
        modelos_disponiveis = 0

        for nome, caminho in (
            ARTEFATOS_ML.items()
        ):

            existe = caminho.exists()

            modelos_status[
                nome
            ] = {
                "arquivo":
                    str(
                        caminho.relative_to(
                            BASE_DIR
                        )
                    ),

                "disponivel":
                    existe
            }

            if existe:

                modelos_disponiveis += 1

                ok(
                    f"{nome}: "
                    f"{caminho.name}"
                )

            else:

                erro(
                    f"{nome}: "
                    f"{caminho.name} ausente"
                )

        modelos_esperados = len(
            ARTEFATOS_ML
        )

        print()

        print(
            f"Artefatos ML: "
            f"{modelos_disponiveis}/"
            f"{modelos_esperados}"
        )

        validacoes.append(
            (
                "Artefatos ML completos",
                modelos_disponiveis
                == modelos_esperados
            )
        )

        # ========================================================
        # ETAPA 3
        # ========================================================

        titulo(
            "ETAPA 3 - VALIDANDO SQLITE"
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

        # ========================================================
        # ETAPA 4
        # ========================================================

        titulo(
            "ETAPA 4 - INVENTARIO END-TO-END"
        )

        componentes_status = {}
        componentes_disponiveis = 0

        for tabela, nome in (
            COMPONENTES.items()
        ):

            existe = tabela_existe(
                conexao,
                tabela
            )

            quantidade = (
                contar_tabela(
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

                componentes_disponiveis += 1

                ok(
                    f"{nome}: "
                    f"{quantidade} registros"
                )

            else:

                erro(
                    f"{nome}: tabela ausente"
                )

        componentes_esperados = len(
            COMPONENTES
        )

        print()

        print(
            f"Componentes: "
            f"{componentes_disponiveis}/"
            f"{componentes_esperados}"
        )

        validacoes.append(
            (
                "Todos os componentes End-to-End disponiveis",
                componentes_disponiveis
                == componentes_esperados
            )
        )

        if (
            componentes_disponiveis
            != componentes_esperados
        ):
            return

        # ========================================================
        # ETAPA 5
        # ========================================================

        titulo(
            "ETAPA 5 - CARREGANDO PIPELINE"
        )

        tabelas = {}
        registros_total = 0

        for tabela in COMPONENTES:

            registros = carregar_tabela(
                conexao,
                tabela
            )

            tabelas[
                tabela
            ] = registros

            registros_total += len(
                registros
            )

            print(
                f"{tabela}: "
                f"{len(registros)} registros"
            )

        ok(
            f"Registros carregados: "
            f"{registros_total}"
        )

        validacoes.append(
            (
                "Pipeline possui registros",
                registros_total > 0
            )
        )

        # ========================================================
        # ETAPA 6
        # ========================================================

        titulo(
            "ETAPA 6 - ESTADO ATUAL"
        )

        casos_atuais = (
            deduplicar_por_ioc(
                tabelas[
                    "soc_incident_cases"
                ]
            )
        )

        iocs_ativos = set(
            casos_atuais.keys()
        )

        ok(
            f"IOCs ativos: "
            f"{len(iocs_ativos)}"
        )

        for ioc in sorted(
            iocs_ativos
        ):

            caso = casos_atuais[
                ioc
            ]

            print(
                f"- {ioc} | "
                f"{texto(
                    primeiro_valor(
                        caso,
                        ['prioridade_soc'],
                        'NAO_DISPONIVEL'
                    )
                )} | "
                f"{texto(
                    primeiro_valor(
                        caso,
                        ['status_caso'],
                        'NAO_DISPONIVEL'
                    )
                )}"
            )

        validacoes.extend(
            [
                (
                    "IOCs ativos encontrados",
                    len(iocs_ativos)
                    > 0
                ),

                (
                    "IOCs ativos sao IPs validos",
                    all(
                        normalizar_ip(
                            ioc
                        )
                        is not None
                        for ioc
                        in iocs_ativos
                    )
                )
            ]
        )

        # ========================================================
        # ETAPA 7
        # ========================================================

        titulo(
            "ETAPA 7 - RECONSTRUINDO LINEAGE V3"
        )

        lineages = []

        for posicao, ioc in enumerate(
            sorted(
                iocs_ativos
            ),
            start=1
        ):

            separador()

            print(
                f"IOC {posicao}/"
                f"{len(iocs_ativos)}"
            )

            separador()

            lineage = construir_lineage(
                ioc,
                tabelas
            )

            lineages.append(
                lineage
            )

            print(
                f"IOC: "
                f"{lineage['ioc']}"
            )

            print(
                f"Prioridade SOC: "
                f"{lineage['prioridade_soc']}"
            )

            print()

            print(
                "01 - HISTORICAL CORRELATION"
            )

            print(
                f"Eventos: "
                f"{lineage['historico_eventos']}"
            )

            print()

            print(
                "02 - CAMPAIGN DETECTION"
            )

            print(
                "Campanha detectada: "
                f"{sim_nao(
                    lineage[
                        'campanha'
                    ][
                        'detectada'
                    ]
                )}"
            )

            print(
                "Campaign Score: "
                f"{lineage[
                    'campanha'
                ][
                    'score'
                ]:.2f}"
            )

            print()

            print(
                "03 - INCIDENT TIMELINE"
            )

            print(
                f"Status: "
                f"{lineage[
                    'timeline'
                ][
                    'status'
                ]}"
            )

            print()

            print(
                "04 - INCIDENT RESPONSE"
            )

            print(
                "Prioridade: "
                f"{lineage[
                    'incident_response'
                ][
                    'prioridade'
                ]}"
            )

            print()

            print(
                "05 - INCIDENT EVIDENCE"
            )

            print(
                "Evidence ID: "
                f"{lineage[
                    'evidence'
                ][
                    'evidence_id'
                ]}"
            )

            print(
                "Evidence ID da Decision: "
                f"{lineage[
                    'evidence'
                ][
                    'evidence_id_decision'
                ]}"
            )

            print(
                "Link exato: "
                f"{sim_nao(
                    lineage[
                        'evidence'
                    ][
                        'linked_by_decision'
                    ]
                )}"
            )

            print(
                "Evidence Score: "
                f"{lineage[
                    'evidence'
                ][
                    'score'
                ]:.2f}"
            )

            print()

            print(
                "06 - MITRE CANONICO / AUDITORIA"
            )

            print(
                "Fonte canonica: "
                f"{lineage[
                    'mitre'
                ][
                    'fonte_canonica'
                ]}"
            )

            print(
                "Canonico:"
            )

            print(
                f"  Contexto: "
                f"{lineage[
                    'mitre'
                ][
                    'contexto'
                ]}"
            )

            print(
                f"  Tatica: "
                f"{lineage[
                    'mitre'
                ][
                    'tatica'
                ]}"
            )

            print(
                f"  Confianca: "
                f"{lineage[
                    'mitre'
                ][
                    'confianca'
                ]}"
            )

            print()

            print(
                "Historico selecionado:"
            )

            print(
                f"  Contexto: "
                f"{lineage[
                    'mitre'
                ][
                    'historico_contexto'
                ]}"
            )

            print(
                f"  Tatica: "
                f"{lineage[
                    'mitre'
                ][
                    'historico_tatica'
                ]}"
            )

            print(
                f"  Confianca: "
                f"{lineage[
                    'mitre'
                ][
                    'historico_confianca'
                ]}"
            )

            print()

            print(
                "Campos comparaveis: "
                f"{lineage[
                    'mitre'
                ][
                    'campos_comparaveis'
                ]}"
            )

            print(
                "Campos iguais: "
                f"{lineage[
                    'mitre'
                ][
                    'campos_iguais'
                ]}"
            )

            print(
                "Divergencias: "
                f"{lineage[
                    'mitre'
                ][
                    'divergencias'
                ]}"
            )

            print(
                "Historico consistente: "
                f"{sim_nao(
                    lineage[
                        'mitre'
                    ][
                        'historico_consistente'
                    ]
                )}"
            )

            print()

            print(
                "07 - SOC DECISION ENGINE"
            )

            print(
                "Decision ID: "
                f"{lineage[
                    'decision'
                ][
                    'decision_id'
                ]}"
            )

            print(
                "Decision Score: "
                f"{lineage[
                    'decision'
                ][
                    'score'
                ]:.2f}"
            )

            print(
                "Classificacao: "
                f"{lineage[
                    'decision'
                ][
                    'classificacao'
                ]}"
            )

            print()

            print(
                "08 - CASE MANAGEMENT"
            )

            print(
                "Case ID: "
                f"{lineage[
                    'case'
                ][
                    'case_id'
                ]}"
            )

            print(
                "Status: "
                f"{lineage[
                    'case'
                ][
                    'status'
                ]}"
            )

            print(
                "Fase: "
                f"{lineage[
                    'case'
                ][
                    'fase'
                ]}"
            )

            print(
                "Owner: "
                f"{lineage[
                    'case'
                ][
                    'owner'
                ]}"
            )

            print()

            print(
                "09 - CASE LIFECYCLE"
            )

            print(
                f"Transicoes: "
                f"{lineage[
                    'lifecycle'
                ][
                    'transicoes'
                ]}"
            )

            print()

            print(
                "10 - HUMAN APPROVAL"
            )

            print(
                "Esperado: "
                f"{sim_nao(
                    lineage[
                        'human_approval'
                    ][
                        'esperado'
                    ]
                )}"
            )

            print(
                "Registro: "
                f"{sim_nao(
                    lineage[
                        'human_approval'
                    ][
                        'registro_encontrado'
                    ]
                )}"
            )

            print(
                "Decisao: "
                f"{lineage[
                    'human_approval'
                ][
                    'decisao'
                ]}"
            )

            print(
                "Acao autorizada: "
                f"{sim_nao(
                    lineage[
                        'human_approval'
                    ][
                        'acao_autorizada'
                    ]
                )}"
            )

            print(
                "Execucao real: "
                f"{sim_nao(
                    lineage[
                        'human_approval'
                    ][
                        'execucao_real'
                    ]
                )}"
            )

            print(
                "Bloqueio automatico: "
                f"{sim_nao(
                    lineage[
                        'human_approval'
                    ][
                        'bloqueio_automatico'
                    ]
                )}"
            )

            print()

            print("LINEAGE:")

            for requisito, resultado in (
                lineage[
                    "requisitos"
                ].items()
            ):

                if resultado:
                    ok(requisito)
                else:
                    erro(requisito)

            if lineage[
                "lineage_completo"
            ]:

                ok(
                    "Lineage End-to-End completo"
                )

            else:

                erro(
                    "Lineage End-to-End incompleto"
                )

        # ========================================================
        # ETAPA 8
        # ========================================================

        titulo(
            "ETAPA 8 - VALIDANDO DECISION -> EVIDENCE"
        )

        decision_evidence_ok = all(
            lineage[
                "evidence"
            ][
                "linked_by_decision"
            ]
            for lineage
            in lineages
        )

        for lineage in lineages:

            if lineage[
                "evidence"
            ][
                "linked_by_decision"
            ]:

                ok(
                    f"{lineage['ioc']} | "
                    "Decision -> Evidence exato"
                )

            else:

                erro(
                    f"{lineage['ioc']} | "
                    "Decision -> Evidence inconsistente"
                )

        validacoes.append(
            (
                "Decision -> Evidence possui linkage exato",
                decision_evidence_ok
            )
        )

        # ========================================================
        # ETAPA 9
        # ========================================================

        titulo(
            "ETAPA 9 - VALIDANDO MITRE"
        )

        mitre_consistente = all(
            lineage[
                "mitre"
            ][
                "historico_consistente"
            ]
            for lineage
            in lineages
        )

        for lineage in lineages:

            print(
                f"IOC: "
                f"{lineage['ioc']}"
            )

            print(
                "MITRE canonico: "
                f"{lineage['mitre']['contexto']} | "
                f"{lineage['mitre']['tatica']} | "
                f"{lineage['mitre']['confianca']}"
            )

            print(
                "Historico consistente: "
                f"{sim_nao(
                    lineage[
                        'mitre'
                    ][
                        'historico_consistente'
                    ]
                )}"
            )

            if lineage[
                "mitre"
            ][
                "historico_consistente"
            ]:

                ok(
                    "MITRE consistente"
                )

            else:

                erro(
                    "MITRE inconsistente"
                )

            print()

        validacoes.append(
            (
                "MITRE consistente em todos os IOCs",
                mitre_consistente
            )
        )

        # ========================================================
        # ETAPA 10
        # ========================================================

        titulo(
            "ETAPA 10 - VALIDANDO LINEAGES"
        )

        completos = sum(
            1
            for lineage
            in lineages
            if lineage[
                "lineage_completo"
            ]
        )

        print(
            f"IOCs ativos: "
            f"{len(lineages)}"
        )

        print(
            f"Lineages completos: "
            f"{completos}"
        )

        prioridades = Counter(
            lineage[
                "prioridade_soc"
            ]
            for lineage
            in lineages
        )

        print()

        print("Prioridades:")

        for prioridade, quantidade in (
            prioridades.items()
        ):

            print(
                f"- {prioridade}: "
                f"{quantidade}"
            )

        validacoes.append(
            (
                "Todos os IOCs possuem lineage completo",
                completos
                == len(
                    lineages
                )
            )
        )

        # ========================================================
        # ETAPA 11
        # ========================================================

        titulo(
            "ETAPA 11 - VALIDANDO OBSERVABILITY"
        )

        snapshots = tabelas[
            "soc_observability_snapshots"
        ]

        ultimo_snapshot = mais_recente(
            snapshots
        )

        snapshot_iocs = inteiro(
            primeiro_valor(
                ultimo_snapshot,
                [
                    "iocs_ativos",
                    "iocs_unicos"
                ],
                0
            )
        )

        snapshot_health = numero(
            primeiro_valor(
                ultimo_snapshot,
                [
                    "saude_pipeline"
                ],
                0
            )
        )

        if ultimo_snapshot:
            ok(
                "Snapshot de observabilidade encontrado"
            )
        else:
            erro(
                "Snapshot de observabilidade nao encontrado"
            )

        print(
            f"Health anterior: "
            f"{snapshot_health:.2f}%"
        )

        print(
            f"IOCs ativos snapshot: "
            f"{snapshot_iocs}"
        )

        validacoes.extend(
            [
                (
                    "Observability possui snapshot",
                    ultimo_snapshot
                    is not None
                ),

                (
                    "Snapshot possui mesma quantidade de IOCs",
                    snapshot_iocs
                    == len(
                        iocs_ativos
                    )
                ),

                (
                    "Observability Health anterior 100%",
                    snapshot_health
                    == 100.0
                )
            ]
        )

        # ========================================================
        # ETAPA 12
        # ========================================================

        titulo(
            "ETAPA 12 - SEGURANCA END-TO-END"
        )

        execucoes_reais = sum(
            1
            for lineage
            in lineages
            if lineage[
                "human_approval"
            ][
                "execucao_real"
            ]
        )

        bloqueios = sum(
            1
            for lineage
            in lineages
            if lineage[
                "human_approval"
            ][
                "bloqueio_automatico"
            ]
        )

        checks_seguranca = [
            (
                "Nenhuma execucao real",
                execucoes_reais == 0
            ),

            (
                "Nenhum bloqueio automatico",
                bloqueios == 0
            ),

            (
                "Modo operacional permanece SIMULACAO",
                MODO_OPERACIONAL
                == "SIMULACAO"
            ),

            (
                "Casos criticos possuem Approval quando esperado",
                all(
                    (
                        not lineage[
                            "human_approval"
                        ][
                            "esperado"
                        ]
                    )
                    or
                    lineage[
                        "human_approval"
                    ][
                        "registro_encontrado"
                    ]
                    for lineage
                    in lineages
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
                "Seguranca End-to-End aprovada",
                seguranca_ok
            )
        )

        # ========================================================
        # ETAPA 13
        # ========================================================

        titulo(
            "ETAPA 13 - PREPARANDO RUN"
        )

        criar_tabela_runs(
            conexao
        )

        adicionadas = migrar_tabela_runs(
            conexao
        )

        ok(
            "Tabela soc_end_to_end_runs pronta"
        )

        for coluna in adicionadas:

            ok(
                f"Coluna adicionada: "
                f"{coluna}"
            )

        validacoes.append(
            (
                "Tabela End-to-End Runs disponivel",
                tabela_existe(
                    conexao,
                    TABELA_RUNS
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
                    "Modelos disponiveis",
                    modelos_disponiveis
                    == modelos_esperados
                ),

                (
                    "Componentes disponiveis",
                    componentes_disponiveis
                    == componentes_esperados
                ),

                (
                    "Pipeline possui IOCs ativos",
                    len(
                        iocs_ativos
                    ) > 0
                ),

                (
                    "Todos possuem Historical Correlation",
                    all(
                        item[
                            "historico_eventos"
                        ] > 0
                        for item
                        in lineages
                    )
                ),

                (
                    "Todos possuem Campaign Context",
                    all(
                        item[
                            "campanha"
                        ][
                            "registro_encontrado"
                        ]
                        for item
                        in lineages
                    )
                ),

                (
                    "Todos possuem Timeline",
                    all(
                        item[
                            "timeline"
                        ][
                            "registro_encontrado"
                        ]
                        for item
                        in lineages
                    )
                ),

                (
                    "Todos possuem Incident Response",
                    all(
                        item[
                            "incident_response"
                        ][
                            "registro_encontrado"
                        ]
                        for item
                        in lineages
                    )
                ),

                (
                    "Todos possuem Evidence",
                    all(
                        item[
                            "evidence"
                        ][
                            "registro_encontrado"
                        ]
                        for item
                        in lineages
                    )
                ),

                (
                    "Todos possuem Decision",
                    all(
                        item[
                            "decision"
                        ][
                            "registro_encontrado"
                        ]
                        for item
                        in lineages
                    )
                ),

                (
                    "Todos possuem MITRE canonico valido",
                    all(
                        item[
                            "mitre"
                        ][
                            "canonico_valido"
                        ]
                        for item
                        in lineages
                    )
                ),

                (
                    "MITRE historico auditavel",
                    all(
                        item[
                            "mitre"
                        ][
                            "historico_encontrado"
                        ]
                        for item
                        in lineages
                    )
                ),

                (
                    "MITRE historico semanticamente consistente",
                    mitre_consistente
                ),

                (
                    "Todos possuem Case",
                    all(
                        item[
                            "case"
                        ][
                            "registro_encontrado"
                        ]
                        for item
                        in lineages
                    )
                ),

                (
                    "Todos os lineages completos",
                    completos
                    == len(
                        lineages
                    )
                ),

                (
                    "Zero execucoes reais",
                    execucoes_reais
                    == 0
                ),

                (
                    "Zero bloqueios automaticos",
                    bloqueios
                    == 0
                )
            ]
        )

        unicas = []
        vistos = set()

        for descricao, resultado in (
            validacoes
        ):

            if descricao in vistos:
                continue

            vistos.add(
                descricao
            )

            unicas.append(
                (
                    descricao,
                    bool(
                        resultado
                    )
                )
            )

        total = len(
            unicas
        )

        aprovadas = 0

        for descricao, resultado in (
            unicas
        ):

            if resultado:

                ok(
                    descricao
                )

                aprovadas += 1

            else:

                erro(
                    descricao
                )

        saude = (
            aprovadas
            / total
            * 100
            if total
            else 0
        )

        print()

        print(
            f"Validacoes: "
            f"{aprovadas}/{total}"
        )

        print(
            f"Saude End-to-End: "
            f"{saude:.2f}%"
        )

        # ========================================================
        # ETAPA 15
        # ========================================================

        titulo(
            "ETAPA 15 - CONSOLIDANDO RUN V3"
        )

        run_id = gerar_id(
            "E2E-46-V3"
        )

        resultado = {
            "projeto":
                PROJETO,

            "aula":
                AULA,

            "versao":
                VERSAO,

            "run_id":
                run_id,

            "timestamp":
                agora_iso(),

            "machine_learning": {
                "esperados":
                    modelos_esperados,

                "disponiveis":
                    modelos_disponiveis,

                "artefatos":
                    modelos_status
            },

            "pipeline": {
                "componentes_esperados":
                    componentes_esperados,

                "componentes_disponiveis":
                    componentes_disponiveis,

                "registros_historicos":
                    registros_total,

                "componentes":
                    componentes_status
            },

            "estado_atual": {
                "iocs_ativos":
                    len(
                        iocs_ativos
                    ),

                "lista_iocs":
                    sorted(
                        iocs_ativos
                    ),

                "lineages_completos":
                    completos
            },

            "semantic_lineage": {
                "decision_evidence":
                    decision_evidence_ok,

                "mitre_consistente":
                    mitre_consistente
            },

            "lineages":
                lineages,

            "observability": {
                "health_anterior":
                    snapshot_health,

                "iocs_ativos":
                    snapshot_iocs
            },

            "seguranca": {
                "execucoes_reais":
                    execucoes_reais,

                "bloqueios_automaticos":
                    bloqueios,

                "modo":
                    MODO_OPERACIONAL
            },

            "validacoes": {
                "total":
                    total,

                "ok":
                    aprovadas,

                "saude":
                    round(
                        saude,
                        2
                    )
            },

            "status": (
                "AULA 46 V3 CONCLUIDA"
                if aprovadas
                == total
                else
                "AULA 46 V3 COM PENDENCIAS"
            )
        }

        salvar_json(
            ARQUIVO_PIPELINE,
            resultado
        )

        ok(
            "Run End-to-End V3 salvo"
        )

        # ========================================================
        # ETAPA 16
        # ========================================================

        titulo(
            "ETAPA 16 - PERSISTINDO RUN"
        )

        persistir_run(
            conexao,
            {
                "run_id":
                    run_id,

                "timestamp":
                    agora_iso(),

                "modelos_esperados":
                    modelos_esperados,

                "modelos_disponiveis":
                    modelos_disponiveis,

                "componentes_esperados":
                    componentes_esperados,

                "componentes_disponiveis":
                    componentes_disponiveis,

                "iocs_ativos":
                    len(
                        iocs_ativos
                    ),

                "iocs_completos":
                    completos,

                "mitre_consistente":
                    mitre_consistente,

                "validacoes_total":
                    total,

                "validacoes_ok":
                    aprovadas,

                "saude_pipeline":
                    round(
                        saude,
                        2
                    ),

                "execucoes_reais":
                    execucoes_reais,

                "bloqueios_automaticos":
                    bloqueios
            }
        )

        ok(
            f"Run persistido: "
            f"{run_id}"
        )

        # ========================================================
        # ETAPA 17
        # ========================================================

        titulo(
            "ETAPA 17 - RELATORIO FINAL"
        )

        relatorio = {
            "projeto":
                PROJETO,

            "aula":
                AULA,

            "versao":
                VERSAO,

            "run_id":
                run_id,

            "artefatos_ml":
                f"{modelos_disponiveis}/"
                f"{modelos_esperados}",

            "componentes":
                f"{componentes_disponiveis}/"
                f"{componentes_esperados}",

            "iocs_ativos":
                len(
                    iocs_ativos
                ),

            "lineages_completos":
                completos,

            "decision_evidence_link":
                decision_evidence_ok,

            "mitre_consistente":
                mitre_consistente,

            "observability_health":
                snapshot_health,

            "execucoes_reais":
                execucoes_reais,

            "bloqueios_automaticos":
                bloqueios,

            "modo_operacional":
                MODO_OPERACIONAL,

            "validacoes": {
                "total":
                    total,

                "ok":
                    aprovadas,

                "saude":
                    round(
                        saude,
                        2
                    )
            },

            "status": (
                "AULA 46 V3 CONCLUIDA"
                if aprovadas
                == total
                else
                "AULA 46 V3 COM PENDENCIAS"
            )
        }

        salvar_json(
            ARQUIVO_RELATORIO,
            relatorio
        )

        ok(
            "Relatorio V3 salvo"
        )

        print(
            "Arquivo: "
            "alertas\\relatorio_aula_46.json"
        )

        # ========================================================
        # RESUMO
        # ========================================================

        titulo(
            "RESUMO FINAL DA AULA 46 V3"
        )

        print(
            f"Artefatos ML: "
            f"{modelos_disponiveis}/"
            f"{modelos_esperados}"
        )

        print(
            f"Componentes: "
            f"{componentes_disponiveis}/"
            f"{componentes_esperados}"
        )

        print()

        print(
            f"IOCs ativos: "
            f"{len(iocs_ativos)}"
        )

        print(
            f"Lineages completos: "
            f"{completos}/"
            f"{len(lineages)}"
        )

        print()

        print(
            "Decision -> Evidence: "
            f"{'SIM' if decision_evidence_ok else 'NAO'}"
        )

        print(
            "MITRE consistente: "
            f"{'SIM' if mitre_consistente else 'NAO'}"
        )

        print()

        for item in lineages:

            print(
                f"{item['ioc']} | "
                f"{item['mitre']['contexto']} | "
                f"{item['mitre']['tatica']} | "
                f"{item['mitre']['confianca']} | "
                f"Historico: "
                f"{'OK' if item['mitre']['historico_consistente'] else 'ERRO'}"
            )

        print()

        print(
            f"Observability Health: "
            f"{snapshot_health:.2f}%"
        )

        print(
            f"Execucoes reais: "
            f"{execucoes_reais}"
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
            f"Saude End-to-End: "
            f"{saude:.2f}%"
        )

        print(
            f"Modo operacional: "
            f"{MODO_OPERACIONAL}"
        )

        print()

        if aprovadas == total:

            print(
                "Status: AULA 46 V3 CONCLUIDA"
            )

        else:

            print(
                "Status: AULA 46 V3 COM PENDENCIAS"
            )

        # ========================================================
        # ARQUITETURA
        # ========================================================

        titulo(
            "ARQUITETURA END-TO-END V3"
        )

        print(
r"""
                    CYBERSENTINEL-ML
                           |
                           v
                     MACHINE LEARNING
                           |
                           v
                 THREAT INTELLIGENCE
                           |
                           v
                      RISK SCORE
                           |
                           v
                HISTORICAL CORRELATION
                           |
                           v
                  CAMPAIGN DETECTION
                           |
                           v
                   INCIDENT TIMELINE
                           |
                           v
                  INCIDENT RESPONSE
                           |
                           v
                  INCIDENT EVIDENCE
                           |
              +------------+------------+
              |                         |
              v                         v
       Evidence Score              MITRE CANONICO
              |                         |
              +------------+------------+
                           |
                           v
                   SOC DECISION ENGINE
                           |
                           v
                    CASE MANAGEMENT
                           |
                           v
                     CASE LIFECYCLE
                           |
                           v
                    HUMAN APPROVAL
                           |
                           v
                     OBSERVABILITY
                           |
                           v
                END-TO-END VALIDATOR


LINEAGE CANONICO:

Decision.evidence_id
        |
        v
Evidence.evidence_id

Evidence:
    mitre_contexto
    mitre_tatica
    mitre_confianca

        |
        v

MITRE CANONICO


mitre_attack_mapping:
        |
        v
HISTORICO / AUDITORIA
        |
        v
NORMALIZACAO DE SCHEMA
        |
        v
COMPARACAO SEMANTICA


REGRA:

Historical schema antigo
NAO substitui Evidence canonico.


SEGURANCA:

Execucao real ............... NAO
Bloqueio automatico ......... NAO
Contencao ................... NAO EXECUTADA
Firewall .................... NAO ALTERADO
Modo ........................ SIMULACAO
"""
        )

        linha()
        print(PROJETO)
        linha()

        print(
            "AULA 46 V3 - PIPELINE END-TO-END"
        )

        if aprovadas == total:

            print(
                "AULA 46 V3 CONCLUIDA"
            )

        else:

            print(
                "AULA 46 V3 COM PENDENCIAS"
            )

    except sqlite3.Error as excecao:

        titulo(
            "ERRO SQLITE - AULA 46 V3"
        )

        erro(
            str(excecao)
        )

        print(
            "Status: AULA 46 V3 COM PENDENCIAS"
        )

    except Exception as excecao:

        titulo(
            "ERRO INESPERADO - AULA 46 V3"
        )

        erro(
            f"{type(excecao).__name__}: "
            f"{excecao}"
        )

        print(
            "Status: AULA 46 V3 COM PENDENCIAS"
        )

    finally:

        if conexao is not None:
            conexao.close()


# ================================================================
# EXECUCAO
# ================================================================

if __name__ == "__main__":
    main()