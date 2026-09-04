# ================================================================
# AULA 47 V2 - TESTES E VALIDACAO FINAL
# CyberSentinel-ML
#
# CORRECAO V2:
#
# - Schemas legados podem identificar IOC por diferentes aliases:
#
#   ip_origem
#   ioc
#   ioc_valor
#   ioc_value
#   ip
#
# - O teste nao exige migracao artificial de tabelas historicas.
# - Nenhum dado operacional e alterado.
#
# Objetivo:
# Executar a bateria final de testes estruturais, funcionais,
# semanticos e de seguranca do CyberSentinel-ML.
#
# ESTA AULA NAO:
# - treina modelos
# - executa inferencia operacional
# - recalcula Risk Score
# - cria Evidence
# - cria Decision
# - cria Case
# - muda Lifecycle
# - executa Approval Gate
# - executa playbook
# - executa contencao
# - bloqueia IP
# - altera firewall
#
# ESTA AULA APENAS:
# - testa
# - valida
# - audita
# - gera relatorio
#
# Modo operacional: SIMULACAO
# ================================================================

import ipaddress
import json
import math
import sqlite3
import uuid

from datetime import datetime, timezone
from pathlib import Path


# ================================================================
# CONFIGURACOES
# ================================================================

PROJETO = "CyberSentinel-ML"

AULA = 47

VERSAO = "2.0"

MODO_OPERACIONAL = "SIMULACAO"

BASE_DIR = Path(__file__).resolve().parent

DADOS_DIR = BASE_DIR / "dados"
MODELOS_DIR = BASE_DIR / "modelos"
PIPELINE_DIR = BASE_DIR / "pipeline"
METRICAS_DIR = BASE_DIR / "metricas"
ALERTAS_DIR = BASE_DIR / "alertas"
TESTES_DIR = BASE_DIR / "testes"

DB_PATH = (
    DADOS_DIR
    / "cybersentinel.db"
)

ARQUIVO_RESULTADOS = (
    TESTES_DIR
    / "final_validation_aula_47.json"
)

ARQUIVO_RELATORIO = (
    ALERTAS_DIR
    / "relatorio_aula_47.json"
)

TABELA_RUNS = (
    "soc_final_validation_runs"
)

LARGURA = 80


# ================================================================
# IOCS ESPERADOS
# ================================================================

IOCS_ESPERADOS = {
    "1.1.1.1",
    "8.8.8.8"
}


# ================================================================
# ALIASES DE IOC
# ================================================================

COLUNAS_IOC_COMPATIVEIS = {
    "ip_origem",
    "ioc",
    "ioc_valor",
    "ioc_value",
    "ip"
}


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
        / "configuracao_multiclasse_otimizada_aula_22.joblib"
}


# ================================================================
# ARQUIVOS FINAIS
# ================================================================

ARQUIVOS_ESPERADOS = {
    "observability_json":
        METRICAS_DIR
        / "soc_metrics_aula_45.json",

    "observability_prom":
        METRICAS_DIR
        / "soc_metrics_aula_45.prom",

    "end_to_end":
        PIPELINE_DIR
        / "end_to_end_aula_46.json",

    "relatorio_aula_45":
        ALERTAS_DIR
        / "relatorio_aula_45.json",

    "relatorio_aula_46":
        ALERTAS_DIR
        / "relatorio_aula_46.json"
}


# ================================================================
# TABELAS OBRIGATORIAS
# ================================================================

TABELAS_OBRIGATORIAS = {
    "correlacao_ioc_eventos",
    "campanhas_ioc",
    "incident_timelines",
    "incident_response_playbooks",
    "mitre_attack_mapping",
    "incident_evidence",
    "soc_incident_decisions",
    "soc_incident_cases",
    "soc_case_transitions",
    "soc_human_approvals",
    "soc_observability_snapshots",
    "soc_end_to_end_runs"
}


# ================================================================
# SCHEMAS MINIMOS V2
#
# obrigatorias:
#   todas devem existir
#
# alternativas:
#   pelo menos UMA deve existir
# ================================================================

SCHEMAS_MINIMOS = {
    "correlacao_ioc_eventos": {
        "obrigatorias": {
            "categoria",
            "risk_score_correlacionado"
        },

        "alternativas": [
            COLUNAS_IOC_COMPATIVEIS
        ]
    },

    "campanhas_ioc": {
        "obrigatorias": set(),

        "alternativas": [
            COLUNAS_IOC_COMPATIVEIS
        ]
    },

    "incident_timelines": {
        "obrigatorias": set(),

        "alternativas": [
            COLUNAS_IOC_COMPATIVEIS
        ]
    },

    "incident_response_playbooks": {
        "obrigatorias": set(),

        "alternativas": [
            COLUNAS_IOC_COMPATIVEIS
        ]
    },

    "mitre_attack_mapping": {
        "obrigatorias": set(),

        "alternativas": [
            COLUNAS_IOC_COMPATIVEIS
        ]
    },

    "incident_evidence": {
        "obrigatorias": {
            "evidence_id",
            "evidence_score",
            "mitre_contexto",
            "mitre_tatica",
            "mitre_confianca"
        },

        "alternativas": [
            COLUNAS_IOC_COMPATIVEIS
        ]
    },

    "soc_incident_decisions": {
        "obrigatorias": {
            "decision_id",
            "evidence_id",
            "decision_score",
            "prioridade_soc",
            "auto_block",
            "modo_operacional"
        },

        "alternativas": [
            COLUNAS_IOC_COMPATIVEIS
        ]
    },

    "soc_incident_cases": {
        "obrigatorias": {
            "case_id",
            "decision_score",
            "prioridade_soc"
        },

        "alternativas": [
            COLUNAS_IOC_COMPATIVEIS
        ]
    },

    "soc_case_transitions": {
        "obrigatorias": {
            "transition_id",
            "case_id",
            "bloqueio_automatico",
            "modo_operacional"
        },

        "alternativas": [
            COLUNAS_IOC_COMPATIVEIS
        ]
    },

    "soc_human_approvals": {
        "obrigatorias": {
            "approval_id",
            "case_id",
            "decisao",
            "acao_autorizada",
            "execucao_real",
            "bloqueio_automatico",
            "modo_operacional"
        },

        "alternativas": [
            COLUNAS_IOC_COMPATIVEIS
        ]
    },

    "soc_observability_snapshots": {
        "obrigatorias": {
            "snapshot_id",
            "saude_pipeline",
            "modo_operacional"
        },

        "alternativas": []
    },

    "soc_end_to_end_runs": {
        "obrigatorias": {
            "run_id",
            "saude_pipeline",
            "execucoes_reais",
            "bloqueios_automaticos",
            "modo_operacional"
        },

        "alternativas": []
    }
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


def numero(
    valor,
    padrao=0.0
):
    try:
        if valor is None:
            return padrao

        resultado = float(
            valor
        )

        if math.isnan(
            resultado
        ):
            return padrao

        if math.isinf(
            resultado
        ):
            return padrao

        return resultado

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

        return int(
            valor
        )

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


def carregar_json(caminho):
    try:
        with open(
            caminho,
            "r",
            encoding="utf-8"
        ) as arquivo:

            return json.load(
                arquivo
            )

    except (
        OSError,
        json.JSONDecodeError
    ):
        return None


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
        (
            tabela,
        )
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
        return set()

    cursor = conexao.cursor()

    cursor.execute(
        f"""
        PRAGMA table_info(
            {tabela}
        )
        """
    )

    return {
        registro["name"]
        for registro
        in cursor.fetchall()
    }


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
        dict(
            registro
        )
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

    registro = cursor.fetchone()

    if not registro:
        return 0

    return inteiro(
        registro[0]
    )


# ================================================================
# VALIDACAO DE SCHEMA V2
# ================================================================

def validar_schema(
    colunas,
    regra
):
    obrigatorias = regra.get(
        "obrigatorias",
        set()
    )

    grupos_alternativos = regra.get(
        "alternativas",
        []
    )

    faltantes = (
        obrigatorias
        - colunas
    )

    alternativas_invalidas = []

    for grupo in grupos_alternativos:

        presentes = (
            colunas
            & grupo
        )

        if not presentes:

            alternativas_invalidas.append(
                sorted(
                    grupo
                )
            )

    valido = (
        not faltantes
        and
        not alternativas_invalidas
    )

    return {
        "valido":
            valido,

        "faltantes":
            sorted(
                faltantes
            ),

        "alternativas_invalidas":
            alternativas_invalidas,

        "colunas_ioc_detectadas":
            sorted(
                colunas
                & COLUNAS_IOC_COMPATIVEIS
            )
    }


# ================================================================
# TIMESTAMP / DEDUP
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

    return max(
        valores
    )


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


def deduplicar_por_ioc(registros):
    grupos = {}

    for registro in registros:

        ioc = obter_ioc(
            registro
        )

        if not ioc:
            continue

        grupos.setdefault(
            ioc,
            []
        ).append(
            registro
        )

    return {
        ioc: mais_recente(
            itens
        )
        for ioc, itens
        in grupos.items()
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

    encontrados = [
        registro
        for registro
        in registros
        if texto(
            registro.get(
                coluna
            ),
            ""
        ) == valor
    ]

    return mais_recente(
        encontrados
    )


# ================================================================
# TABELA DE VALIDACOES
# ================================================================

def criar_tabela_testes(
    conexao
):
    cursor = conexao.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS soc_final_validation_runs (
            validation_id TEXT PRIMARY KEY,
            timestamp TEXT,

            testes_total INTEGER,
            testes_ok INTEGER,
            testes_falha INTEGER,

            cobertura REAL,

            iocs_ativos INTEGER,

            artefatos_ml_ok INTEGER,
            schemas_ok INTEGER,
            lineage_ok INTEGER,
            seguranca_ok INTEGER,

            execucoes_reais INTEGER,
            bloqueios_automaticos INTEGER,

            modo_operacional TEXT,

            status TEXT
        )
        """
    )

    conexao.commit()


def persistir_validacao(
    conexao,
    dados
):
    cursor = conexao.cursor()

    cursor.execute(
        """
        INSERT INTO soc_final_validation_runs (
            validation_id,
            timestamp,

            testes_total,
            testes_ok,
            testes_falha,

            cobertura,

            iocs_ativos,

            artefatos_ml_ok,
            schemas_ok,
            lineage_ok,
            seguranca_ok,

            execucoes_reais,
            bloqueios_automaticos,

            modo_operacional,

            status
        )
        VALUES (
            ?, ?,
            ?, ?, ?,
            ?,
            ?,
            ?, ?, ?, ?,
            ?, ?,
            ?,
            ?
        )
        """,
        (
            dados[
                "validation_id"
            ],

            dados[
                "timestamp"
            ],

            dados[
                "testes_total"
            ],

            dados[
                "testes_ok"
            ],

            dados[
                "testes_falha"
            ],

            dados[
                "cobertura"
            ],

            dados[
                "iocs_ativos"
            ],

            int(
                dados[
                    "artefatos_ml_ok"
                ]
            ),

            int(
                dados[
                    "schemas_ok"
                ]
            ),

            int(
                dados[
                    "lineage_ok"
                ]
            ),

            int(
                dados[
                    "seguranca_ok"
                ]
            ),

            dados[
                "execucoes_reais"
            ],

            dados[
                "bloqueios_automaticos"
            ],

            MODO_OPERACIONAL,

            dados[
                "status"
            ]
        )
    )

    conexao.commit()


# ================================================================
# TEST SUITE
# ================================================================

class TestSuite:

    def __init__(self):
        self.resultados = []

    def testar(
        self,
        categoria,
        nome,
        resultado,
        detalhes=None
    ):
        resultado = bool(
            resultado
        )

        registro = {
            "categoria":
                categoria,

            "teste":
                nome,

            "resultado":
                (
                    "PASS"
                    if resultado
                    else "FAIL"
                ),

            "ok":
                resultado,

            "detalhes":
                detalhes
        }

        self.resultados.append(
            registro
        )

        if resultado:

            ok(
                f"[{categoria}] {nome}"
            )

        else:

            erro(
                f"[{categoria}] {nome}"
            )

            if detalhes is not None:

                print(
                    f"    Detalhes: "
                    f"{detalhes}"
                )

        return resultado

    def total(self):
        return len(
            self.resultados
        )

    def aprovados(self):
        return sum(
            1
            for item
            in self.resultados
            if item[
                "ok"
            ]
        )

    def falhas(self):
        return (
            self.total()
            - self.aprovados()
        )

    def cobertura(self):
        return percentual(
            self.aprovados(),
            self.total()
        )

    def por_categoria(self):
        categorias = {}

        for item in self.resultados:

            categoria = item[
                "categoria"
            ]

            if categoria not in categorias:

                categorias[
                    categoria
                ] = {
                    "total":
                        0,

                    "ok":
                        0,

                    "falhas":
                        0
                }

            categorias[
                categoria
            ][
                "total"
            ] += 1

            if item[
                "ok"
            ]:

                categorias[
                    categoria
                ][
                    "ok"
                ] += 1

            else:

                categorias[
                    categoria
                ][
                    "falhas"
                ] += 1

        return categorias


# ================================================================
# MAIN
# ================================================================

def main():

    titulo(
        "AULA 47 V2 - TESTES E VALIDACAO FINAL"
    )

    print(PROJETO)

    print(
        "Final Test Suite + "
        "Legacy Schema Compatibility"
    )

    print()

    print("Objetivo:")

    print(
        "Executar os testes finais aceitando "
        "schemas historicos compativeis do projeto."
    )

    print()

    print("REGRA V2:")

    print(
        "Schema legado nao precisa obrigatoriamente "
        "usar a coluna literal ip_origem."
    )

    print(
        "Qualquer identificador IOC reconhecido "
        "pelo pipeline e valido."
    )

    print()

    print(
        "Nenhuma tabela sera alterada."
    )

    print(
        "Nenhum estado operacional sera alterado."
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

    suite = TestSuite()

    try:

        # ========================================================
        # ETAPA 1
        # ========================================================

        titulo(
            "ETAPA 1 - PREPARANDO AMBIENTE"
        )

        TESTES_DIR.mkdir(
            parents=True,
            exist_ok=True
        )

        ALERTAS_DIR.mkdir(
            parents=True,
            exist_ok=True
        )

        suite.testar(
            "AMBIENTE",
            "Diretorio testes disponivel",
            TESTES_DIR.exists()
        )

        suite.testar(
            "AMBIENTE",
            "Diretorio alertas disponivel",
            ALERTAS_DIR.exists()
        )

        suite.testar(
            "AMBIENTE",
            "Banco SQLite existe",
            DB_PATH.exists(),
            str(DB_PATH)
        )

        if not DB_PATH.exists():
            return

        conexao = conectar_banco()

        # ========================================================
        # ETAPA 2
        # ========================================================

        titulo(
            "ETAPA 2 - MACHINE LEARNING"
        )

        artefatos_ml_ok = True

        for nome, caminho in (
            ARTEFATOS_ML.items()
        ):

            existe = caminho.exists()

            if not existe:
                artefatos_ml_ok = False

            suite.testar(
                "MACHINE_LEARNING",
                f"Artefato {nome} existe",
                existe,
                caminho.name
            )

            if existe:

                tamanho_ok = (
                    caminho.stat().st_size
                    > 0
                )

                if not tamanho_ok:
                    artefatos_ml_ok = False

                suite.testar(
                    "MACHINE_LEARNING",
                    f"Artefato {nome} nao esta vazio",
                    tamanho_ok,
                    caminho.stat().st_size
                )

        # ========================================================
        # ETAPA 3
        # ========================================================

        titulo(
            "ETAPA 3 - TABELAS SQLITE"
        )

        tabelas_carregadas = {}

        for tabela in sorted(
            TABELAS_OBRIGATORIAS
        ):

            existe = tabela_existe(
                conexao,
                tabela
            )

            suite.testar(
                "SQLITE",
                f"Tabela {tabela} existe",
                existe
            )

            if existe:

                quantidade = contar_tabela(
                    conexao,
                    tabela
                )

                suite.testar(
                    "SQLITE",
                    f"Tabela {tabela} possui registros",
                    quantidade > 0,
                    quantidade
                )

                tabelas_carregadas[
                    tabela
                ] = carregar_tabela(
                    conexao,
                    tabela
                )

        # ========================================================
        # ETAPA 4
        # ========================================================

        titulo(
            "ETAPA 4 - SCHEMAS V2"
        )

        schemas_ok = True

        for tabela, regra in (
            SCHEMAS_MINIMOS.items()
        ):

            colunas = obter_colunas(
                conexao,
                tabela
            )

            resultado_schema = validar_schema(
                colunas,
                regra
            )

            resultado = resultado_schema[
                "valido"
            ]

            if not resultado:
                schemas_ok = False

            detalhes = None

            if not resultado:

                detalhes = {
                    "faltantes":
                        resultado_schema[
                            "faltantes"
                        ],

                    "grupos_alternativos_ausentes":
                        resultado_schema[
                            "alternativas_invalidas"
                        ],

                    "ioc_detectado":
                        resultado_schema[
                            "colunas_ioc_detectadas"
                        ]
                }

            suite.testar(
                "SCHEMA",
                f"Schema minimo de {tabela}",
                resultado,
                detalhes
            )

            if resultado_schema[
                "colunas_ioc_detectadas"
            ]:

                info(
                    f"{tabela} | "
                    "identificador IOC: "
                    f"{resultado_schema['colunas_ioc_detectadas']}"
                )

        # ========================================================
        # ETAPA 5
        # ========================================================

        titulo(
            "ETAPA 5 - IOCS ATIVOS"
        )

        casos = tabelas_carregadas[
            "soc_incident_cases"
        ]

        casos_atuais = (
            deduplicar_por_ioc(
                casos
            )
        )

        iocs_ativos = set(
            casos_atuais.keys()
        )

        suite.testar(
            "IOC",
            "Existem IOCs ativos",
            len(
                iocs_ativos
            ) > 0,
            sorted(
                iocs_ativos
            )
        )

        suite.testar(
            "IOC",
            "Todos os IOCs ativos sao IPs validos",
            all(
                normalizar_ip(
                    ioc
                )
                is not None
                for ioc
                in iocs_ativos
            ),
            sorted(
                iocs_ativos
            )
        )

        suite.testar(
            "IOC",
            "Conjunto atual corresponde ao laboratorio",
            iocs_ativos
            == IOCS_ESPERADOS,
            (
                f"atual={sorted(iocs_ativos)} "
                f"esperado={sorted(IOCS_ESPERADOS)}"
            )
        )

        # ========================================================
        # ETAPA 6
        # ========================================================

        titulo(
            "ETAPA 6 - SCORES"
        )

        correlacoes = tabelas_carregadas[
            "correlacao_ioc_eventos"
        ]

        evidencias = tabelas_carregadas[
            "incident_evidence"
        ]

        decisoes = tabelas_carregadas[
            "soc_incident_decisions"
        ]

        risk_scores = [
            numero(
                registro.get(
                    "risk_score_correlacionado"
                )
            )
            for registro
            in correlacoes
        ]

        evidence_scores = [
            numero(
                registro.get(
                    "evidence_score"
                )
            )
            for registro
            in evidencias
        ]

        decision_scores = [
            numero(
                registro.get(
                    "decision_score"
                )
            )
            for registro
            in decisoes
        ]

        suite.testar(
            "SCORES",
            "Risk Scores entre 0 e 100",
            all(
                0 <= score <= 100
                for score
                in risk_scores
            ),
            risk_scores
        )

        suite.testar(
            "SCORES",
            "Evidence Scores entre 0 e 100",
            all(
                0 <= score <= 100
                for score
                in evidence_scores
            ),
            evidence_scores
        )

        suite.testar(
            "SCORES",
            "Decision Scores entre 0 e 100",
            all(
                0 <= score <= 100
                for score
                in decision_scores
            ),
            decision_scores
        )

        # ========================================================
        # ETAPA 7
        # ========================================================

        titulo(
            "ETAPA 7 - DECISION -> EVIDENCE"
        )

        decisoes_atuais = (
            deduplicar_por_ioc(
                decisoes
            )
        )

        for ioc in sorted(
            iocs_ativos
        ):

            decision = (
                decisoes_atuais.get(
                    ioc
                )
            )

            evidence_id = texto(
                primeiro_valor(
                    decision,
                    [
                        "evidence_id"
                    ],
                    ""
                )
            )

            evidence = buscar_por_id(
                evidencias,
                "evidence_id",
                evidence_id
            )

            resultado = (
                decision
                is not None
                and
                evidence
                is not None
                and
                obter_ioc(
                    evidence
                ) == ioc
            )

            suite.testar(
                "LINEAGE",
                f"{ioc} Decision referencia Evidence exato",
                resultado,
                evidence_id
            )

        # ========================================================
        # ETAPA 8
        # ========================================================

        titulo(
            "ETAPA 8 - MITRE CANONICO"
        )

        for ioc in sorted(
            iocs_ativos
        ):

            decision = (
                decisoes_atuais[
                    ioc
                ]
            )

            evidence_id = texto(
                decision.get(
                    "evidence_id"
                )
            )

            evidence = buscar_por_id(
                evidencias,
                "evidence_id",
                evidence_id
            )

            contexto = texto(
                primeiro_valor(
                    evidence,
                    [
                        "mitre_contexto"
                    ],
                    ""
                )
            )

            tatica = texto(
                primeiro_valor(
                    evidence,
                    [
                        "mitre_tatica"
                    ],
                    ""
                )
            )

            confianca = texto(
                primeiro_valor(
                    evidence,
                    [
                        "mitre_confianca"
                    ],
                    ""
                )
            )

            campos_ok = all(
                valor.upper()
                not in {
                    "",
                    "NAO_DISPONIVEL",
                    "NAO_ATRIBUIDA",
                    "NAO_ATRIBUIDO",
                    "UNKNOWN",
                    "NULL"
                }
                for valor
                in [
                    contexto,
                    tatica,
                    confianca
                ]
            )

            suite.testar(
                "MITRE",
                f"{ioc} possui MITRE canonico completo",
                campos_ok,
                (
                    f"{contexto} | "
                    f"{tatica} | "
                    f"{confianca}"
                )
            )

        # ========================================================
        # ETAPA 9
        # ========================================================

        titulo(
            "ETAPA 9 - CASOS SOC"
        )

        for ioc in sorted(
            iocs_ativos
        ):

            caso = casos_atuais[
                ioc
            ]

            case_id = texto(
                caso.get(
                    "case_id"
                )
            )

            prioridade = texto(
                primeiro_valor(
                    caso,
                    [
                        "prioridade_soc"
                    ],
                    ""
                )
            ).upper()

            status_caso = texto(
                primeiro_valor(
                    caso,
                    [
                        "status_caso",
                        "status"
                    ],
                    ""
                )
            ).upper()

            suite.testar(
                "CASE",
                f"{ioc} possui Case ID",
                bool(
                    case_id
                ),
                case_id
            )

            suite.testar(
                "CASE",
                f"{ioc} possui prioridade SOC",
                prioridade
                in {
                    "BAIXO",
                    "MEDIO",
                    "ALTO",
                    "CRITICO"
                },
                prioridade
            )

            suite.testar(
                "CASE",
                f"{ioc} possui status operacional",
                bool(
                    status_caso
                ),
                status_caso
            )

        # ========================================================
        # ETAPA 10
        # ========================================================

        titulo(
            "ETAPA 10 - CASE LIFECYCLE"
        )

        transicoes = tabelas_carregadas[
            "soc_case_transitions"
        ]

        suite.testar(
            "LIFECYCLE",
            "Lifecycle possui transicoes",
            len(
                transicoes
            ) > 0,
            len(
                transicoes
            )
        )

        transicoes_auto_block = [
            registro
            for registro
            in transicoes
            if booleano(
                registro.get(
                    "bloqueio_automatico"
                )
            )
        ]

        suite.testar(
            "LIFECYCLE",
            "Lifecycle nao possui bloqueio automatico",
            len(
                transicoes_auto_block
            ) == 0,
            len(
                transicoes_auto_block
            )
        )

        lifecycle_modos = {
            texto(
                registro.get(
                    "modo_operacional"
                )
            ).upper()
            for registro
            in transicoes
        }

        suite.testar(
            "LIFECYCLE",
            "Lifecycle permanece em SIMULACAO",
            lifecycle_modos
            <= {
                "SIMULACAO"
            },
            sorted(
                lifecycle_modos
            )
        )

        # ========================================================
        # ETAPA 11
        # ========================================================

        titulo(
            "ETAPA 11 - HUMAN APPROVAL"
        )

        approvals = tabelas_carregadas[
            "soc_human_approvals"
        ]

        suite.testar(
            "APPROVAL",
            "Existe registro de Human Approval",
            len(
                approvals
            ) > 0,
            len(
                approvals
            )
        )

        aprovacoes_reais = [
            registro
            for registro
            in approvals
            if booleano(
                registro.get(
                    "execucao_real"
                )
            )
        ]

        aprovacoes_auto_block = [
            registro
            for registro
            in approvals
            if booleano(
                registro.get(
                    "bloqueio_automatico"
                )
            )
        ]

        suite.testar(
            "APPROVAL",
            "Approval nao executou acao real",
            len(
                aprovacoes_reais
            ) == 0,
            len(
                aprovacoes_reais
            )
        )

        suite.testar(
            "APPROVAL",
            "Approval nao realizou bloqueio automatico",
            len(
                aprovacoes_auto_block
            ) == 0,
            len(
                aprovacoes_auto_block
            )
        )

        modos_approval = {
            texto(
                registro.get(
                    "modo_operacional"
                )
            ).upper()
            for registro
            in approvals
        }

        suite.testar(
            "APPROVAL",
            "Approval permanece em SIMULACAO",
            modos_approval
            <= {
                "SIMULACAO"
            },
            sorted(
                modos_approval
            )
        )

        # ========================================================
        # ETAPA 12
        # ========================================================

        titulo(
            "ETAPA 12 - CENARIOS DE REFERENCIA"
        )

        caso_critico = casos_atuais.get(
            "8.8.8.8"
        )

        caso_baixo = casos_atuais.get(
            "1.1.1.1"
        )

        suite.testar(
            "CENARIO_CRITICO",
            "8.8.8.8 possui prioridade CRITICO",
            texto(
                primeiro_valor(
                    caso_critico,
                    [
                        "prioridade_soc"
                    ],
                    ""
                )
            ).upper()
            == "CRITICO"
        )

        suite.testar(
            "CENARIO_CRITICO",
            "8.8.8.8 possui Decision Score 92.15",
            abs(
                numero(
                    primeiro_valor(
                        caso_critico,
                        [
                            "decision_score"
                        ],
                        0
                    )
                )
                - 92.15
            ) < 0.01
        )

        suite.testar(
            "CENARIO_BAIXO",
            "1.1.1.1 possui prioridade BAIXO",
            texto(
                primeiro_valor(
                    caso_baixo,
                    [
                        "prioridade_soc"
                    ],
                    ""
                )
            ).upper()
            == "BAIXO"
        )

        suite.testar(
            "CENARIO_BAIXO",
            "1.1.1.1 possui Decision Score 25.50",
            abs(
                numero(
                    primeiro_valor(
                        caso_baixo,
                        [
                            "decision_score"
                        ],
                        0
                    )
                )
                - 25.50
            ) < 0.01
        )

        # ========================================================
        # ETAPA 13
        # ========================================================

        titulo(
            "ETAPA 13 - OBSERVABILITY"
        )

        snapshots = tabelas_carregadas[
            "soc_observability_snapshots"
        ]

        ultimo_snapshot = mais_recente(
            snapshots
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

        suite.testar(
            "OBSERVABILITY",
            "Snapshot de observabilidade existe",
            ultimo_snapshot
            is not None
        )

        suite.testar(
            "OBSERVABILITY",
            "Observability Health esta em 100%",
            abs(
                snapshot_health
                - 100.0
            ) < 0.001,
            snapshot_health
        )

        suite.testar(
            "OBSERVABILITY",
            "Observability possui 2 IOCs ativos",
            snapshot_iocs
            == 2,
            snapshot_iocs
        )

        # ========================================================
        # ETAPA 14
        # ========================================================

        titulo(
            "ETAPA 14 - END-TO-END"
        )

        runs_e2e = tabelas_carregadas[
            "soc_end_to_end_runs"
        ]

        ultimo_e2e = mais_recente(
            runs_e2e
        )

        e2e_health = numero(
            primeiro_valor(
                ultimo_e2e,
                [
                    "saude_pipeline"
                ],
                0
            )
        )

        e2e_iocs = inteiro(
            primeiro_valor(
                ultimo_e2e,
                [
                    "iocs_ativos"
                ],
                0
            )
        )

        e2e_completos = inteiro(
            primeiro_valor(
                ultimo_e2e,
                [
                    "iocs_completos"
                ],
                0
            )
        )

        e2e_mitre = booleano(
            primeiro_valor(
                ultimo_e2e,
                [
                    "mitre_consistente"
                ],
                False
            )
        )

        suite.testar(
            "END_TO_END",
            "Run End-to-End existe",
            ultimo_e2e
            is not None
        )

        suite.testar(
            "END_TO_END",
            "Ultimo End-to-End possui Health 100%",
            abs(
                e2e_health
                - 100.0
            ) < 0.001,
            e2e_health
        )

        suite.testar(
            "END_TO_END",
            "Ultimo End-to-End possui 2 IOCs ativos",
            e2e_iocs
            == 2,
            e2e_iocs
        )

        suite.testar(
            "END_TO_END",
            "Ultimo End-to-End possui 2 lineages completos",
            e2e_completos
            == 2,
            e2e_completos
        )

        suite.testar(
            "END_TO_END",
            "Ultimo End-to-End possui MITRE consistente",
            e2e_mitre,
            e2e_mitre
        )

        suite.testar(
            "END_TO_END",
            "Ultimo End-to-End possui zero execucoes reais",
            inteiro(
                primeiro_valor(
                    ultimo_e2e,
                    [
                        "execucoes_reais"
                    ],
                    0
                )
            ) == 0
        )

        suite.testar(
            "END_TO_END",
            "Ultimo End-to-End possui zero bloqueios automaticos",
            inteiro(
                primeiro_valor(
                    ultimo_e2e,
                    [
                        "bloqueios_automaticos"
                    ],
                    0
                )
            ) == 0
        )

        # ========================================================
        # ETAPA 15
        # ========================================================

        titulo(
            "ETAPA 15 - ARQUIVOS"
        )

        for nome, caminho in (
            ARQUIVOS_ESPERADOS.items()
        ):

            existe = caminho.exists()

            suite.testar(
                "ARQUIVOS",
                f"{nome} existe",
                existe,
                str(
                    caminho.relative_to(
                        BASE_DIR
                    )
                )
            )

            if existe:

                suite.testar(
                    "ARQUIVOS",
                    f"{nome} nao esta vazio",
                    caminho.stat().st_size
                    > 0,
                    caminho.stat().st_size
                )

        # ========================================================
        # ETAPA 16
        # ========================================================

        titulo(
            "ETAPA 16 - JSON END-TO-END"
        )

        json_e2e = carregar_json(
            ARQUIVOS_ESPERADOS[
                "end_to_end"
            ]
        )

        suite.testar(
            "JSON",
            "end_to_end_aula_46.json possui JSON valido",
            json_e2e
            is not None
        )

        if json_e2e:

            suite.testar(
                "JSON",
                "Arquivo End-to-End registra Aula 46",
                inteiro(
                    json_e2e.get(
                        "aula"
                    )
                ) == 46
            )

            suite.testar(
                "JSON",
                "Arquivo End-to-End registra versao 3",
                texto(
                    json_e2e.get(
                        "versao"
                    )
                ).startswith(
                    "3"
                )
            )

            semantic = (
                json_e2e.get(
                    "semantic_lineage",
                    {}
                )
            )

            suite.testar(
                "JSON",
                "JSON confirma Decision -> Evidence",
                booleano(
                    semantic.get(
                        "decision_evidence"
                    )
                )
            )

            suite.testar(
                "JSON",
                "JSON confirma MITRE consistente",
                booleano(
                    semantic.get(
                        "mitre_consistente"
                    )
                )
            )

        # ========================================================
        # ETAPA 17
        # ========================================================

        titulo(
            "ETAPA 17 - SEGURANCA"
        )

        decisoes_auto_block = [
            registro
            for registro
            in decisoes
            if booleano(
                primeiro_valor(
                    registro,
                    [
                        "auto_block",
                        "bloqueio_automatico"
                    ],
                    False
                )
            )
        ]

        execucoes_reais_total = len(
            aprovacoes_reais
        )

        bloqueios_total = (
            len(
                decisoes_auto_block
            )
            +
            len(
                transicoes_auto_block
            )
            +
            len(
                aprovacoes_auto_block
            )
        )

        suite.testar(
            "SEGURANCA",
            "Decision Engine nunca habilitou auto-block",
            len(
                decisoes_auto_block
            ) == 0,
            len(
                decisoes_auto_block
            )
        )

        suite.testar(
            "SEGURANCA",
            "Pipeline possui zero execucoes reais",
            execucoes_reais_total
            == 0,
            execucoes_reais_total
        )

        suite.testar(
            "SEGURANCA",
            "Pipeline possui zero bloqueios automaticos",
            bloqueios_total
            == 0,
            bloqueios_total
        )

        suite.testar(
            "SEGURANCA",
            "Modo global e SIMULACAO",
            MODO_OPERACIONAL
            == "SIMULACAO"
        )

        # ========================================================
        # ETAPA 18
        # ========================================================

        titulo(
            "ETAPA 18 - RESUMO POR CATEGORIA"
        )

        categorias = (
            suite.por_categoria()
        )

        for categoria in sorted(
            categorias.keys()
        ):

            dados = categorias[
                categoria
            ]

            print(
                f"{categoria:<20} | "
                f"{dados['ok']:>2}/"
                f"{dados['total']:<2} | "
                f"Falhas: "
                f"{dados['falhas']}"
            )

        # ========================================================
        # ETAPA 19
        # ========================================================

        titulo(
            "ETAPA 19 - VALIDACAO GLOBAL"
        )

        total = suite.total()

        aprovados = suite.aprovados()

        falhas = suite.falhas()

        cobertura = suite.cobertura()

        artefatos_ml_final = all(
            item[
                "ok"
            ]
            for item
            in suite.resultados
            if item[
                "categoria"
            ]
            == "MACHINE_LEARNING"
        )

        schemas_final = all(
            item[
                "ok"
            ]
            for item
            in suite.resultados
            if item[
                "categoria"
            ]
            == "SCHEMA"
        )

        lineage_final = all(
            item[
                "ok"
            ]
            for item
            in suite.resultados
            if item[
                "categoria"
            ]
            in {
                "LINEAGE",
                "MITRE",
                "END_TO_END"
            }
        )

        seguranca_final = all(
            item[
                "ok"
            ]
            for item
            in suite.resultados
            if item[
                "categoria"
            ]
            in {
                "SEGURANCA",
                "APPROVAL",
                "LIFECYCLE"
            }
        )

        print(
            f"Testes executados: "
            f"{total}"
        )

        print(
            f"Testes aprovados: "
            f"{aprovados}"
        )

        print(
            f"Testes com falha: "
            f"{falhas}"
        )

        print(
            f"Cobertura final: "
            f"{cobertura:.2f}%"
        )

        print()

        if falhas == 0:

            ok(
                "TODOS OS TESTES FINAIS FORAM APROVADOS"
            )

        else:

            erro(
                "EXISTEM TESTES FINAIS COM FALHA"
            )

        # ========================================================
        # ETAPA 20
        # ========================================================

        titulo(
            "ETAPA 20 - PERSISTINDO VALIDACAO"
        )

        criar_tabela_testes(
            conexao
        )

        validation_id = gerar_id(
            "VAL-47-V2"
        )

        status = (
            "AULA 47 V2 CONCLUIDA"
            if falhas == 0
            else
            "AULA 47 V2 COM PENDENCIAS"
        )

        dados_validacao = {
            "validation_id":
                validation_id,

            "timestamp":
                agora_iso(),

            "testes_total":
                total,

            "testes_ok":
                aprovados,

            "testes_falha":
                falhas,

            "cobertura":
                round(
                    cobertura,
                    2
                ),

            "iocs_ativos":
                len(
                    iocs_ativos
                ),

            "artefatos_ml_ok":
                artefatos_ml_final,

            "schemas_ok":
                schemas_final,

            "lineage_ok":
                lineage_final,

            "seguranca_ok":
                seguranca_final,

            "execucoes_reais":
                execucoes_reais_total,

            "bloqueios_automaticos":
                bloqueios_total,

            "status":
                status
        }

        persistir_validacao(
            conexao,
            dados_validacao
        )

        ok(
            f"Validation Run persistido: "
            f"{validation_id}"
        )

        # ========================================================
        # ETAPA 21
        # ========================================================

        titulo(
            "ETAPA 21 - EXPORTANDO RESULTADOS"
        )

        resultado_final = {
            "projeto":
                PROJETO,

            "aula":
                AULA,

            "versao":
                VERSAO,

            "validation_id":
                validation_id,

            "timestamp":
                agora_iso(),

            "ambiente": {
                "modo_operacional":
                    MODO_OPERACIONAL,

                "iocs_ativos":
                    sorted(
                        iocs_ativos
                    )
            },

            "resultado": {
                "testes_total":
                    total,

                "testes_ok":
                    aprovados,

                "testes_falha":
                    falhas,

                "cobertura":
                    round(
                        cobertura,
                        2
                    )
            },

            "categorias":
                categorias,

            "checks_finais": {
                "machine_learning":
                    artefatos_ml_final,

                "schemas":
                    schemas_final,

                "lineage":
                    lineage_final,

                "seguranca":
                    seguranca_final
            },

            "seguranca": {
                "execucoes_reais":
                    execucoes_reais_total,

                "bloqueios_automaticos":
                    bloqueios_total,

                "modo_operacional":
                    MODO_OPERACIONAL
            },

            "testes":
                suite.resultados,

            "status":
                status
        }

        salvar_json(
            ARQUIVO_RESULTADOS,
            resultado_final
        )

        ok(
            "Resultado completo V2 salvo"
        )

        print(
            "Arquivo: "
            "testes\\final_validation_aula_47.json"
        )

        relatorio = {
            "projeto":
                PROJETO,

            "aula":
                AULA,

            "versao":
                VERSAO,

            "titulo":
                "Testes e Validacao Final V2",

            "validation_id":
                validation_id,

            "timestamp":
                agora_iso(),

            "testes":
                f"{aprovados}/{total}",

            "falhas":
                falhas,

            "cobertura":
                round(
                    cobertura,
                    2
                ),

            "iocs_ativos":
                len(
                    iocs_ativos
                ),

            "machine_learning":
                artefatos_ml_final,

            "schemas":
                schemas_final,

            "lineage":
                lineage_final,

            "seguranca":
                seguranca_final,

            "execucoes_reais":
                execucoes_reais_total,

            "bloqueios_automaticos":
                bloqueios_total,

            "modo_operacional":
                MODO_OPERACIONAL,

            "status":
                status
        }

        salvar_json(
            ARQUIVO_RELATORIO,
            relatorio
        )

        ok(
            "Relatorio final V2 salvo"
        )

        print(
            "Arquivo: "
            "alertas\\relatorio_aula_47.json"
        )

        # ========================================================
        # RESUMO
        # ========================================================

        titulo(
            "RESUMO FINAL DA AULA 47 V2"
        )

        print(
            f"IOCs ativos: "
            f"{len(iocs_ativos)}"
        )

        print()

        print(
            "Machine Learning: "
            f"{'OK' if artefatos_ml_final else 'FALHA'}"
        )

        print(
            "Schemas: "
            f"{'OK' if schemas_final else 'FALHA'}"
        )

        print(
            "Lineage: "
            f"{'OK' if lineage_final else 'FALHA'}"
        )

        print(
            "Seguranca: "
            f"{'OK' if seguranca_final else 'FALHA'}"
        )

        print()

        print(
            f"Testes executados: "
            f"{total}"
        )

        print(
            f"Aprovados: "
            f"{aprovados}"
        )

        print(
            f"Falhas: "
            f"{falhas}"
        )

        print(
            f"Cobertura: "
            f"{cobertura:.2f}%"
        )

        print()

        print(
            f"Execucoes reais: "
            f"{execucoes_reais_total}"
        )

        print(
            f"Bloqueios automaticos: "
            f"{bloqueios_total}"
        )

        print(
            f"Modo operacional: "
            f"{MODO_OPERACIONAL}"
        )

        print()

        print(
            f"Status: "
            f"{status}"
        )

        # ========================================================
        # ARQUITETURA
        # ========================================================

        titulo(
            "ARQUITETURA DA AULA 47 V2"
        )

        print(
r"""
                     CYBERSENTINEL-ML
                            |
                            v
                   FINAL TEST SUITE
                            |
                            v
                  SCHEMA VALIDATION
                            |
              +-------------+-------------+
              |                           |
              v                           v
       SCHEMA MODERNO                SCHEMA LEGADO
       ip_origem                     ioc / ip /
              |                      ioc_valor
              |                           |
              +-------------+-------------+
                            |
                            v
                   IDENTIFICADOR IOC
                            |
                            v
                  COMPATIBILIDADE OK
                            |
                            v
                     LINEAGE TESTS
                            |
                            v
                   SECURITY TESTS
                            |
                            v
                  FINAL VALIDATION


REGRA:

Schema compativel
    !=
nome de coluna obrigatoriamente identico


O pipeline reconhece:

- ip_origem
- ioc
- ioc_valor
- ioc_value
- ip


NAO fazemos migracao artificial
apenas para satisfazer um teste.


INVARIANTES:

Decision.evidence_id
        ==
Evidence.evidence_id


Risk Score:
0 <= score <= 100


Evidence Score:
0 <= score <= 100


Decision Score:
0 <= score <= 100


SEGURANCA:

Execucao real ............... 0
Bloqueio automatico ......... 0
Contencao ................... NAO EXECUTADA
Firewall .................... NAO ALTERADO
Modo ........................ SIMULACAO
"""
        )

        linha()
        print(PROJETO)
        linha()

        print(
            "AULA 47 V2 - TESTES E VALIDACAO FINAL"
        )

        print(status)

    except sqlite3.Error as excecao:

        titulo(
            "ERRO SQLITE - AULA 47 V2"
        )

        erro(
            str(excecao)
        )

        print(
            "Status: AULA 47 V2 COM PENDENCIAS"
        )

    except Exception as excecao:

        titulo(
            "ERRO INESPERADO - AULA 47 V2"
        )

        erro(
            f"{type(excecao).__name__}: "
            f"{excecao}"
        )

        print(
            "Status: AULA 47 V2 COM PENDENCIAS"
        )

    finally:

        if conexao is not None:
            conexao.close()


# ================================================================
# EXECUCAO
# ================================================================

if __name__ == "__main__":
    main()