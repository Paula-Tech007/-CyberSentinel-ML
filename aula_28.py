# ============================================================
# CyberSentinel-ML
# AULA 28 - OBSERVABILIDADE E METRICAS OPERACIONAIS
#
# OBJETIVO:
# - Manter detector binario + multiclasse
# - Manter persistencia SQLite
# - Medir latencia de processamento
# - Medir tempo de inferencia ML
# - Registrar sucesso / erro
# - Consultar metricas historicas
# - Observar categorias e severidades
#
# FLUXO:
#
# EVENTO HTTP
#     |
#     v
# VALIDACAO
#     |
#     v
# ML BINARIO
#     |
#     +---- NORMAL
#     |
#     v
# MULTICLASSE
#     |
#     v
# ALERTA SOC
#     |
#     v
# SQLITE
#     |
#     +---- EVENTOS
#     +---- ALERTAS
#     +---- METRICAS
#
# ============================================================

import sqlite3
import time
from pathlib import Path
from datetime import datetime, timezone

import joblib
import numpy as np
import pandas as pd
from flask import Flask, jsonify, request


# ============================================================
# CONFIGURACOES
# ============================================================

PROJETO = "CyberSentinel-ML"
AULA = 28
API_VERSION = "1.3"

BASE_DIR = Path(__file__).resolve().parent

PASTA_MODELOS = BASE_DIR / "modelos"
PASTA_DADOS = BASE_DIR / "dados"

BANCO_PATH = (
    PASTA_DADOS /
    "cybersentinel.db"
)

MODELO_BINARIO_PATH = (
    PASTA_MODELOS /
    "unsw_decision_tree.joblib"
)

CONFIG_BINARIO_PATH = (
    PASTA_MODELOS /
    "configuracao_modelo.joblib"
)

MODELO_MULTICLASSE_PATH = (
    PASTA_MODELOS /
    "unsw_attack_multiclass_otimizado.joblib"
)

CONFIG_MULTICLASSE_PATH = (
    PASTA_MODELOS /
    "configuracao_multiclasse_otimizada_aula_22.joblib"
)


FEATURES = [
    "spkts",
    "dpkts",
    "sbytes",
    "dbytes",
    "rate",
    "sttl",
    "dttl",
    "sload",
    "dload",
]


# ============================================================
# FLASK
# ============================================================

app = Flask(__name__)


# ============================================================
# FUNCOES VISUAIS
# ============================================================

def linha():
    print("=" * 72)


def titulo(texto):
    print()
    linha()
    print(texto)
    linha()


def sucesso(texto):
    print(f"[OK] {texto}")


def erro(texto):
    print(f"[ERRO] {texto}")


def agora():
    return datetime.now(
        timezone.utc
    ).isoformat()


# ============================================================
# CABECALHO
# ============================================================

linha()
print("AULA 28 - OBSERVABILIDADE E METRICAS OPERACIONAIS")
print(PROJETO)
print(f"API v{API_VERSION}")
linha()


# ============================================================
# ETAPA 1 - DIRETORIOS
# ============================================================

titulo(
    "ETAPA 1 - PREPARANDO DIRETORIOS"
)

PASTA_MODELOS.mkdir(
    parents=True,
    exist_ok=True
)

PASTA_DADOS.mkdir(
    parents=True,
    exist_ok=True
)

sucesso(
    "Diretorio modelos pronto"
)

sucesso(
    "Diretorio dados pronto"
)


# ============================================================
# ETAPA 2 - VALIDANDO ARTEFATOS
# ============================================================

titulo(
    "ETAPA 2 - VALIDANDO ARTEFATOS ML"
)

artefatos = {

    "Modelo binario":
        MODELO_BINARIO_PATH,

    "Configuracao binaria":
        CONFIG_BINARIO_PATH,

    "Modelo multiclasse":
        MODELO_MULTICLASSE_PATH,

    "Configuracao multiclasse":
        CONFIG_MULTICLASSE_PATH,
}


for nome, caminho in artefatos.items():

    if not caminho.exists():

        erro(
            f"{nome} nao encontrado: "
            f"{caminho}"
        )

        raise FileNotFoundError(
            caminho
        )

    sucesso(
        f"{nome}: "
        f"{caminho.relative_to(BASE_DIR)}"
    )


# ============================================================
# ETAPA 3 - CARREGANDO MODELOS
# ============================================================

titulo(
    "ETAPA 3 - CARREGANDO MODELOS"
)

modelo_binario = joblib.load(
    MODELO_BINARIO_PATH
)

config_binario = joblib.load(
    CONFIG_BINARIO_PATH
)

modelo_multiclasse = joblib.load(
    MODELO_MULTICLASSE_PATH
)

config_multiclasse = joblib.load(
    CONFIG_MULTICLASSE_PATH
)

sucesso(
    "Modelo binario carregado"
)

sucesso(
    "Configuracao binaria carregada"
)

sucesso(
    "Modelo multiclasse carregado"
)

sucesso(
    "Configuracao multiclasse carregada"
)


print()

print(
    f"Modelo binario: "
    f"{type(modelo_binario).__name__}"
)

print(
    f"Modelo multiclasse: "
    f"{type(modelo_multiclasse).__name__}"
)


# ============================================================
# ETAPA 4 - CONFIGURACAO ML
# ============================================================

titulo(
    "ETAPA 4 - VALIDANDO CONFIGURACAO"
)

features_binario = list(
    config_binario.get(
        "features",
        FEATURES
    )
)

features_multiclasse = list(
    config_multiclasse.get(
        "features",
        FEATURES
    )
)


if features_binario != FEATURES:

    raise ValueError(
        "Features binarias incompativeis."
    )


if features_multiclasse != FEATURES:

    raise ValueError(
        "Features multiclasse incompativeis."
    )


THRESHOLD = float(
    config_binario.get(
        "threshold",
        0.5
    )
)


sucesso(
    "Features binarias compativeis"
)

sucesso(
    "Features multiclasse compativeis"
)


print()

print(
    f"Features: {len(FEATURES)}"
)

print(
    f"Threshold: {THRESHOLD:.4f}"
)


# ============================================================
# SQLITE
# ============================================================

def conectar_banco():

    conexao = sqlite3.connect(
        BANCO_PATH,
        timeout=10
    )

    conexao.row_factory = (
        sqlite3.Row
    )

    return conexao


# ============================================================
# INICIALIZANDO BANCO
# ============================================================

def inicializar_banco():

    conexao = conectar_banco()

    cursor = conexao.cursor()


    # ========================================================
    # TABELA EVENTOS
    # ========================================================

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS eventos (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            id_evento TEXT NOT NULL,

            origem TEXT,

            timestamp TEXT NOT NULL,

            classificacao TEXT NOT NULL,

            probabilidade_ataque REAL,

            categoria_ataque TEXT,

            confianca_categoria REAL,

            severidade TEXT,

            alerta_soc INTEGER NOT NULL,

            alerta_id TEXT,

            spkts REAL,

            dpkts REAL,

            sbytes REAL,

            dbytes REAL,

            rate REAL,

            sttl REAL,

            dttl REAL,

            sload REAL,

            dload REAL

        )
        """
    )


    # ========================================================
    # TABELA ALERTAS
    # ========================================================

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS alertas (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            alerta_id TEXT NOT NULL UNIQUE,

            id_evento TEXT NOT NULL,

            timestamp TEXT NOT NULL,

            categoria TEXT,

            severidade TEXT,

            probabilidade REAL,

            confianca REAL,

            origem TEXT

        )
        """
    )


    # ========================================================
    # NOVA TABELA - METRICAS
    # ========================================================

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS metricas (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            timestamp TEXT NOT NULL,

            endpoint TEXT NOT NULL,

            id_evento TEXT,

            status TEXT NOT NULL,

            classificacao TEXT,

            categoria TEXT,

            severidade TEXT,

            tempo_validacao_ms REAL,

            tempo_binario_ms REAL,

            tempo_multiclasse_ms REAL,

            tempo_total_ms REAL,

            erro TEXT

        )
        """
    )


    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS
        idx_metricas_timestamp
        ON metricas(timestamp)
        """
    )


    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS
        idx_metricas_status
        ON metricas(status)
        """
    )


    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS
        idx_metricas_classificacao
        ON metricas(classificacao)
        """
    )


    conexao.commit()

    conexao.close()


# ============================================================
# ETAPA 5 - SQLITE
# ============================================================

titulo(
    "ETAPA 5 - INICIALIZANDO OBSERVABILIDADE"
)

inicializar_banco()

sucesso(
    "SQLite inicializado"
)

sucesso(
    "Tabela eventos pronta"
)

sucesso(
    "Tabela alertas pronta"
)

sucesso(
    "Tabela metricas pronta"
)


print()

print(
    f"Banco: "
    f"{BANCO_PATH.relative_to(BASE_DIR)}"
)


# ============================================================
# VALIDACAO DO EVENTO
# ============================================================

def validar_evento(evento):

    if not isinstance(
        evento,
        dict
    ):

        raise ValueError(
            "Evento precisa ser objeto JSON."
        )


    valores = {}


    for feature in FEATURES:

        if feature not in evento:

            raise ValueError(
                f"Feature obrigatoria "
                f"ausente: {feature}"
            )


        try:

            valor = float(
                evento[feature]
            )

        except (
            TypeError,
            ValueError
        ):

            raise ValueError(
                f"Valor invalido para "
                f"{feature}"
            )


        if not np.isfinite(
            valor
        ):

            raise ValueError(
                f"Valor nao finito para "
                f"{feature}"
            )


        if valor < 0:

            raise ValueError(
                f"Valor negativo nao "
                f"permitido para {feature}"
            )


        valores[feature] = valor


    dataframe = pd.DataFrame(
        [valores],
        columns=FEATURES
    )


    return dataframe, valores


# ============================================================
# DETECTOR BINARIO
# ============================================================

def detectar_binario(dataframe):

    if hasattr(
        modelo_binario,
        "predict_proba"
    ):

        probabilidades = (
            modelo_binario.predict_proba(
                dataframe
            )
        )


        classes = list(
            modelo_binario.classes_
        )


        if 1 in classes:

            indice = classes.index(1)

        elif "1" in classes:

            indice = classes.index("1")

        else:

            raise ValueError(
                "Classe ATAQUE nao encontrada."
            )


        probabilidade = float(
            probabilidades[
                0,
                indice
            ]
        )


        classificacao = (
            1
            if probabilidade >= THRESHOLD
            else 0
        )


        return (
            classificacao,
            probabilidade
        )


    predicao = int(
        modelo_binario.predict(
            dataframe
        )[0]
    )


    return (
        predicao,
        float(predicao)
    )


# ============================================================
# MULTICLASSE
# ============================================================

def detectar_categoria(dataframe):

    categoria = str(
        modelo_multiclasse.predict(
            dataframe
        )[0]
    )


    confianca = None


    if hasattr(
        modelo_multiclasse,
        "predict_proba"
    ):

        probabilidades = (
            modelo_multiclasse.predict_proba(
                dataframe
            )[0]
        )


        confianca = float(
            np.max(
                probabilidades
            )
        )


    return (
        categoria,
        confianca
    )


# ============================================================
# SEVERIDADE
# ============================================================

def calcular_severidade(
    categoria,
    probabilidade
):

    criticos = {
        "Backdoor",
        "Exploits",
        "Shellcode",
        "Worms",
    }


    altos = {
        "DoS",
        "Generic",
    }


    if categoria in criticos:

        return "CRITICO"


    if categoria in altos:

        return "ALTO"


    if probabilidade >= 0.90:

        return "ALTO"


    return "MEDIO"


# ============================================================
# ALERTA ID
# ============================================================

def gerar_alerta_id():

    return (
        "OBS-ALT-"
        + datetime.now(
            timezone.utc
        ).strftime(
            "%Y%m%d%H%M%S%f"
        )
    )


# ============================================================
# PERSISTIR EVENTO
# ============================================================

def persistir_evento(
    resultado,
    valores
):

    conexao = conectar_banco()

    cursor = conexao.cursor()


    cursor.execute(
        """
        INSERT INTO eventos (

            id_evento,
            origem,
            timestamp,
            classificacao,
            probabilidade_ataque,
            categoria_ataque,
            confianca_categoria,
            severidade,
            alerta_soc,
            alerta_id,

            spkts,
            dpkts,
            sbytes,
            dbytes,
            rate,
            sttl,
            dttl,
            sload,
            dload

        )

        VALUES (
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
            ?, ?, ?, ?, ?, ?, ?, ?, ?
        )
        """,

        (
            resultado["id_evento"],

            resultado["origem"],

            resultado["timestamp"],

            resultado["classificacao"],

            resultado[
                "probabilidade_ataque"
            ],

            resultado.get(
                "categoria_ataque"
            ),

            resultado.get(
                "confianca_categoria"
            ),

            resultado.get(
                "severidade"
            ),

            1
            if resultado[
                "alerta_soc"
            ]
            else 0,

            resultado.get(
                "alerta_id"
            ),

            valores["spkts"],
            valores["dpkts"],
            valores["sbytes"],
            valores["dbytes"],
            valores["rate"],
            valores["sttl"],
            valores["dttl"],
            valores["sload"],
            valores["dload"],
        )
    )


    conexao.commit()

    registro_id = (
        cursor.lastrowid
    )

    conexao.close()


    return registro_id


# ============================================================
# PERSISTIR ALERTA
# ============================================================

def persistir_alerta(resultado):

    conexao = conectar_banco()

    cursor = conexao.cursor()


    cursor.execute(
        """
        INSERT INTO alertas (

            alerta_id,
            id_evento,
            timestamp,
            categoria,
            severidade,
            probabilidade,
            confianca,
            origem

        )

        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,

        (
            resultado["alerta_id"],

            resultado["id_evento"],

            resultado["timestamp"],

            resultado[
                "categoria_ataque"
            ],

            resultado[
                "severidade"
            ],

            resultado[
                "probabilidade_ataque"
            ],

            resultado.get(
                "confianca_categoria"
            ),

            resultado["origem"],
        )
    )


    conexao.commit()

    registro_id = (
        cursor.lastrowid
    )

    conexao.close()


    return registro_id


# ============================================================
# PERSISTIR METRICAS
# ============================================================

def persistir_metrica(
    id_evento,
    status,
    classificacao=None,
    categoria=None,
    severidade=None,
    tempo_validacao_ms=None,
    tempo_binario_ms=None,
    tempo_multiclasse_ms=None,
    tempo_total_ms=None,
    erro_mensagem=None
):

    conexao = conectar_banco()

    cursor = conexao.cursor()


    cursor.execute(
        """
        INSERT INTO metricas (

            timestamp,
            endpoint,
            id_evento,
            status,
            classificacao,
            categoria,
            severidade,
            tempo_validacao_ms,
            tempo_binario_ms,
            tempo_multiclasse_ms,
            tempo_total_ms,
            erro

        )

        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,

        (
            agora(),
            "/predict",
            id_evento,
            status,
            classificacao,
            categoria,
            severidade,
            tempo_validacao_ms,
            tempo_binario_ms,
            tempo_multiclasse_ms,
            tempo_total_ms,
            erro_mensagem,
        )
    )


    conexao.commit()

    conexao.close()


# ============================================================
# PROCESSAMENTO OBSERVAVEL
# ============================================================

def processar_evento(evento):

    inicio_total = (
        time.perf_counter()
    )


    id_evento = str(
        evento.get(
            "id_evento",
            "SEM-ID"
        )
        if isinstance(evento, dict)
        else "SEM-ID"
    )


    # ========================================================
    # VALIDACAO
    # ========================================================

    inicio_validacao = (
        time.perf_counter()
    )


    dataframe, valores = (
        validar_evento(
            evento
        )
    )


    tempo_validacao_ms = (
        (
            time.perf_counter()
            - inicio_validacao
        )
        * 1000
    )


    origem = str(
        evento.get(
            "origem",
            "API"
        )
    )


    # ========================================================
    # ML BINARIO
    # ========================================================

    inicio_binario = (
        time.perf_counter()
    )


    (
        classificacao,
        probabilidade
    ) = detectar_binario(
        dataframe
    )


    tempo_binario_ms = (
        (
            time.perf_counter()
            - inicio_binario
        )
        * 1000
    )


    timestamp = agora()


    # ========================================================
    # NORMAL
    # ========================================================

    if classificacao == 0:

        resultado = {

            "projeto":
                PROJETO,

            "id_evento":
                id_evento,

            "origem":
                origem,

            "timestamp":
                timestamp,

            "classificacao":
                "NORMAL",

            "probabilidade_ataque":
                round(
                    probabilidade,
                    6
                ),

            "probabilidade_ataque_percentual":
                round(
                    probabilidade * 100,
                    2
                ),

            "categoria_ataque":
                None,

            "confianca_categoria":
                None,

            "severidade":
                None,

            "alerta_soc":
                False,

            "alerta_id":
                None,

            "threshold":
                THRESHOLD,
        }


        registro = persistir_evento(
            resultado,
            valores
        )


        tempo_total_ms = (
            (
                time.perf_counter()
                - inicio_total
            )
            * 1000
        )


        persistir_metrica(
            id_evento=id_evento,
            status="SUCESSO",
            classificacao="NORMAL",
            tempo_validacao_ms=tempo_validacao_ms,
            tempo_binario_ms=tempo_binario_ms,
            tempo_multiclasse_ms=0.0,
            tempo_total_ms=tempo_total_ms
        )


        resultado[
            "registro_banco"
        ] = registro


        resultado[
            "observabilidade"
        ] = {

            "tempo_validacao_ms":
                round(
                    tempo_validacao_ms,
                    4
                ),

            "tempo_binario_ms":
                round(
                    tempo_binario_ms,
                    4
                ),

            "tempo_multiclasse_ms":
                0.0,

            "tempo_total_ms":
                round(
                    tempo_total_ms,
                    4
                ),
        }


        return resultado


    # ========================================================
    # MULTICLASSE
    # ========================================================

    inicio_multiclasse = (
        time.perf_counter()
    )


    (
        categoria,
        confianca
    ) = detectar_categoria(
        dataframe
    )


    tempo_multiclasse_ms = (
        (
            time.perf_counter()
            - inicio_multiclasse
        )
        * 1000
    )


    severidade = calcular_severidade(
        categoria,
        probabilidade
    )


    alerta_id = gerar_alerta_id()


    resultado = {

        "projeto":
            PROJETO,

        "id_evento":
            id_evento,

        "origem":
            origem,

        "timestamp":
            timestamp,

        "classificacao":
            "ATAQUE",

        "probabilidade_ataque":
            round(
                probabilidade,
                6
            ),

        "probabilidade_ataque_percentual":
            round(
                probabilidade * 100,
                2
            ),

        "categoria_ataque":
            categoria,

        "confianca_categoria":
            (
                round(
                    confianca,
                    6
                )
                if confianca is not None
                else None
            ),

        "confianca_categoria_percentual":
            (
                round(
                    confianca * 100,
                    2
                )
                if confianca is not None
                else None
            ),

        "severidade":
            severidade,

        "alerta_soc":
            True,

        "alerta_id":
            alerta_id,

        "threshold":
            THRESHOLD,
    }


    registro_evento = (
        persistir_evento(
            resultado,
            valores
        )
    )


    registro_alerta = (
        persistir_alerta(
            resultado
        )
    )


    tempo_total_ms = (
        (
            time.perf_counter()
            - inicio_total
        )
        * 1000
    )


    persistir_metrica(
        id_evento=id_evento,
        status="SUCESSO",
        classificacao="ATAQUE",
        categoria=categoria,
        severidade=severidade,
        tempo_validacao_ms=tempo_validacao_ms,
        tempo_binario_ms=tempo_binario_ms,
        tempo_multiclasse_ms=tempo_multiclasse_ms,
        tempo_total_ms=tempo_total_ms
    )


    resultado[
        "registro_banco"
    ] = registro_evento


    resultado[
        "registro_alerta"
    ] = registro_alerta


    resultado[
        "observabilidade"
    ] = {

        "tempo_validacao_ms":
            round(
                tempo_validacao_ms,
                4
            ),

        "tempo_binario_ms":
            round(
                tempo_binario_ms,
                4
            ),

        "tempo_multiclasse_ms":
            round(
                tempo_multiclasse_ms,
                4
            ),

        "tempo_total_ms":
            round(
                tempo_total_ms,
                4
            ),
    }


    return resultado


# ============================================================
# ROOT
# ============================================================

@app.route(
    "/",
    methods=["GET"]
)
def raiz():

    return jsonify(
        {
            "projeto":
                PROJETO,

            "aula":
                AULA,

            "api":
                API_VERSION,

            "status":
                "online",

            "observabilidade":
                True,

            "persistencia":
                "SQLite",

            "endpoints": {

                "health":
                    "GET /health",

                "predict":
                    "POST /predict",

                "metrics":
                    "GET /metrics",

                "categories":
                    "GET /metrics/categories",

                "severity":
                    "GET /metrics/severity",

                "latency":
                    "GET /metrics/latency",

                "recent":
                    "GET /metrics/recent",
            },
        }
    ), 200


# ============================================================
# HEALTH
# ============================================================

@app.route(
    "/health",
    methods=["GET"]
)
def health():

    return jsonify(
        {
            "projeto":
                PROJETO,

            "api":
                API_VERSION,

            "status":
                "healthy",

            "observabilidade":
                "SQLite Metrics",

            "banco":
                str(
                    BANCO_PATH.relative_to(
                        BASE_DIR
                    )
                ),

            "features":
                len(FEATURES),

            "threshold":
                THRESHOLD,

            "timestamp":
                agora(),
        }
    ), 200


# ============================================================
# PREDICT
# ============================================================

@app.route(
    "/predict",
    methods=["POST"]
)
def predict():

    inicio_total = (
        time.perf_counter()
    )


    id_evento = "SEM-ID"


    try:

        if not request.is_json:

            raise ValueError(
                "Content-Type precisa ser "
                "application/json."
            )


        evento = request.get_json(
            silent=False
        )


        if isinstance(
            evento,
            dict
        ):

            id_evento = str(
                evento.get(
                    "id_evento",
                    "SEM-ID"
                )
            )


        resultado = processar_evento(
            evento
        )


        resultado[
            "status"
        ] = "PROCESSADO"


        return jsonify(
            resultado
        ), 200


    except ValueError as exc:

        tempo_total_ms = (
            (
                time.perf_counter()
                - inicio_total
            )
            * 1000
        )


        persistir_metrica(
            id_evento=id_evento,
            status="REJEITADO",
            tempo_total_ms=tempo_total_ms,
            erro_mensagem=str(exc)
        )


        return jsonify(
            {
                "projeto":
                    PROJETO,

                "status":
                    "REJEITADO",

                "erro":
                    str(exc),

                "timestamp":
                    agora(),

                "tempo_total_ms":
                    round(
                        tempo_total_ms,
                        4
                    ),
            }
        ), 400


    except Exception as exc:

        tempo_total_ms = (
            (
                time.perf_counter()
                - inicio_total
            )
            * 1000
        )


        persistir_metrica(
            id_evento=id_evento,
            status="ERRO",
            tempo_total_ms=tempo_total_ms,
            erro_mensagem=str(exc)
        )


        print(
            "[ERRO INTERNO]",
            type(exc).__name__,
            str(exc)
        )


        return jsonify(
            {
                "projeto":
                    PROJETO,

                "status":
                    "ERRO",

                "erro":
                    "Falha interna no processamento.",

                "timestamp":
                    agora(),
            }
        ), 500


# ============================================================
# METRICAS GERAIS
# ============================================================

@app.route(
    "/metrics",
    methods=["GET"]
)
def metrics():

    conexao = conectar_banco()

    cursor = conexao.cursor()


    cursor.execute(
        """
        SELECT COUNT(*)
        FROM metricas
        """
    )

    total = cursor.fetchone()[0]


    cursor.execute(
        """
        SELECT COUNT(*)
        FROM metricas
        WHERE status = 'SUCESSO'
        """
    )

    sucesso_total = cursor.fetchone()[0]


    cursor.execute(
        """
        SELECT COUNT(*)
        FROM metricas
        WHERE status = 'REJEITADO'
        """
    )

    rejeitados = cursor.fetchone()[0]


    cursor.execute(
        """
        SELECT COUNT(*)
        FROM metricas
        WHERE status = 'ERRO'
        """
    )

    erros = cursor.fetchone()[0]


    cursor.execute(
        """
        SELECT COUNT(*)
        FROM metricas
        WHERE classificacao = 'ATAQUE'
        """
    )

    ataques = cursor.fetchone()[0]


    cursor.execute(
        """
        SELECT COUNT(*)
        FROM metricas
        WHERE classificacao = 'NORMAL'
        """
    )

    normais = cursor.fetchone()[0]


    conexao.close()


    taxa_sucesso = (
        (
            sucesso_total
            / total
        )
        * 100
        if total > 0
        else 0.0
    )


    return jsonify(
        {
            "projeto":
                PROJETO,

            "metricas": {

                "requisicoes_total":
                    total,

                "sucesso":
                    sucesso_total,

                "rejeitados":
                    rejeitados,

                "erros":
                    erros,

                "ataques":
                    ataques,

                "normais":
                    normais,

                "taxa_sucesso_percentual":
                    round(
                        taxa_sucesso,
                        2
                    ),
            },

            "timestamp":
                agora(),
        }
    ), 200


# ============================================================
# METRICAS POR CATEGORIA
# ============================================================

@app.route(
    "/metrics/categories",
    methods=["GET"]
)
def metricas_categorias():

    conexao = conectar_banco()

    cursor = conexao.cursor()


    cursor.execute(
        """
        SELECT

            categoria,
            COUNT(*) AS quantidade

        FROM metricas

        WHERE categoria IS NOT NULL

        GROUP BY categoria

        ORDER BY quantidade DESC
        """
    )


    dados = [
        {
            "categoria":
                linha["categoria"],

            "quantidade":
                linha["quantidade"],
        }

        for linha in cursor.fetchall()
    ]


    conexao.close()


    return jsonify(
        {
            "projeto":
                PROJETO,

            "categorias":
                dados,

            "timestamp":
                agora(),
        }
    ), 200


# ============================================================
# METRICAS POR SEVERIDADE
# ============================================================

@app.route(
    "/metrics/severity",
    methods=["GET"]
)
def metricas_severidade():

    conexao = conectar_banco()

    cursor = conexao.cursor()


    cursor.execute(
        """
        SELECT

            severidade,
            COUNT(*) AS quantidade

        FROM metricas

        WHERE severidade IS NOT NULL

        GROUP BY severidade

        ORDER BY quantidade DESC
        """
    )


    dados = [
        {
            "severidade":
                linha["severidade"],

            "quantidade":
                linha["quantidade"],
        }

        for linha in cursor.fetchall()
    ]


    conexao.close()


    return jsonify(
        {
            "projeto":
                PROJETO,

            "severidades":
                dados,

            "timestamp":
                agora(),
        }
    ), 200


# ============================================================
# LATENCIA
# ============================================================

@app.route(
    "/metrics/latency",
    methods=["GET"]
)
def metricas_latencia():

    conexao = conectar_banco()

    cursor = conexao.cursor()


    cursor.execute(
        """
        SELECT

            COUNT(*) AS quantidade,

            AVG(tempo_validacao_ms)
                AS validacao_media,

            AVG(tempo_binario_ms)
                AS binario_media,

            AVG(tempo_multiclasse_ms)
                AS multiclasse_media,

            AVG(tempo_total_ms)
                AS total_media,

            MIN(tempo_total_ms)
                AS total_minimo,

            MAX(tempo_total_ms)
                AS total_maximo

        FROM metricas

        WHERE status = 'SUCESSO'
        """
    )


    resultado = cursor.fetchone()

    conexao.close()


    return jsonify(
        {
            "projeto":
                PROJETO,

            "latencia_ms": {

                "amostras":
                    resultado[
                        "quantidade"
                    ],

                "validacao_media":
                    round(
                        resultado[
                            "validacao_media"
                        ] or 0,
                        4
                    ),

                "binario_media":
                    round(
                        resultado[
                            "binario_media"
                        ] or 0,
                        4
                    ),

                "multiclasse_media":
                    round(
                        resultado[
                            "multiclasse_media"
                        ] or 0,
                        4
                    ),

                "total_media":
                    round(
                        resultado[
                            "total_media"
                        ] or 0,
                        4
                    ),

                "total_minimo":
                    round(
                        resultado[
                            "total_minimo"
                        ] or 0,
                        4
                    ),

                "total_maximo":
                    round(
                        resultado[
                            "total_maximo"
                        ] or 0,
                        4
                    ),
            },

            "timestamp":
                agora(),
        }
    ), 200


# ============================================================
# METRICAS RECENTES
# ============================================================

@app.route(
    "/metrics/recent",
    methods=["GET"]
)
def metricas_recent():

    try:

        limite = int(
            request.args.get(
                "limit",
                20
            )
        )

    except ValueError:

        limite = 20


    limite = max(
        1,
        min(
            limite,
            100
        )
    )


    conexao = conectar_banco()

    cursor = conexao.cursor()


    cursor.execute(
        """
        SELECT

            id,
            timestamp,
            endpoint,
            id_evento,
            status,
            classificacao,
            categoria,
            severidade,
            tempo_validacao_ms,
            tempo_binario_ms,
            tempo_multiclasse_ms,
            tempo_total_ms,
            erro

        FROM metricas

        ORDER BY id DESC

        LIMIT ?
        """,

        (
            limite,
        )
    )


    dados = [
        dict(linha)
        for linha in cursor.fetchall()
    ]


    conexao.close()


    return jsonify(
        {
            "projeto":
                PROJETO,

            "quantidade":
                len(dados),

            "metricas":
                dados,

            "timestamp":
                agora(),
        }
    ), 200


# ============================================================
# VALIDACAO DO BANCO
# ============================================================

def validar_tabela_metricas():

    conexao = conectar_banco()

    cursor = conexao.cursor()


    cursor.execute(
        """
        SELECT name
        FROM sqlite_master

        WHERE
            type='table'
            AND
            name='metricas'
        """
    )


    resultado = (
        cursor.fetchone()
    )


    conexao.close()


    return (
        resultado is not None
    )


# ============================================================
# 404
# ============================================================

@app.errorhandler(404)
def endpoint_inexistente(_erro):

    return jsonify(
        {
            "status":
                "ERRO",

            "erro":
                "Endpoint nao encontrado.",

            "endpoints": [

                "/",
                "/health",
                "/predict",
                "/metrics",
                "/metrics/categories",
                "/metrics/severity",
                "/metrics/latency",
                "/metrics/recent",
            ],
        }
    ), 404


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    titulo(
        "VALIDACAO FINAL DA AULA 28"
    )


    validacoes = {

        "Modelo binario carregado":
            modelo_binario is not None,

        "Modelo multiclasse carregado":
            modelo_multiclasse is not None,

        "Configuracao binaria carregada":
            config_binario is not None,

        "Configuracao multiclasse carregada":
            config_multiclasse is not None,

        "9 features configuradas":
            len(FEATURES) == 9,

        "Threshold valido":
            0 <= THRESHOLD <= 1,

        "Banco SQLite existente":
            BANCO_PATH.exists(),

        "Tabela metricas criada":
            validar_tabela_metricas(),
    }


    validacoes_ok = 0


    for nome, resultado in (
        validacoes.items()
    ):

        if resultado:

            sucesso(nome)
            validacoes_ok += 1

        else:

            erro(nome)


    saude = (
        validacoes_ok
        / len(validacoes)
        * 100
    )


    print()

    print(
        f"Validacoes: "
        f"{validacoes_ok}/"
        f"{len(validacoes)}"
    )

    print(
        f"Saude: "
        f"{saude:.2f}%"
    )


    if saude != 100:

        raise RuntimeError(
            "Aula 28 nao passou "
            "nas validacoes."
        )


    titulo(
        "CYBERSENTINEL-ML OBSERVABILITY"
    )


    print(
        "API de observabilidade pronta."
    )

    print()

    print(
        "Endereco:"
    )

    print(
        "http://127.0.0.1:5003"
    )

    print()

    print(
        "Predicao:"
    )

    print(
        "POST http://127.0.0.1:5003/predict"
    )

    print()

    print(
        "Metricas gerais:"
    )

    print(
        "GET http://127.0.0.1:5003/metrics"
    )

    print()

    print(
        "Categorias:"
    )

    print(
        "GET http://127.0.0.1:5003/metrics/categories"
    )

    print()

    print(
        "Severidade:"
    )

    print(
        "GET http://127.0.0.1:5003/metrics/severity"
    )

    print()

    print(
        "Latencia:"
    )

    print(
        "GET http://127.0.0.1:5003/metrics/latency"
    )

    print()

    print(
        "Metricas recentes:"
    )

    print(
        "GET http://127.0.0.1:5003/metrics/recent"
    )

    print()

    print(
        "Pressione CTRL+C para encerrar."
    )

    linha()


    # ========================================================
    # LABORATORIO LOCAL
    # ========================================================

    app.run(
        host="127.0.0.1",
        port=5003,
        debug=False
    )