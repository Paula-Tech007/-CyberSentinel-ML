# ============================================================
# CyberSentinel-ML
# AULA 27 - PERSISTENCIA E HISTORICO SOC
#
# Objetivo:
# - Receber eventos via API
# - Validar as 9 features
# - Executar detector binario
# - Executar classificador multiclasse para ataques
# - Calcular severidade
# - Persistir TODOS os resultados em SQLite
# - Persistir alertas SOC
# - Consultar historico
# - Consultar estatisticas persistentes
#
# Arquitetura:
#
# EVENTO HTTP
#     |
#     v
# VALIDACAO
#     |
#     v
# DETECTOR BINARIO
#     |
#     +-------- NORMAL
#     |
#     v
# ATAQUE
#     |
#     v
# MULTICLASSE
#     |
#     v
# CATEGORIA
#     |
#     v
# SEVERIDADE
#     |
#     v
# ALERTA SOC
#     |
#     v
# SQLITE
#
# ============================================================

import json
import sqlite3
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
AULA = 27
API_VERSION = "1.2"

BASE_DIR = Path(__file__).resolve().parent

PASTA_MODELOS = BASE_DIR / "modelos"
PASTA_DADOS = BASE_DIR / "dados"
PASTA_ALERTAS = BASE_DIR / "alertas"

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
print("AULA 27 - PERSISTENCIA E HISTORICO SOC")
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

PASTA_ALERTAS.mkdir(
    parents=True,
    exist_ok=True
)

sucesso(
    "Diretorio modelos pronto"
)

sucesso(
    "Diretorio dados pronto"
)

sucesso(
    "Diretorio alertas pronto"
)


# ============================================================
# ETAPA 2 - VALIDANDO ARTEFATOS ML
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
    "Modelo binario: "
    f"{type(modelo_binario).__name__}"
)

print(
    "Modelo multiclasse: "
    f"{type(modelo_multiclasse).__name__}"
)


# ============================================================
# ETAPA 4 - CONFIGURACAO ML
# ============================================================

titulo(
    "ETAPA 4 - VALIDANDO CONFIGURACAO ML"
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
# CRIANDO BANCO
# ============================================================

def inicializar_banco():

    conexao = conectar_banco()

    cursor = conexao.cursor()


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


    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS
        idx_eventos_id_evento
        ON eventos(id_evento)
        """
    )


    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS
        idx_eventos_classificacao
        ON eventos(classificacao)
        """
    )


    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS
        idx_eventos_timestamp
        ON eventos(timestamp)
        """
    )


    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS
        idx_alertas_severidade
        ON alertas(severidade)
        """
    )


    conexao.commit()

    conexao.close()


# ============================================================
# ETAPA 5 - BANCO
# ============================================================

titulo(
    "ETAPA 5 - INICIALIZANDO SQLITE"
)

inicializar_banco()

sucesso(
    "Banco SQLite inicializado"
)

sucesso(
    "Tabela eventos pronta"
)

sucesso(
    "Tabela alertas pronta"
)

print()

print(
    f"Banco: "
    f"{BANCO_PATH.relative_to(BASE_DIR)}"
)


# ============================================================
# VALIDACAO DE EVENTO
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
                "Classe de ataque nao "
                "encontrada."
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
# CLASSIFICADOR MULTICLASSE
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

    categorias_criticas = {
        "Backdoor",
        "Exploits",
        "Shellcode",
        "Worms",
    }


    categorias_altas = {
        "DoS",
        "Generic",
    }


    if categoria in categorias_criticas:

        return "CRITICO"


    if categoria in categorias_altas:

        return "ALTO"


    if probabilidade >= 0.90:

        return "ALTO"


    return "MEDIO"


# ============================================================
# GERAR ALERTA ID
# ============================================================

def gerar_alerta_id():

    return (
        "DB-ALT-"
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

def persistir_alerta(
    resultado
):

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
# PROCESSAR EVENTO
# ============================================================

def processar_evento(evento):

    dataframe, valores = (
        validar_evento(
            evento
        )
    )


    id_evento = str(
        evento.get(
            "id_evento",
            "SEM-ID"
        )
    )


    origem = str(
        evento.get(
            "origem",
            "API"
        )
    )


    (
        classificacao,
        probabilidade
    ) = detectar_binario(
        dataframe
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

            "confianca_categoria_percentual":
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


        registro_id = persistir_evento(
            resultado,
            valores
        )


        resultado[
            "registro_banco"
        ] = registro_id


        return resultado


    # ========================================================
    # ATAQUE
    # ========================================================

    (
        categoria,
        confianca
    ) = detectar_categoria(
        dataframe
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


    resultado[
        "registro_banco"
    ] = registro_evento


    resultado[
        "registro_alerta"
    ] = registro_alerta


    return resultado


# ============================================================
# ENDPOINT RAIZ
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

            "persistencia":
                "SQLite",

            "endpoints": {
                "health":
                    "GET /health",

                "predict":
                    "POST /predict",

                "historico":
                    "GET /history",

                "alertas":
                    "GET /alerts",

                "stats":
                    "GET /stats",
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

    banco_ok = BANCO_PATH.exists()


    return jsonify(
        {
            "projeto":
                PROJETO,

            "api":
                API_VERSION,

            "status":
                (
                    "healthy"
                    if banco_ok
                    else "degraded"
                ),

            "persistencia":
                "SQLite",

            "banco":
                str(
                    BANCO_PATH.relative_to(
                        BASE_DIR
                    )
                ),

            "modelo_binario":
                type(
                    modelo_binario
                ).__name__,

            "modelo_multiclasse":
                type(
                    modelo_multiclasse
                ).__name__,

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

    if not request.is_json:

        return jsonify(
            {
                "status":
                    "ERRO",

                "erro":
                    "Content-Type precisa "
                    "ser application/json."
            }
        ), 415


    try:

        evento = request.get_json(
            silent=False
        )


        resultado = (
            processar_evento(
                evento
            )
        )


        resultado[
            "status"
        ] = "PROCESSADO"


        return jsonify(
            resultado
        ), 200


    except ValueError as exc:

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
            }
        ), 400


    except Exception as exc:

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
                    "Falha interna no "
                    "processamento.",

                "timestamp":
                    agora(),
            }
        ), 500


# ============================================================
# HISTORY
# ============================================================

@app.route(
    "/history",
    methods=["GET"]
)
def history():

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
            id_evento,
            origem,
            timestamp,
            classificacao,
            probabilidade_ataque,
            categoria_ataque,
            confianca_categoria,
            severidade,
            alerta_soc,
            alerta_id

        FROM eventos

        ORDER BY id DESC

        LIMIT ?
        """,

        (limite,)
    )


    registros = [
        dict(linha)
        for linha in cursor.fetchall()
    ]


    conexao.close()


    for registro in registros:

        registro[
            "alerta_soc"
        ] = bool(
            registro[
                "alerta_soc"
            ]
        )


    return jsonify(
        {
            "projeto":
                PROJETO,

            "quantidade":
                len(registros),

            "historico":
                registros,

            "timestamp":
                agora(),
        }
    ), 200


# ============================================================
# ALERTS
# ============================================================

@app.route(
    "/alerts",
    methods=["GET"]
)
def alerts():

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
            alerta_id,
            id_evento,
            timestamp,
            categoria,
            severidade,
            probabilidade,
            confianca,
            origem

        FROM alertas

        ORDER BY id DESC

        LIMIT ?
        """,

        (limite,)
    )


    registros = [
        dict(linha)
        for linha in cursor.fetchall()
    ]


    conexao.close()


    return jsonify(
        {
            "projeto":
                PROJETO,

            "quantidade":
                len(registros),

            "alertas":
                registros,

            "timestamp":
                agora(),
        }
    ), 200


# ============================================================
# STATS PERSISTENTES
# ============================================================

@app.route(
    "/stats",
    methods=["GET"]
)
def stats():

    conexao = conectar_banco()

    cursor = conexao.cursor()


    cursor.execute(
        """
        SELECT COUNT(*)
        FROM eventos
        """
    )

    total_eventos = (
        cursor.fetchone()[0]
    )


    cursor.execute(
        """
        SELECT COUNT(*)
        FROM eventos
        WHERE classificacao = 'NORMAL'
        """
    )

    normais = (
        cursor.fetchone()[0]
    )


    cursor.execute(
        """
        SELECT COUNT(*)
        FROM eventos
        WHERE classificacao = 'ATAQUE'
        """
    )

    ataques = (
        cursor.fetchone()[0]
    )


    cursor.execute(
        """
        SELECT COUNT(*)
        FROM alertas
        """
    )

    total_alertas = (
        cursor.fetchone()[0]
    )


    cursor.execute(
        """
        SELECT COUNT(*)
        FROM alertas
        WHERE severidade = 'CRITICO'
        """
    )

    criticos = (
        cursor.fetchone()[0]
    )


    cursor.execute(
        """
        SELECT COUNT(*)
        FROM alertas
        WHERE severidade = 'ALTO'
        """
    )

    altos = (
        cursor.fetchone()[0]
    )


    cursor.execute(
        """
        SELECT COUNT(*)
        FROM alertas
        WHERE severidade = 'MEDIO'
        """
    )

    medios = (
        cursor.fetchone()[0]
    )


    conexao.close()


    return jsonify(
        {
            "projeto":
                PROJETO,

            "persistencia":
                "SQLite",

            "estatisticas": {

                "eventos_total":
                    total_eventos,

                "normais":
                    normais,

                "ataques":
                    ataques,

                "alertas_total":
                    total_alertas,

                "alertas_criticos":
                    criticos,

                "alertas_altos":
                    altos,

                "alertas_medios":
                    medios,
            },

            "timestamp":
                agora(),
        }
    ), 200


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
                "/history",
                "/alerts",
                "/stats",
            ],
        }
    ), 404


# ============================================================
# VALIDACOES
# ============================================================

def validar_banco():

    conexao = conectar_banco()

    cursor = conexao.cursor()


    cursor.execute(
        """
        SELECT name
        FROM sqlite_master
        WHERE type='table'
        """
    )


    tabelas = {
        linha[0]
        for linha in cursor.fetchall()
    }


    conexao.close()


    return (
        "eventos" in tabelas
        and
        "alertas" in tabelas
    )


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    titulo(
        "VALIDACAO FINAL DA AULA 27"
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

        "Banco SQLite criado":
            BANCO_PATH.exists(),

        "Tabelas SQLite validadas":
            validar_banco(),
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
            "Aula 27 nao passou "
            "nas validacoes."
        )


    titulo(
        "CYBERSENTINEL-ML API PERSISTENTE"
    )


    print(
        "API pronta."
    )

    print()

    print(
        "Persistencia:"
    )

    print(
        f"SQLite -> "
        f"{BANCO_PATH.relative_to(BASE_DIR)}"
    )

    print()

    print(
        "Endereco:"
    )

    print(
        "http://127.0.0.1:5002"
    )

    print()

    print(
        "Health:"
    )

    print(
        "GET http://127.0.0.1:5002/health"
    )

    print()

    print(
        "Predicao:"
    )

    print(
        "POST http://127.0.0.1:5002/predict"
    )

    print()

    print(
        "Historico:"
    )

    print(
        "GET http://127.0.0.1:5002/history"
    )

    print()

    print(
        "Alertas:"
    )

    print(
        "GET http://127.0.0.1:5002/alerts"
    )

    print()

    print(
        "Estatisticas:"
    )

    print(
        "GET http://127.0.0.1:5002/stats"
    )

    print()

    print(
        "Pressione CTRL+C para encerrar."
    )

    linha()


    # Somente localhost no laboratorio.
    # Debug permanece desligado.

    app.run(
        host="127.0.0.1",
        port=5002,
        debug=False
    )