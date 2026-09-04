# ============================================================
# CyberSentinel-ML
# AULA 30 - BASELINE DINAMICO E DETECCAO DE DESVIO
#
# OBJETIVOS:
# - Utilizar metricas da Aula 28
# - Utilizar SQLite das aulas anteriores
# - Construir baseline operacional dinamico
# - Calcular media e desvio-padrao
# - Comparar janela recente com historico
# - Detectar desvio de latencia
# - Detectar desvio na taxa de ataques
# - Evitar conclusoes com poucas amostras
# - Persistir snapshots do baseline
#
# IMPORTANTE:
# Esta aula trabalha com observabilidade do pipeline.
# Nao estamos retreinando o modelo ML nesta etapa.
# ============================================================

import math
import sqlite3
from pathlib import Path
from datetime import datetime, timezone

from flask import Flask, jsonify, request


# ============================================================
# CONFIGURACOES
# ============================================================

PROJETO = "CyberSentinel-ML"
AULA = 30
API_VERSION = "1.5"

BASE_DIR = Path(__file__).resolve().parent
PASTA_DADOS = BASE_DIR / "dados"
BANCO_PATH = PASTA_DADOS / "cybersentinel.db"

app = Flask(__name__)


# ============================================================
# CONFIGURACAO DO BASELINE
# ============================================================

JANELA_BASELINE = 500
JANELA_ATUAL = 50

MINIMO_AMOSTRAS_BASELINE = 20
MINIMO_AMOSTRAS_ATUAL = 5

FATOR_DESVIO_PADRAO = 2.0

LIMITE_ABSOLUTO_LATENCIA_MS = 500.0
LIMITE_VARIACAO_ATAQUES_PERCENTUAL = 30.0


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


def aviso(texto):
    print(f"[AVISO] {texto}")


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
print("AULA 30 - BASELINE DINAMICO E DETECCAO DE DESVIO")
print(PROJETO)
print(f"API v{API_VERSION}")
linha()


# ============================================================
# PREPARANDO AMBIENTE
# ============================================================

titulo("ETAPA 1 - PREPARANDO AMBIENTE")

PASTA_DADOS.mkdir(
    parents=True,
    exist_ok=True
)

sucesso("Diretorio dados pronto")


if not BANCO_PATH.exists():

    erro("Banco cybersentinel.db nao encontrado")

    raise FileNotFoundError(
        "Banco SQLite das aulas anteriores "
        "nao foi encontrado."
    )


sucesso(
    f"Banco encontrado: "
    f"{BANCO_PATH.relative_to(BASE_DIR)}"
)


# ============================================================
# SQLITE
# ============================================================

def conectar_banco():

    conexao = sqlite3.connect(
        BANCO_PATH,
        timeout=10
    )

    conexao.row_factory = sqlite3.Row

    return conexao


# ============================================================
# VALIDAR TABELA
# ============================================================

def tabela_existe(nome):

    conexao = conectar_banco()

    cursor = conexao.cursor()

    cursor.execute(
        """
        SELECT name
        FROM sqlite_master
        WHERE type = 'table'
        AND name = ?
        """,
        (nome,)
    )

    resultado = cursor.fetchone()

    conexao.close()

    return resultado is not None


# ============================================================
# VALIDANDO OBSERVABILIDADE
# ============================================================

titulo("ETAPA 2 - VALIDANDO OBSERVABILIDADE")

if not tabela_existe("metricas"):

    erro("Tabela metricas nao encontrada")

    raise RuntimeError(
        "Execute primeiro a Aula 28."
    )


sucesso("Tabela metricas encontrada")


# ============================================================
# CRIAR TABELA DE BASELINES
# ============================================================

def inicializar_tabela_baselines():

    conexao = conectar_banco()

    cursor = conexao.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS baselines_operacionais (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            timestamp TEXT NOT NULL,

            quantidade_amostras INTEGER NOT NULL,

            latencia_media REAL,

            latencia_desvio REAL,

            latencia_minima REAL,

            latencia_maxima REAL,

            taxa_ataques REAL,

            taxa_erros REAL,

            taxa_rejeicoes REAL,

            status TEXT NOT NULL

        )
        """
    )

    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS
        idx_baselines_timestamp
        ON baselines_operacionais(timestamp)
        """
    )

    conexao.commit()

    conexao.close()


titulo("ETAPA 3 - PREPARANDO BASELINE")

inicializar_tabela_baselines()

sucesso("Tabela baselines_operacionais pronta")


# ============================================================
# CARREGAR METRICAS
# ============================================================

def carregar_metricas(limite):

    conexao = conectar_banco()

    cursor = conexao.cursor()

    cursor.execute(
        """
        SELECT

            id,
            timestamp,
            status,
            classificacao,
            categoria,
            severidade,
            tempo_total_ms

        FROM metricas

        ORDER BY id DESC

        LIMIT ?
        """,
        (limite,)
    )

    dados = [
        dict(item)
        for item in cursor.fetchall()
    ]

    conexao.close()

    return dados


# ============================================================
# CALCULOS ESTATISTICOS
# ============================================================

def calcular_media(valores):

    if not valores:
        return 0.0

    return sum(valores) / len(valores)


def calcular_desvio_padrao(valores):

    if len(valores) < 2:
        return 0.0

    media = calcular_media(valores)

    variancia = sum(
        (valor - media) ** 2
        for valor in valores
    ) / len(valores)

    return math.sqrt(variancia)


# ============================================================
# ANALISAR CONJUNTO
# ============================================================

def analisar_metricas(metricas):

    total = len(metricas)

    sucessos = [
        item
        for item in metricas
        if item["status"] == "SUCESSO"
    ]

    latencias = [
        float(item["tempo_total_ms"])
        for item in sucessos
        if item["tempo_total_ms"] is not None
    ]

    ataques = sum(
        1
        for item in metricas
        if item["classificacao"] == "ATAQUE"
    )

    normais = sum(
        1
        for item in metricas
        if item["classificacao"] == "NORMAL"
    )

    erros = sum(
        1
        for item in metricas
        if item["status"] == "ERRO"
    )

    rejeicoes = sum(
        1
        for item in metricas
        if item["status"] == "REJEITADO"
    )

    classificados = ataques + normais

    taxa_ataques = (
        ataques / classificados * 100
        if classificados
        else 0.0
    )

    taxa_erros = (
        erros / total * 100
        if total
        else 0.0
    )

    taxa_rejeicoes = (
        rejeicoes / total * 100
        if total
        else 0.0
    )

    return {

        "amostras":
            total,

        "sucessos":
            len(sucessos),

        "ataques":
            ataques,

        "normais":
            normais,

        "erros":
            erros,

        "rejeicoes":
            rejeicoes,

        "latencia_media_ms":
            round(
                calcular_media(latencias),
                4
            ),

        "latencia_desvio_ms":
            round(
                calcular_desvio_padrao(latencias),
                4
            ),

        "latencia_minima_ms":
            round(
                min(latencias)
                if latencias
                else 0.0,
                4
            ),

        "latencia_maxima_ms":
            round(
                max(latencias)
                if latencias
                else 0.0,
                4
            ),

        "taxa_ataques_percentual":
            round(taxa_ataques, 2),

        "taxa_erros_percentual":
            round(taxa_erros, 2),

        "taxa_rejeicoes_percentual":
            round(taxa_rejeicoes, 2),
    }


# ============================================================
# CONSTRUIR BASELINE
# ============================================================

def construir_baseline():

    metricas = carregar_metricas(
        JANELA_BASELINE
    )

    analise = analisar_metricas(
        metricas
    )

    if (
        analise["amostras"]
        < MINIMO_AMOSTRAS_BASELINE
    ):

        status = "AMOSTRAS_INSUFICIENTES"

    else:

        status = "BASELINE_VALIDO"

    baseline = {
        **analise,
        "status": status,
        "timestamp": agora(),
    }

    return baseline


# ============================================================
# SALVAR BASELINE
# ============================================================

def salvar_baseline(baseline):

    conexao = conectar_banco()

    cursor = conexao.cursor()

    cursor.execute(
        """
        INSERT INTO baselines_operacionais (

            timestamp,
            quantidade_amostras,
            latencia_media,
            latencia_desvio,
            latencia_minima,
            latencia_maxima,
            taxa_ataques,
            taxa_erros,
            taxa_rejeicoes,
            status

        )

        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,

        (
            baseline["timestamp"],

            baseline["amostras"],

            baseline["latencia_media_ms"],

            baseline["latencia_desvio_ms"],

            baseline["latencia_minima_ms"],

            baseline["latencia_maxima_ms"],

            baseline[
                "taxa_ataques_percentual"
            ],

            baseline[
                "taxa_erros_percentual"
            ],

            baseline[
                "taxa_rejeicoes_percentual"
            ],

            baseline["status"],
        )
    )

    conexao.commit()

    registro = cursor.lastrowid

    conexao.close()

    return registro


# ============================================================
# JANELA ATUAL
# ============================================================

def construir_janela_atual():

    metricas = carregar_metricas(
        JANELA_ATUAL
    )

    analise = analisar_metricas(
        metricas
    )

    return analise


# ============================================================
# DETECTAR DESVIOS
# ============================================================

def detectar_desvios(
    baseline,
    atual
):

    desvios = []


    # ========================================================
    # PROTECAO CONTRA POUCAS AMOSTRAS
    # ========================================================

    if (
        baseline["amostras"]
        < MINIMO_AMOSTRAS_BASELINE
    ):

        return {
            "status": "BASELINE_INSUFICIENTE",
            "desvios": [],
        }


    if (
        atual["amostras"]
        < MINIMO_AMOSTRAS_ATUAL
    ):

        return {
            "status": "JANELA_ATUAL_INSUFICIENTE",
            "desvios": [],
        }


    # ========================================================
    # LIMITE DINAMICO DE LATENCIA
    # ========================================================

    limite_dinamico_latencia = (
        baseline["latencia_media_ms"]
        +
        (
            FATOR_DESVIO_PADRAO
            *
            baseline["latencia_desvio_ms"]
        )
    )


    # ========================================================
    # LATENCIA MEDIA
    # ========================================================

    if (
        atual["latencia_media_ms"]
        > limite_dinamico_latencia
        and
        atual["latencia_media_ms"]
        > baseline["latencia_media_ms"]
    ):

        desvios.append(
            {
                "tipo":
                    "DESVIO_LATENCIA_MEDIA",

                "severidade":
                    "ALTO",

                "valor_atual":
                    atual[
                        "latencia_media_ms"
                    ],

                "baseline":
                    baseline[
                        "latencia_media_ms"
                    ],

                "limite_dinamico":
                    round(
                        limite_dinamico_latencia,
                        4
                    ),

                "descricao":
                    (
                        "Latencia media da janela "
                        "atual acima do comportamento "
                        "historico esperado."
                    ),
            }
        )


    # ========================================================
    # PICO ABSOLUTO
    # ========================================================

    if (
        atual["latencia_maxima_ms"]
        > LIMITE_ABSOLUTO_LATENCIA_MS
    ):

        desvios.append(
            {
                "tipo":
                    "PICO_LATENCIA_ABSOLUTO",

                "severidade":
                    "CRITICO",

                "valor_atual":
                    atual[
                        "latencia_maxima_ms"
                    ],

                "limite":
                    LIMITE_ABSOLUTO_LATENCIA_MS,

                "descricao":
                    (
                        "Pico absoluto de latencia "
                        "acima do limite de seguranca "
                        "operacional do laboratorio."
                    ),
            }
        )


    # ========================================================
    # TAXA DE ATAQUES
    # ========================================================

    diferenca_ataques = (
        atual[
            "taxa_ataques_percentual"
        ]
        -
        baseline[
            "taxa_ataques_percentual"
        ]
    )


    if (
        diferenca_ataques
        >
        LIMITE_VARIACAO_ATAQUES_PERCENTUAL
    ):

        desvios.append(
            {
                "tipo":
                    "DESVIO_TAXA_ATAQUES",

                "severidade":
                    "ALTO",

                "valor_atual":
                    atual[
                        "taxa_ataques_percentual"
                    ],

                "baseline":
                    baseline[
                        "taxa_ataques_percentual"
                    ],

                "variacao":
                    round(
                        diferenca_ataques,
                        2
                    ),

                "limite_variacao":
                    LIMITE_VARIACAO_ATAQUES_PERCENTUAL,

                "descricao":
                    (
                        "A proporcao de ataques "
                        "aumentou significativamente "
                        "em relacao ao baseline."
                    ),
            }
        )


    # ========================================================
    # ERROS
    # ========================================================

    if (
        atual["taxa_erros_percentual"]
        >
        baseline["taxa_erros_percentual"]
        + 10
    ):

        desvios.append(
            {
                "tipo":
                    "DESVIO_TAXA_ERROS",

                "severidade":
                    "CRITICO",

                "valor_atual":
                    atual[
                        "taxa_erros_percentual"
                    ],

                "baseline":
                    baseline[
                        "taxa_erros_percentual"
                    ],

                "descricao":
                    (
                        "A taxa de erros aumentou "
                        "significativamente em "
                        "relacao ao baseline."
                    ),
            }
        )


    # ========================================================
    # REJEICOES
    # ========================================================

    if (
        atual[
            "taxa_rejeicoes_percentual"
        ]
        >
        baseline[
            "taxa_rejeicoes_percentual"
        ]
        + 20
    ):

        desvios.append(
            {
                "tipo":
                    "DESVIO_REJEICOES",

                "severidade":
                    "ALTO",

                "valor_atual":
                    atual[
                        "taxa_rejeicoes_percentual"
                    ],

                "baseline":
                    baseline[
                        "taxa_rejeicoes_percentual"
                    ],

                "descricao":
                    (
                        "A taxa de eventos rejeitados "
                        "aumentou em relacao ao "
                        "comportamento historico."
                    ),
            }
        )


    # ========================================================
    # STATUS
    # ========================================================

    if any(
        item["severidade"] == "CRITICO"
        for item in desvios
    ):

        status = "CRITICO"

    elif desvios:

        status = "DESVIO_DETECTADO"

    else:

        status = "ESTAVEL"


    return {
        "status": status,
        "desvios": desvios,
    }


# ============================================================
# CONSULTAR BASELINES
# ============================================================

def consultar_baselines(limite=20):

    conexao = conectar_banco()

    cursor = conexao.cursor()

    cursor.execute(
        """
        SELECT

            id,
            timestamp,
            quantidade_amostras,
            latencia_media,
            latencia_desvio,
            latencia_minima,
            latencia_maxima,
            taxa_ataques,
            taxa_erros,
            taxa_rejeicoes,
            status

        FROM baselines_operacionais

        ORDER BY id DESC

        LIMIT ?
        """,

        (limite,)
    )

    dados = [
        dict(item)
        for item in cursor.fetchall()
    ]

    conexao.close()

    return dados


# ============================================================
# ROOT
# ============================================================

@app.route("/", methods=["GET"])
def root():

    return jsonify(
        {
            "projeto":
                PROJETO,

            "aula":
                AULA,

            "api":
                API_VERSION,

            "servico":
                "Dynamic Operational Baseline",

            "endpoints": {
                "health":
                    "GET /health",

                "baseline":
                    "GET /baseline",

                "analyze":
                    "GET /analyze",

                "history":
                    "GET /baseline/history",

                "config":
                    "GET /config",
            },

            "timestamp":
                agora(),
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

            "banco":
                str(
                    BANCO_PATH.relative_to(
                        BASE_DIR
                    )
                ),

            "metricas":
                tabela_existe("metricas"),

            "baselines":
                tabela_existe(
                    "baselines_operacionais"
                ),

            "timestamp":
                agora(),
        }
    ), 200


# ============================================================
# CONFIG
# ============================================================

@app.route(
    "/config",
    methods=["GET"]
)
def config():

    return jsonify(
        {
            "projeto":
                PROJETO,

            "configuracao": {

                "janela_baseline":
                    JANELA_BASELINE,

                "janela_atual":
                    JANELA_ATUAL,

                "minimo_amostras_baseline":
                    MINIMO_AMOSTRAS_BASELINE,

                "minimo_amostras_atual":
                    MINIMO_AMOSTRAS_ATUAL,

                "fator_desvio_padrao":
                    FATOR_DESVIO_PADRAO,

                "limite_absoluto_latencia_ms":
                    LIMITE_ABSOLUTO_LATENCIA_MS,

                "limite_variacao_ataques_percentual":
                    LIMITE_VARIACAO_ATAQUES_PERCENTUAL,
            },

            "timestamp":
                agora(),
        }
    ), 200


# ============================================================
# BASELINE
# ============================================================

@app.route(
    "/baseline",
    methods=["GET"]
)
def baseline():

    baseline_atual = construir_baseline()

    registro = salvar_baseline(
        baseline_atual
    )

    baseline_atual[
        "registro_banco"
    ] = registro

    return jsonify(
        {
            "projeto":
                PROJETO,

            "baseline":
                baseline_atual,

            "timestamp":
                agora(),
        }
    ), 200


# ============================================================
# ANALYZE
# ============================================================

@app.route(
    "/analyze",
    methods=["GET"]
)
def analyze():

    baseline_atual = construir_baseline()

    janela_atual = construir_janela_atual()

    resultado = detectar_desvios(
        baseline_atual,
        janela_atual
    )

    return jsonify(
        {
            "projeto":
                PROJETO,

            "baseline":
                baseline_atual,

            "janela_atual":
                janela_atual,

            "analise":
                resultado,

            "timestamp":
                agora(),
        }
    ), 200


# ============================================================
# HISTORICO
# ============================================================

@app.route(
    "/baseline/history",
    methods=["GET"]
)
def baseline_history():

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
        min(limite, 100)
    )


    dados = consultar_baselines(
        limite
    )


    return jsonify(
        {
            "projeto":
                PROJETO,

            "quantidade":
                len(dados),

            "baselines":
                dados,

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
            "projeto":
                PROJETO,

            "status":
                "ERRO",

            "erro":
                "Endpoint nao encontrado.",

            "endpoints": [
                "/",
                "/health",
                "/config",
                "/baseline",
                "/analyze",
                "/baseline/history",
            ],
        }
    ), 404


# ============================================================
# VALIDACAO
# ============================================================

def validar_aula():

    validacoes = {

        "Banco SQLite encontrado":
            BANCO_PATH.exists(),

        "Tabela metricas encontrada":
            tabela_existe("metricas"),

        "Tabela baselines criada":
            tabela_existe(
                "baselines_operacionais"
            ),

        "Janela baseline valida":
            JANELA_BASELINE > 0,

        "Janela atual valida":
            JANELA_ATUAL > 0,

        "Minimo baseline valido":
            MINIMO_AMOSTRAS_BASELINE > 0,

        "Minimo atual valido":
            MINIMO_AMOSTRAS_ATUAL > 0,

        "Fator estatistico valido":
            FATOR_DESVIO_PADRAO > 0,
    }


    quantidade_ok = 0


    for nome, resultado in validacoes.items():

        if resultado:

            sucesso(nome)
            quantidade_ok += 1

        else:

            erro(nome)


    saude = (
        quantidade_ok
        / len(validacoes)
        * 100
    )


    print()

    print(
        f"Validacoes: "
        f"{quantidade_ok}/"
        f"{len(validacoes)}"
    )

    print(
        f"Saude: {saude:.2f}%"
    )


    if saude != 100:

        raise RuntimeError(
            "Aula 30 nao passou "
            "nas validacoes."
        )


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    titulo(
        "VALIDACAO FINAL DA AULA 30"
    )

    validar_aula()


    # ========================================================
    # BASELINE INICIAL
    # ========================================================

    titulo(
        "ANALISE DO BASELINE ATUAL"
    )


    baseline_inicial = (
        construir_baseline()
    )


    print(
        f"Amostras disponiveis: "
        f"{baseline_inicial['amostras']}"
    )

    print(
        f"Status baseline: "
        f"{baseline_inicial['status']}"
    )

    print(
        f"Latencia media: "
        f"{baseline_inicial['latencia_media_ms']:.4f} ms"
    )

    print(
        f"Desvio padrao: "
        f"{baseline_inicial['latencia_desvio_ms']:.4f} ms"
    )

    print(
        f"Taxa ataques: "
        f"{baseline_inicial['taxa_ataques_percentual']:.2f}%"
    )


    if (
        baseline_inicial["status"]
        == "AMOSTRAS_INSUFICIENTES"
    ):

        aviso(
            "Ainda nao existem amostras suficientes "
            "para considerar o baseline confiavel."
        )

        print()

        print(
            f"Necessario: "
            f"{MINIMO_AMOSTRAS_BASELINE} amostras"
        )

        print(
            f"Disponivel: "
            f"{baseline_inicial['amostras']} amostra(s)"
        )


    # ========================================================
    # API
    # ========================================================

    titulo(
        "CYBERSENTINEL-ML DYNAMIC BASELINE"
    )


    print(
        "Motor de baseline dinamico pronto."
    )

    print()

    print(
        "Endereco:"
    )

    print(
        "http://127.0.0.1:5005"
    )

    print()

    print(
        "Health:"
    )

    print(
        "GET http://127.0.0.1:5005/health"
    )

    print()

    print(
        "Configuracao:"
    )

    print(
        "GET http://127.0.0.1:5005/config"
    )

    print()

    print(
        "Construir baseline:"
    )

    print(
        "GET http://127.0.0.1:5005/baseline"
    )

    print()

    print(
        "Analisar desvio:"
    )

    print(
        "GET http://127.0.0.1:5005/analyze"
    )

    print()

    print(
        "Historico:"
    )

    print(
        "GET http://127.0.0.1:5005/baseline/history"
    )

    print()

    print(
        "Pressione CTRL+C para encerrar."
    )

    linha()


    app.run(
        host="127.0.0.1",
        port=5005,
        debug=False
    )