# ============================================================
# CyberSentinel-ML
# AULA 29 - DETECCAO DE ANOMALIAS OPERACIONAIS
#
# OBJETIVO:
# - Ler as metricas persistidas pela Aula 28
# - Monitorar a saude operacional do pipeline
# - Detectar aumento de erros/rejeicoes
# - Detectar latencia elevada
# - Detectar concentracao de ataques
# - Detectar concentracao de eventos criticos
# - Gerar alertas operacionais
# - Persistir os alertas no SQLite
# - Expor API de monitoramento
#
# IMPORTANTE:
# Os limites desta aula sao limites de LABORATORIO.
# Eles nao representam thresholds universais de producao.
# ============================================================

import sqlite3
from pathlib import Path
from datetime import datetime, timezone

from flask import Flask, jsonify, request


# ============================================================
# CONFIGURACOES
# ============================================================

PROJETO = "CyberSentinel-ML"
AULA = 29
API_VERSION = "1.4"

BASE_DIR = Path(__file__).resolve().parent
PASTA_DADOS = BASE_DIR / "dados"

BANCO_PATH = PASTA_DADOS / "cybersentinel.db"

app = Flask(__name__)


# ============================================================
# LIMITES OPERACIONAIS DO LABORATORIO
# ============================================================

LIMITE_AMOSTRAS = 100

LIMITE_LATENCIA_MEDIA_MS = 150.0
LIMITE_LATENCIA_MAXIMA_MS = 500.0

LIMITE_TAXA_ERRO_PERCENTUAL = 10.0
LIMITE_TAXA_REJEICAO_PERCENTUAL = 20.0

LIMITE_TAXA_ATAQUES_PERCENTUAL = 80.0
LIMITE_TAXA_CRITICOS_PERCENTUAL = 50.0


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
    return datetime.now(timezone.utc).isoformat()


# ============================================================
# CABECALHO
# ============================================================

linha()
print("AULA 29 - DETECCAO DE ANOMALIAS OPERACIONAIS")
print(PROJETO)
print(f"API v{API_VERSION}")
linha()


# ============================================================
# ETAPA 1 - PREPARANDO AMBIENTE
# ============================================================

titulo("ETAPA 1 - PREPARANDO AMBIENTE")

PASTA_DADOS.mkdir(
    parents=True,
    exist_ok=True
)

sucesso("Diretorio dados pronto")


if not BANCO_PATH.exists():
    erro(
        f"Banco SQLite nao encontrado: "
        f"{BANCO_PATH}"
    )

    raise FileNotFoundError(
        "Execute primeiro as aulas anteriores "
        "para criar o banco cybersentinel.db."
    )


sucesso(
    f"Banco encontrado: "
    f"{BANCO_PATH.relative_to(BASE_DIR)}"
)


# ============================================================
# BANCO
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
# ETAPA 2 - VALIDANDO AULA 28
# ============================================================

titulo("ETAPA 2 - VALIDANDO OBSERVABILIDADE")

if not tabela_existe("metricas"):

    erro("Tabela metricas nao encontrada")

    raise RuntimeError(
        "A tabela metricas da Aula 28 "
        "precisa existir."
    )


sucesso("Tabela metricas encontrada")


# ============================================================
# TABELA DE ALERTAS OPERACIONAIS
# ============================================================

def inicializar_alertas_operacionais():

    conexao = conectar_banco()

    cursor = conexao.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS alertas_operacionais (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            alerta_id TEXT NOT NULL UNIQUE,

            timestamp TEXT NOT NULL,

            tipo TEXT NOT NULL,

            severidade TEXT NOT NULL,

            metrica TEXT NOT NULL,

            valor REAL,

            limite REAL,

            descricao TEXT NOT NULL,

            status TEXT NOT NULL

        )
        """
    )

    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS
        idx_alertas_operacionais_timestamp
        ON alertas_operacionais(timestamp)
        """
    )

    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS
        idx_alertas_operacionais_tipo
        ON alertas_operacionais(tipo)
        """
    )

    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS
        idx_alertas_operacionais_severidade
        ON alertas_operacionais(severidade)
        """
    )

    conexao.commit()

    conexao.close()


titulo("ETAPA 3 - PREPARANDO ALERTAS OPERACIONAIS")

inicializar_alertas_operacionais()

sucesso("Tabela alertas_operacionais pronta")


# ============================================================
# GERAR ID
# ============================================================

def gerar_alerta_id():

    return (
        "OPS-ALT-"
        + datetime.now(
            timezone.utc
        ).strftime("%Y%m%d%H%M%S%f")
    )


# ============================================================
# SALVAR ALERTA
# ============================================================

def salvar_alerta(alerta):

    conexao = conectar_banco()

    cursor = conexao.cursor()

    cursor.execute(
        """
        INSERT INTO alertas_operacionais (

            alerta_id,
            timestamp,
            tipo,
            severidade,
            metrica,
            valor,
            limite,
            descricao,
            status

        )

        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,

        (
            alerta["alerta_id"],
            alerta["timestamp"],
            alerta["tipo"],
            alerta["severidade"],
            alerta["metrica"],
            alerta["valor"],
            alerta["limite"],
            alerta["descricao"],
            alerta["status"],
        )
    )

    conexao.commit()

    registro = cursor.lastrowid

    conexao.close()

    return registro


# ============================================================
# CRIAR ALERTA
# ============================================================

def criar_alerta(
    tipo,
    severidade,
    metrica,
    valor,
    limite,
    descricao
):

    alerta = {

        "alerta_id":
            gerar_alerta_id(),

        "timestamp":
            agora(),

        "tipo":
            tipo,

        "severidade":
            severidade,

        "metrica":
            metrica,

        "valor":
            round(float(valor), 4),

        "limite":
            round(float(limite), 4),

        "descricao":
            descricao,

        "status":
            "ABERTO",
    }

    registro = salvar_alerta(alerta)

    alerta["registro_banco"] = registro

    return alerta


# ============================================================
# LER JANELA RECENTE
# ============================================================

def carregar_metricas_recentes(
    limite=LIMITE_AMOSTRAS
):

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

        (limite,)
    )

    dados = [
        dict(linha)
        for linha in cursor.fetchall()
    ]

    conexao.close()

    return dados


# ============================================================
# CALCULAR RESUMO
# ============================================================

def calcular_resumo(metricas):

    total = len(metricas)

    sucesso_total = sum(
        1
        for item in metricas
        if item["status"] == "SUCESSO"
    )

    rejeitados = sum(
        1
        for item in metricas
        if item["status"] == "REJEITADO"
    )

    erros = sum(
        1
        for item in metricas
        if item["status"] == "ERRO"
    )

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

    criticos = sum(
        1
        for item in metricas
        if item["severidade"] == "CRITICO"
    )

    latencias = [
        float(item["tempo_total_ms"])
        for item in metricas
        if (
            item["status"] == "SUCESSO"
            and item["tempo_total_ms"] is not None
        )
    ]

    latencia_media = (
        sum(latencias) / len(latencias)
        if latencias
        else 0.0
    )

    latencia_maxima = (
        max(latencias)
        if latencias
        else 0.0
    )

    taxa_sucesso = (
        sucesso_total / total * 100
        if total
        else 0.0
    )

    taxa_rejeicao = (
        rejeitados / total * 100
        if total
        else 0.0
    )

    taxa_erro = (
        erros / total * 100
        if total
        else 0.0
    )

    eventos_classificados = (
        ataques + normais
    )

    taxa_ataques = (
        ataques
        / eventos_classificados
        * 100
        if eventos_classificados
        else 0.0
    )

    taxa_criticos = (
        criticos
        / ataques
        * 100
        if ataques
        else 0.0
    )

    return {

        "amostras":
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

        "criticos":
            criticos,

        "taxa_sucesso_percentual":
            round(taxa_sucesso, 2),

        "taxa_rejeicao_percentual":
            round(taxa_rejeicao, 2),

        "taxa_erro_percentual":
            round(taxa_erro, 2),

        "taxa_ataques_percentual":
            round(taxa_ataques, 2),

        "taxa_criticos_percentual":
            round(taxa_criticos, 2),

        "latencia_media_ms":
            round(latencia_media, 4),

        "latencia_maxima_ms":
            round(latencia_maxima, 4),
    }


# ============================================================
# MOTOR DE DETECCAO OPERACIONAL
# ============================================================

def detectar_anomalias(
    resumo,
    persistir=True
):

    alertas = []

    # --------------------------------------------------------
    # SEM DADOS
    # --------------------------------------------------------

    if resumo["amostras"] == 0:

        return alertas


    # --------------------------------------------------------
    # LATENCIA MEDIA
    # --------------------------------------------------------

    if (
        resumo["latencia_media_ms"]
        > LIMITE_LATENCIA_MEDIA_MS
    ):

        alerta = {

            "tipo":
                "LATENCIA_ELEVADA",

            "severidade":
                "ALTO",

            "metrica":
                "latencia_media_ms",

            "valor":
                resumo["latencia_media_ms"],

            "limite":
                LIMITE_LATENCIA_MEDIA_MS,

            "descricao":
                (
                    "Latencia media do pipeline "
                    "acima do limite operacional."
                ),
        }

        alertas.append(alerta)


    # --------------------------------------------------------
    # LATENCIA MAXIMA
    # --------------------------------------------------------

    if (
        resumo["latencia_maxima_ms"]
        > LIMITE_LATENCIA_MAXIMA_MS
    ):

        alerta = {

            "tipo":
                "PICO_LATENCIA",

            "severidade":
                "CRITICO",

            "metrica":
                "latencia_maxima_ms",

            "valor":
                resumo["latencia_maxima_ms"],

            "limite":
                LIMITE_LATENCIA_MAXIMA_MS,

            "descricao":
                (
                    "Foi identificado um pico "
                    "de latencia no pipeline."
                ),
        }

        alertas.append(alerta)


    # --------------------------------------------------------
    # TAXA DE ERRO
    # --------------------------------------------------------

    if (
        resumo["taxa_erro_percentual"]
        > LIMITE_TAXA_ERRO_PERCENTUAL
    ):

        alerta = {

            "tipo":
                "TAXA_ERRO_ELEVADA",

            "severidade":
                "CRITICO",

            "metrica":
                "taxa_erro_percentual",

            "valor":
                resumo[
                    "taxa_erro_percentual"
                ],

            "limite":
                LIMITE_TAXA_ERRO_PERCENTUAL,

            "descricao":
                (
                    "A taxa de erros internos "
                    "superou o limite operacional."
                ),
        }

        alertas.append(alerta)


    # --------------------------------------------------------
    # REJEICOES
    # --------------------------------------------------------

    if (
        resumo["taxa_rejeicao_percentual"]
        > LIMITE_TAXA_REJEICAO_PERCENTUAL
    ):

        alerta = {

            "tipo":
                "REJEICOES_ELEVADAS",

            "severidade":
                "ALTO",

            "metrica":
                "taxa_rejeicao_percentual",

            "valor":
                resumo[
                    "taxa_rejeicao_percentual"
                ],

            "limite":
                LIMITE_TAXA_REJEICAO_PERCENTUAL,

            "descricao":
                (
                    "Quantidade elevada de "
                    "eventos rejeitados."
                ),
        }

        alertas.append(alerta)


    # --------------------------------------------------------
    # CONCENTRACAO DE ATAQUES
    # --------------------------------------------------------

    if (
        resumo["taxa_ataques_percentual"]
        > LIMITE_TAXA_ATAQUES_PERCENTUAL
    ):

        alerta = {

            "tipo":
                "CONCENTRACAO_ATAQUES",

            "severidade":
                "ALTO",

            "metrica":
                "taxa_ataques_percentual",

            "valor":
                resumo[
                    "taxa_ataques_percentual"
                ],

            "limite":
                LIMITE_TAXA_ATAQUES_PERCENTUAL,

            "descricao":
                (
                    "Alta concentracao de eventos "
                    "classificados como ATAQUE "
                    "na janela analisada."
                ),
        }

        alertas.append(alerta)


    # --------------------------------------------------------
    # EVENTOS CRITICOS
    # --------------------------------------------------------

    if (
        resumo["ataques"] > 0
        and
        resumo["taxa_criticos_percentual"]
        > LIMITE_TAXA_CRITICOS_PERCENTUAL
    ):

        alerta = {

            "tipo":
                "CONCENTRACAO_CRITICOS",

            "severidade":
                "CRITICO",

            "metrica":
                "taxa_criticos_percentual",

            "valor":
                resumo[
                    "taxa_criticos_percentual"
                ],

            "limite":
                LIMITE_TAXA_CRITICOS_PERCENTUAL,

            "descricao":
                (
                    "Alta concentracao de "
                    "ataques com severidade "
                    "CRITICO."
                ),
        }

        alertas.append(alerta)


    # --------------------------------------------------------
    # PERSISTENCIA
    # --------------------------------------------------------

    if persistir:

        alertas_persistidos = []

        for item in alertas:

            alerta_salvo = criar_alerta(

                tipo=item["tipo"],

                severidade=item[
                    "severidade"
                ],

                metrica=item["metrica"],

                valor=item["valor"],

                limite=item["limite"],

                descricao=item[
                    "descricao"
                ],
            )

            alertas_persistidos.append(
                alerta_salvo
            )

        return alertas_persistidos


    return alertas


# ============================================================
# CONSULTAR ALERTAS
# ============================================================

def consultar_alertas(limite=50):

    conexao = conectar_banco()

    cursor = conexao.cursor()

    cursor.execute(
        """
        SELECT

            id,
            alerta_id,
            timestamp,
            tipo,
            severidade,
            metrica,
            valor,
            limite,
            descricao,
            status

        FROM alertas_operacionais

        ORDER BY id DESC

        LIMIT ?
        """,

        (limite,)
    )

    dados = [
        dict(linha)
        for linha in cursor.fetchall()
    ]

    conexao.close()

    return dados


# ============================================================
# STATUS OPERACIONAL
# ============================================================

def determinar_status(alertas):

    if any(
        item["severidade"] == "CRITICO"
        for item in alertas
    ):

        return "CRITICO"

    if any(
        item["severidade"] == "ALTO"
        for item in alertas
    ):

        return "DEGRADADO"

    return "SAUDAVEL"


# ============================================================
# ENDPOINT ROOT
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
                "Operational Anomaly Detection",

            "endpoints": {

                "health":
                    "GET /health",

                "monitor":
                    "GET /monitor",

                "alerts":
                    "GET /alerts",

                "thresholds":
                    "GET /thresholds",
            },

            "timestamp":
                agora(),
        }
    ), 200


# ============================================================
# HEALTH
# ============================================================

@app.route("/health", methods=["GET"])
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

            "alertas_operacionais":
                tabela_existe(
                    "alertas_operacionais"
                ),

            "timestamp":
                agora(),
        }
    ), 200


# ============================================================
# THRESHOLDS
# ============================================================

@app.route(
    "/thresholds",
    methods=["GET"]
)
def thresholds():

    return jsonify(
        {
            "projeto":
                PROJETO,

            "ambiente":
                "LABORATORIO",

            "limites": {

                "amostras":
                    LIMITE_AMOSTRAS,

                "latencia_media_ms":
                    LIMITE_LATENCIA_MEDIA_MS,

                "latencia_maxima_ms":
                    LIMITE_LATENCIA_MAXIMA_MS,

                "taxa_erro_percentual":
                    LIMITE_TAXA_ERRO_PERCENTUAL,

                "taxa_rejeicao_percentual":
                    LIMITE_TAXA_REJEICAO_PERCENTUAL,

                "taxa_ataques_percentual":
                    LIMITE_TAXA_ATAQUES_PERCENTUAL,

                "taxa_criticos_percentual":
                    LIMITE_TAXA_CRITICOS_PERCENTUAL,
            },

            "timestamp":
                agora(),
        }
    ), 200


# ============================================================
# MONITOR
# ============================================================

@app.route(
    "/monitor",
    methods=["GET"]
)
def monitor():

    try:

        limite = int(
            request.args.get(
                "limit",
                LIMITE_AMOSTRAS
            )
        )

    except ValueError:

        limite = LIMITE_AMOSTRAS


    limite = max(
        1,
        min(limite, 1000)
    )


    metricas = carregar_metricas_recentes(
        limite
    )


    resumo = calcular_resumo(
        metricas
    )


    alertas = detectar_anomalias(
        resumo,
        persistir=True
    )


    status_operacional = (
        determinar_status(
            alertas
        )
    )


    return jsonify(
        {
            "projeto":
                PROJETO,

            "api":
                API_VERSION,

            "status_operacional":
                status_operacional,

            "janela_analisada":
                limite,

            "resumo":
                resumo,

            "anomalias_detectadas":
                len(alertas),

            "alertas":
                alertas,

            "timestamp":
                agora(),
        }
    ), 200


# ============================================================
# ALERTAS OPERACIONAIS
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
        min(limite, 100)
    )


    alertas = consultar_alertas(
        limite
    )


    return jsonify(
        {
            "projeto":
                PROJETO,

            "quantidade":
                len(alertas),

            "alertas":
                alertas,

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
                "/monitor",
                "/alerts",
                "/thresholds",
            ],
        }
    ), 404


# ============================================================
# VALIDACAO FINAL
# ============================================================

def validar_aula():

    validacoes = {

        "Banco SQLite encontrado":
            BANCO_PATH.exists(),

        "Tabela metricas encontrada":
            tabela_existe("metricas"),

        "Tabela alertas_operacionais criada":
            tabela_existe(
                "alertas_operacionais"
            ),

        "Limite de amostras valido":
            LIMITE_AMOSTRAS > 0,

        "Threshold de latencia valido":
            LIMITE_LATENCIA_MEDIA_MS > 0,

        "Threshold de erro valido":
            (
                0
                <= LIMITE_TAXA_ERRO_PERCENTUAL
                <= 100
            ),

        "Threshold de ataques valido":
            (
                0
                <= LIMITE_TAXA_ATAQUES_PERCENTUAL
                <= 100
            ),

        "Threshold de criticos valido":
            (
                0
                <= LIMITE_TAXA_CRITICOS_PERCENTUAL
                <= 100
            ),
    }


    quantidade_ok = 0


    for nome, resultado in (
        validacoes.items()
    ):

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
            "Aula 29 nao passou "
            "nas validacoes."
        )


    return quantidade_ok, saude


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    titulo(
        "VALIDACAO FINAL DA AULA 29"
    )


    validar_aula()


    # ========================================================
    # ANALISE INICIAL
    # ========================================================

    titulo(
        "ANALISE OPERACIONAL INICIAL"
    )


    metricas_iniciais = (
        carregar_metricas_recentes(
            LIMITE_AMOSTRAS
        )
    )


    resumo_inicial = (
        calcular_resumo(
            metricas_iniciais
        )
    )


    alertas_iniciais = (
        detectar_anomalias(
            resumo_inicial,
            persistir=False
        )
    )


    status_inicial = (
        determinar_status(
            alertas_iniciais
        )
    )


    print(
        f"Amostras encontradas: "
        f"{resumo_inicial['amostras']}"
    )

    print(
        f"Ataques: "
        f"{resumo_inicial['ataques']}"
    )

    print(
        f"Normais: "
        f"{resumo_inicial['normais']}"
    )

    print(
        f"Erros: "
        f"{resumo_inicial['erros']}"
    )

    print(
        f"Rejeitados: "
        f"{resumo_inicial['rejeitados']}"
    )

    print(
        f"Latencia media: "
        f"{resumo_inicial['latencia_media_ms']:.4f} ms"
    )

    print(
        f"Latencia maxima: "
        f"{resumo_inicial['latencia_maxima_ms']:.4f} ms"
    )

    print(
        f"Anomalias atuais: "
        f"{len(alertas_iniciais)}"
    )

    print(
        f"Status operacional: "
        f"{status_inicial}"
    )


    # ========================================================
    # API
    # ========================================================

    titulo(
        "CYBERSENTINEL-ML OPERATIONAL MONITOR"
    )


    print(
        "Motor de deteccao operacional pronto."
    )

    print()

    print(
        "Endereco:"
    )

    print(
        "http://127.0.0.1:5004"
    )

    print()

    print(
        "Health:"
    )

    print(
        "GET http://127.0.0.1:5004/health"
    )

    print()

    print(
        "Monitor:"
    )

    print(
        "GET http://127.0.0.1:5004/monitor"
    )

    print()

    print(
        "Alertas:"
    )

    print(
        "GET http://127.0.0.1:5004/alerts"
    )

    print()

    print(
        "Thresholds:"
    )

    print(
        "GET http://127.0.0.1:5004/thresholds"
    )

    print()

    print(
        "Pressione CTRL+C para encerrar."
    )

    linha()


    app.run(
        host="127.0.0.1",
        port=5004,
        debug=False
    )