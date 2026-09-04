# ============================================================
# CyberSentinel-ML
# AULA 25 - API LOCAL DE DETECCAO ML
#
# Fluxo:
# HTTP POST -> Validacao -> Detector Binario ->
# Multiclasse -> Severidade -> Resposta JSON
# ============================================================

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
AULA = 25
VERSAO_API = "1.0"

BASE_DIR = Path(__file__).resolve().parent

PASTA_MODELOS = BASE_DIR / "modelos"
PASTA_ALERTAS = BASE_DIR / "alertas"

MODELO_BINARIO_PATH = (
    PASTA_MODELOS / "unsw_decision_tree.joblib"
)

CONFIG_BINARIO_PATH = (
    PASTA_MODELOS / "configuracao_modelo.joblib"
)

MODELO_MULTICLASSE_PATH = (
    PASTA_MODELOS / "unsw_attack_multiclass_otimizado.joblib"
)

CONFIG_MULTICLASSE_PATH = (
    PASTA_MODELOS /
    "configuracao_multiclasse_otimizada_aula_22.joblib"
)

ARQUIVO_ALERTAS_API = (
    PASTA_ALERTAS / "alertas_api_aula_25.jsonl"
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
    return datetime.now(timezone.utc).isoformat()


# ============================================================
# INICIALIZANDO FLASK
# ============================================================

app = Flask(__name__)


# ============================================================
# CABECALHO
# ============================================================

linha()
print("AULA 25 - API LOCAL DE DETECCAO ML")
print(PROJETO)
print(f"API v{VERSAO_API}")
linha()


# ============================================================
# ETAPA 1 - PREPARANDO DIRETORIOS
# ============================================================

titulo("ETAPA 1 - PREPARANDO DIRETORIOS")

PASTA_MODELOS.mkdir(
    parents=True,
    exist_ok=True,
)

PASTA_ALERTAS.mkdir(
    parents=True,
    exist_ok=True,
)

sucesso("Diretorio modelos pronto")
sucesso("Diretorio alertas pronto")


# ============================================================
# ETAPA 2 - VALIDANDO ARTEFATOS
# ============================================================

titulo("ETAPA 2 - VALIDANDO ARTEFATOS ML")

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
            f"{nome} nao encontrado: {caminho}"
        )

        raise FileNotFoundError(
            f"Artefato obrigatorio ausente: {caminho}"
        )

    sucesso(
        f"{nome}: "
        f"{caminho.relative_to(BASE_DIR)}"
    )


# ============================================================
# ETAPA 3 - CARREGANDO MODELOS
# ============================================================

titulo("ETAPA 3 - CARREGANDO MODELOS")

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

sucesso("Modelo binario carregado")
sucesso("Configuracao binaria carregada")
sucesso("Modelo multiclasse carregado")
sucesso("Configuracao multiclasse carregada")

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
# ETAPA 4 - VALIDANDO FEATURES
# ============================================================

titulo("ETAPA 4 - VALIDANDO COMPATIBILIDADE")

features_binario = list(
    config_binario.get(
        "features",
        FEATURES,
    )
)

features_multiclasse = list(
    config_multiclasse.get(
        "features",
        FEATURES,
    )
)

if features_binario != FEATURES:

    raise ValueError(
        "Features do modelo binario "
        "nao sao compativeis com a API."
    )

if features_multiclasse != FEATURES:

    raise ValueError(
        "Features do modelo multiclasse "
        "nao sao compativeis com a API."
    )

sucesso("Features do modelo binario compativeis")
sucesso("Features do modelo multiclasse compativeis")


# ============================================================
# THRESHOLD
# ============================================================

try:

    THRESHOLD = float(
        config_binario.get(
            "threshold",
            0.5,
        )
    )

except Exception:

    THRESHOLD = 0.5


print()
print(
    f"Threshold binario: "
    f"{THRESHOLD:.4f}"
)

print(
    f"Quantidade de features: "
    f"{len(FEATURES)}"
)


# ============================================================
# CONTADORES DA API
# ============================================================

estatisticas = {
    "requisicoes": 0,
    "eventos_validos": 0,
    "eventos_invalidos": 0,
    "normais": 0,
    "ataques": 0,
    "erros": 0,
}


# ============================================================
# VALIDACAO DO EVENTO
# ============================================================

def validar_evento(evento):

    if not isinstance(evento, dict):

        raise ValueError(
            "O corpo da requisicao precisa "
            "ser um objeto JSON."
        )

    valores = {}

    for feature in FEATURES:

        if feature not in evento:

            raise ValueError(
                f"Feature obrigatoria ausente: {feature}"
            )

        try:

            valor = float(
                evento[feature]
            )

        except (TypeError, ValueError):

            raise ValueError(
                f"Valor invalido para {feature}: "
                f"{evento[feature]}"
            )

        if not np.isfinite(valor):

            raise ValueError(
                f"Valor nao finito para {feature}"
            )

        # UNSW-NB15 utiliza valores nao negativos
        # para estas nove features.
        if valor < 0:

            raise ValueError(
                f"Valor negativo nao permitido "
                f"para {feature}"
            )

        valores[feature] = valor

    dataframe = pd.DataFrame(
        [valores],
        columns=FEATURES,
    )

    return dataframe


# ============================================================
# DETECTOR BINARIO
# ============================================================

def detectar_binario(dataframe):

    if hasattr(
        modelo_binario,
        "predict_proba",
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

            indice_ataque = classes.index(1)

        elif "1" in classes:

            indice_ataque = classes.index("1")

        else:

            raise ValueError(
                "Classe ATAQUE nao encontrada "
                "no modelo binario."
            )

        probabilidade = float(
            probabilidades[
                0,
                indice_ataque
            ]
        )

        classificacao = (
            1
            if probabilidade >= THRESHOLD
            else 0
        )

        return (
            classificacao,
            probabilidade,
        )

    predicao = modelo_binario.predict(
        dataframe
    )[0]

    classificacao = int(predicao)

    probabilidade = (
        1.0
        if classificacao == 1
        else 0.0
    )

    return (
        classificacao,
        probabilidade,
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
        "predict_proba",
    ):

        probabilidades = (
            modelo_multiclasse.predict_proba(
                dataframe
            )[0]
        )

        confianca = float(
            np.max(probabilidades)
        )

    return (
        categoria,
        confianca,
    )


# ============================================================
# SEVERIDADE
# ============================================================

def calcular_severidade(
    categoria,
    probabilidade_ataque,
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

    if probabilidade_ataque >= 0.90:
        return "ALTO"

    return "MEDIO"


# ============================================================
# PERSISTENCIA DOS ALERTAS
# ============================================================

def salvar_alerta(alerta):

    import json

    with open(
        ARQUIVO_ALERTAS_API,
        "a",
        encoding="utf-8",
    ) as arquivo:

        arquivo.write(
            json.dumps(
                alerta,
                ensure_ascii=False,
            )
        )

        arquivo.write("\n")


# ============================================================
# ENDPOINT RAIZ
# ============================================================

@app.route(
    "/",
    methods=["GET"],
)
def raiz():

    return jsonify(
        {
            "projeto":
                PROJETO,

            "aula":
                AULA,

            "api":
                VERSAO_API,

            "status":
                "online",

            "mensagem":
                "CyberSentinel-ML API",

            "endpoints": {
                "health":
                    "GET /health",

                "predict":
                    "POST /predict",

                "stats":
                    "GET /stats",
            },
        }
    ), 200


# ============================================================
# HEALTH CHECK
# ============================================================

@app.route(
    "/health",
    methods=["GET"],
)
def health():

    artefatos_ok = all(
        caminho.exists()
        for caminho in artefatos.values()
    )

    status = (
        "healthy"
        if artefatos_ok
        else "degraded"
    )

    codigo_http = (
        200
        if artefatos_ok
        else 503
    )

    return jsonify(
        {
            "projeto":
                PROJETO,

            "status":
                status,

            "timestamp":
                agora(),

            "modelo_binario":
                type(
                    modelo_binario
                ).__name__,

            "modelo_multiclasse":
                type(
                    modelo_multiclasse
                ).__name__,

            "threshold":
                THRESHOLD,

            "features":
                len(FEATURES),
        }
    ), codigo_http


# ============================================================
# ESTATISTICAS
# ============================================================

@app.route(
    "/stats",
    methods=["GET"],
)
def stats():

    return jsonify(
        {
            "projeto":
                PROJETO,

            "timestamp":
                agora(),

            "estatisticas":
                estatisticas,
        }
    ), 200


# ============================================================
# ENDPOINT PRINCIPAL DE PREDICAO
# ============================================================

@app.route(
    "/predict",
    methods=["POST"],
)
def predict():

    estatisticas["requisicoes"] += 1

    # ========================================================
    # VALIDANDO CONTENT-TYPE
    # ========================================================

    if not request.is_json:

        estatisticas[
            "eventos_invalidos"
        ] += 1

        return jsonify(
            {
                "status":
                    "erro",

                "erro":
                    "Content-Type precisa ser "
                    "application/json",
            }
        ), 415

    # ========================================================
    # RECEBENDO JSON
    # ========================================================

    try:

        evento = request.get_json(
            silent=False
        )

    except Exception:

        estatisticas[
            "eventos_invalidos"
        ] += 1

        return jsonify(
            {
                "status":
                    "erro",

                "erro":
                    "JSON invalido.",
            }
        ), 400

    # ========================================================
    # VALIDANDO SCHEMA
    # ========================================================

    try:

        dataframe = validar_evento(
            evento
        )

        estatisticas[
            "eventos_validos"
        ] += 1

    except ValueError as exc:

        estatisticas[
            "eventos_invalidos"
        ] += 1

        return jsonify(
            {
                "status":
                    "rejeitado",

                "erro":
                    str(exc),

                "timestamp":
                    agora(),
            }
        ), 400

    # ========================================================
    # EXECUTANDO MACHINE LEARNING
    # ========================================================

    try:

        (
            classificacao,
            probabilidade_ataque,
        ) = detectar_binario(
            dataframe
        )

        id_evento = str(
            evento.get(
                "id_evento",
                "SEM-ID",
            )
        )

        origem = str(
            evento.get(
                "origem",
                "API",
            )
        )

        # ====================================================
        # EVENTO NORMAL
        # ====================================================

        if classificacao == 0:

            estatisticas[
                "normais"
            ] += 1

            resposta = {
                "projeto":
                    PROJETO,

                "status":
                    "processado",

                "id_evento":
                    id_evento,

                "origem":
                    origem,

                "timestamp":
                    agora(),

                "classificacao":
                    "NORMAL",

                "probabilidade_ataque":
                    round(
                        probabilidade_ataque,
                        6,
                    ),

                "probabilidade_ataque_percentual":
                    round(
                        probabilidade_ataque
                        * 100,
                        2,
                    ),

                "threshold":
                    THRESHOLD,

                "categoria_ataque":
                    None,

                "confianca_categoria":
                    None,

                "severidade":
                    None,

                "alerta_soc":
                    False,
            }

            return jsonify(
                resposta
            ), 200

        # ====================================================
        # EVENTO ATAQUE
        # ====================================================

        estatisticas[
            "ataques"
        ] += 1

        (
            categoria,
            confianca_categoria,
        ) = detectar_categoria(
            dataframe
        )

        severidade = (
            calcular_severidade(
                categoria,
                probabilidade_ataque,
            )
        )

        alerta_id = (
            "API-ALT-"
            + datetime.now(
                timezone.utc
            ).strftime(
                "%Y%m%d%H%M%S%f"
            )
        )

        resposta = {
            "projeto":
                PROJETO,

            "status":
                "processado",

            "id_evento":
                id_evento,

            "origem":
                origem,

            "timestamp":
                agora(),

            "classificacao":
                "ATAQUE",

            "probabilidade_ataque":
                round(
                    probabilidade_ataque,
                    6,
                ),

            "probabilidade_ataque_percentual":
                round(
                    probabilidade_ataque
                    * 100,
                    2,
                ),

            "threshold":
                THRESHOLD,

            "categoria_ataque":
                categoria,

            "confianca_categoria":
                (
                    round(
                        confianca_categoria,
                        6,
                    )
                    if confianca_categoria
                    is not None
                    else None
                ),

            "confianca_categoria_percentual":
                (
                    round(
                        confianca_categoria
                        * 100,
                        2,
                    )
                    if confianca_categoria
                    is not None
                    else None
                ),

            "severidade":
                severidade,

            "alerta_soc":
                True,

            "alerta_id":
                alerta_id,
        }

        alerta = {
            **resposta,

            "features": {
                feature:
                    float(
                        evento[feature]
                    )

                for feature in FEATURES
            },
        }

        salvar_alerta(
            alerta
        )

        return jsonify(
            resposta
        ), 200

    except Exception as exc:

        estatisticas[
            "erros"
        ] += 1

        return jsonify(
            {
                "status":
                    "erro",

                "erro":
                    "Falha interna no "
                    "processamento ML.",

                "timestamp":
                    agora(),
            }
        ), 500


# ============================================================
# TRATAMENTO 404
# ============================================================

@app.errorhandler(404)
def pagina_nao_encontrada(_erro):

    return jsonify(
        {
            "status":
                "erro",

            "erro":
                "Endpoint nao encontrado.",

            "endpoints_validos": [
                "/",
                "/health",
                "/predict",
                "/stats",
            ],
        }
    ), 404


# ============================================================
# INICIALIZACAO
# ============================================================

if __name__ == "__main__":

    titulo(
        "VALIDACAO FINAL DA API"
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

        "Threshold configurado":
            0 <= THRESHOLD <= 1,
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
        f"Saude: "
        f"{saude:.2f}%"
    )

    if saude != 100:

        raise RuntimeError(
            "API nao passou nas validacoes."
        )

    titulo(
        "CYBERSENTINEL-ML API"
    )

    print("API pronta.")
    print()
    print("Endereco local:")
    print("http://127.0.0.1:5000")
    print()
    print("Health:")
    print("http://127.0.0.1:5000/health")
    print()
    print("Predicao:")
    print("POST http://127.0.0.1:5000/predict")
    print()
    print("Estatisticas:")
    print("http://127.0.0.1:5000/stats")
    print()
    print(
        "Pressione CTRL+C para encerrar."
    )

    linha()

    # IMPORTANTE:
    # localhost apenas.
    # Nao expomos esta API na rede nesta aula.
    # debug=False evita o debugger interativo.
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False,
    )