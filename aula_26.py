# ============================================================
# CyberSentinel-ML
# AULA 26 - API BATCH / PROCESSAMENTO EM LOTE
#
# Fluxo:
#
# HTTP POST
#     |
#     v
# LISTA DE EVENTOS
#     |
#     v
# VALIDACAO INDIVIDUAL
#     |
#     v
# DETECTOR BINARIO
#     |
#     +---- NORMAL
#     |
#     v
# ATAQUE
#     |
#     v
# CLASSIFICADOR MULTICLASSE
#     |
#     v
# CATEGORIA + SEVERIDADE
#     |
#     v
# ALERTA SOC
#     |
#     v
# RESPOSTA BATCH
#
# ============================================================

import json
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
AULA = 26
VERSAO_API = "1.1"
LIMITE_BATCH = 100

BASE_DIR = Path(__file__).resolve().parent

PASTA_MODELOS = BASE_DIR / "modelos"
PASTA_ALERTAS = BASE_DIR / "alertas"

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

ARQUIVO_ALERTAS = (
    PASTA_ALERTAS /
    "alertas_api_batch_aula_26.jsonl"
)


# ============================================================
# FEATURES
# ============================================================

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
# FUNCOES AUXILIARES
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
# FLASK
# ============================================================

app = Flask(__name__)


# ============================================================
# CABECALHO
# ============================================================

linha()
print("AULA 26 - API BATCH / PROCESSAMENTO EM LOTE")
print(PROJETO)
print(f"API v{VERSAO_API}")
linha()


# ============================================================
# ETAPA 1 - DIRETORIOS
# ============================================================

titulo(
    "ETAPA 1 - PREPARANDO DIRETORIOS"
)

PASTA_MODELOS.mkdir(
    parents=True,
    exist_ok=True,
)

PASTA_ALERTAS.mkdir(
    parents=True,
    exist_ok=True,
)

sucesso(
    "Diretorio modelos pronto"
)

sucesso(
    "Diretorio alertas pronto"
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
    "Modelo binario: "
    f"{type(modelo_binario).__name__}"
)

print(
    "Modelo multiclasse: "
    f"{type(modelo_multiclasse).__name__}"
)


# ============================================================
# ETAPA 4 - VALIDANDO CONFIGURACOES
# ============================================================

titulo(
    "ETAPA 4 - VALIDANDO CONFIGURACOES"
)

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
        "incompativeis."
    )


if features_multiclasse != FEATURES:

    raise ValueError(
        "Features do modelo multiclasse "
        "incompativeis."
    )


sucesso(
    "Features binarias compativeis"
)

sucesso(
    "Features multiclasse compativeis"
)


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
    f"Threshold: "
    f"{THRESHOLD:.4f}"
)

print(
    f"Features: "
    f"{len(FEATURES)}"
)

print(
    f"Limite por batch: "
    f"{LIMITE_BATCH}"
)


# ============================================================
# ESTATISTICAS
# ============================================================

estatisticas = {

    "batches_recebidos": 0,

    "eventos_recebidos": 0,

    "eventos_validos": 0,

    "eventos_invalidos": 0,

    "normais": 0,

    "ataques": 0,

    "alertas": 0,

    "erros_ml": 0,
}


# ============================================================
# VALIDACAO
# ============================================================

def validar_evento(evento):

    if not isinstance(
        evento,
        dict,
    ):

        raise ValueError(
            "Evento precisa ser "
            "um objeto JSON."
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
            ValueError,
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


    return pd.DataFrame(
        [valores],
        columns=FEATURES,
    )


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

            indice_ataque = (
                classes.index(1)
            )

        elif "1" in classes:

            indice_ataque = (
                classes.index("1")
            )

        else:

            raise ValueError(
                "Classe ATAQUE nao "
                "encontrada no modelo."
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


    predicao = (
        modelo_binario.predict(
            dataframe
        )[0]
    )


    classificacao = int(
        predicao
    )


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
        "predict_proba",
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
        confianca,
    )


# ============================================================
# SEVERIDADE
# ============================================================

def calcular_severidade(
    categoria,
    probabilidade,
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
# SALVAR ALERTA
# ============================================================

def salvar_alerta(alerta):

    with open(
        ARQUIVO_ALERTAS,
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
# PROCESSAMENTO INDIVIDUAL
# ============================================================

def processar_evento(
    evento,
    indice,
):

    id_evento = str(
        evento.get(
            "id_evento",
            f"BATCH-AUTO-{indice:04d}",
        )
        if isinstance(evento, dict)
        else f"BATCH-INVALIDO-{indice:04d}"
    )


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


        return {

            "id_evento":
                id_evento,

            "status":
                "REJEITADO",

            "erro":
                str(exc),

            "timestamp":
                agora(),
        }


    try:

        (
            classificacao,
            probabilidade,
        ) = detectar_binario(
            dataframe
        )


        # ====================================================
        # NORMAL
        # ====================================================

        if classificacao == 0:

            estatisticas[
                "normais"
            ] += 1


            return {

                "id_evento":
                    id_evento,

                "status":
                    "PROCESSADO",

                "classificacao":
                    "NORMAL",

                "probabilidade_ataque":
                    round(
                        probabilidade,
                        6,
                    ),

                "probabilidade_ataque_percentual":
                    round(
                        probabilidade * 100,
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

                "timestamp":
                    agora(),
            }


        # ====================================================
        # ATAQUE
        # ====================================================

        estatisticas[
            "ataques"
        ] += 1


        (
            categoria,
            confianca,
        ) = detectar_categoria(
            dataframe
        )


        severidade = calcular_severidade(
            categoria,
            probabilidade,
        )


        alerta_id = (
            "BATCH-ALT-"
            + datetime.now(
                timezone.utc
            ).strftime(
                "%Y%m%d%H%M%S%f"
            )
        )


        resultado = {

            "id_evento":
                id_evento,

            "status":
                "PROCESSADO",

            "classificacao":
                "ATAQUE",

            "probabilidade_ataque":
                round(
                    probabilidade,
                    6,
                ),

            "probabilidade_ataque_percentual":
                round(
                    probabilidade * 100,
                    2,
                ),

            "threshold":
                THRESHOLD,

            "categoria_ataque":
                categoria,

            "confianca_categoria":
                (
                    round(
                        confianca,
                        6,
                    )
                    if confianca is not None
                    else None
                ),

            "confianca_categoria_percentual":
                (
                    round(
                        confianca * 100,
                        2,
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

            "timestamp":
                agora(),
        }


        alerta = {

            **resultado,

            "origem":
                str(
                    evento.get(
                        "origem",
                        "BATCH_API",
                    )
                ),

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


        estatisticas[
            "alertas"
        ] += 1


        return resultado


    except Exception:

        estatisticas[
            "erros_ml"
        ] += 1


        return {

            "id_evento":
                id_evento,

            "status":
                "ERRO_ML",

            "erro":
                "Falha interna no "
                "processamento ML.",

            "timestamp":
                agora(),
        }


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

            "endpoints": {

                "health":
                    "GET /health",

                "predict_batch":
                    "POST /predict/batch",

                "stats":
                    "GET /stats",
            },

            "limite_batch":
                LIMITE_BATCH,
        }
    ), 200


# ============================================================
# HEALTH
# ============================================================

@app.route(
    "/health",
    methods=["GET"],
)
def health():

    return jsonify(
        {
            "projeto":
                PROJETO,

            "status":
                "healthy",

            "api":
                VERSAO_API,

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

            "limite_batch":
                LIMITE_BATCH,

            "timestamp":
                agora(),
        }
    ), 200


# ============================================================
# STATS
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

            "api":
                VERSAO_API,

            "estatisticas":
                estatisticas,

            "timestamp":
                agora(),
        }
    ), 200


# ============================================================
# ENDPOINT BATCH
# ============================================================

@app.route(
    "/predict/batch",
    methods=["POST"],
)
def predict_batch():

    estatisticas[
        "batches_recebidos"
    ] += 1


    # ========================================================
    # CONTENT TYPE
    # ========================================================

    if not request.is_json:

        return jsonify(
            {
                "status":
                    "ERRO",

                "erro":
                    "Content-Type precisa "
                    "ser application/json.",
            }
        ), 415


    # ========================================================
    # JSON
    # ========================================================

    try:

        corpo = request.get_json(
            silent=False
        )

    except Exception:

        return jsonify(
            {
                "status":
                    "ERRO",

                "erro":
                    "JSON invalido.",
            }
        ), 400


    # ========================================================
    # FORMATO ACEITO
    #
    # {
    #     "eventos": [...]
    # }
    #
    # ou diretamente:
    #
    # [...]
    # ========================================================

    if isinstance(
        corpo,
        dict,
    ):

        eventos = corpo.get(
            "eventos"
        )

    elif isinstance(
        corpo,
        list,
    ):

        eventos = corpo

    else:

        eventos = None


    if not isinstance(
        eventos,
        list,
    ):

        return jsonify(
            {
                "status":
                    "ERRO",

                "erro":
                    "Envie uma lista de "
                    "eventos ou um objeto "
                    "com a chave 'eventos'.",
            }
        ), 400


    if len(eventos) == 0:

        return jsonify(
            {
                "status":
                    "ERRO",

                "erro":
                    "O batch esta vazio.",
            }
        ), 400


    if len(eventos) > LIMITE_BATCH:

        return jsonify(
            {
                "status":
                    "ERRO",

                "erro":
                    "Limite maximo do "
                    f"batch: {LIMITE_BATCH}.",

                "recebidos":
                    len(eventos),
            }
        ), 413


    estatisticas[
        "eventos_recebidos"
    ] += len(eventos)


    # ========================================================
    # PROCESSAMENTO
    # ========================================================

    resultados = []


    for indice, evento in enumerate(
        eventos,
        start=1,
    ):

        resultado = processar_evento(
            evento,
            indice,
        )

        resultados.append(
            resultado
        )


    # ========================================================
    # RESUMO DESTE BATCH
    # ========================================================

    processados = sum(
        1
        for resultado in resultados
        if resultado.get("status")
        == "PROCESSADO"
    )


    rejeitados = sum(
        1
        for resultado in resultados
        if resultado.get("status")
        == "REJEITADO"
    )


    erros_ml = sum(
        1
        for resultado in resultados
        if resultado.get("status")
        == "ERRO_ML"
    )


    normais = sum(
        1
        for resultado in resultados
        if resultado.get(
            "classificacao"
        ) == "NORMAL"
    )


    ataques = sum(
        1
        for resultado in resultados
        if resultado.get(
            "classificacao"
        ) == "ATAQUE"
    )


    alertas = sum(
        1
        for resultado in resultados
        if resultado.get(
            "alerta_soc"
        ) is True
    )


    return jsonify(
        {
            "projeto":
                PROJETO,

            "api":
                VERSAO_API,

            "status":
                "PROCESSADO",

            "timestamp":
                agora(),

            "resumo": {

                "recebidos":
                    len(eventos),

                "processados":
                    processados,

                "rejeitados":
                    rejeitados,

                "erros_ml":
                    erros_ml,

                "normais":
                    normais,

                "ataques":
                    ataques,

                "alertas":
                    alertas,
            },

            "resultados":
                resultados,
        }
    ), 200


# ============================================================
# 404
# ============================================================

@app.errorhandler(404)
def nao_encontrado(_erro):

    return jsonify(
        {
            "status":
                "ERRO",

            "erro":
                "Endpoint nao encontrado.",

            "endpoints": [
                "/",
                "/health",
                "/predict/batch",
                "/stats",
            ],
        }
    ), 404


# ============================================================
# INICIALIZACAO
# ============================================================

if __name__ == "__main__":

    titulo(
        "VALIDACAO FINAL DA AULA 26"
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

        "Limite batch configurado":
            LIMITE_BATCH > 0,
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
        f"Saude: "
        f"{saude:.2f}%"
    )


    if saude != 100:

        raise RuntimeError(
            "Aula 26 nao passou "
            "nas validacoes."
        )


    titulo(
        "CYBERSENTINEL-ML API BATCH"
    )


    print(
        "API Batch pronta."
    )

    print()

    print(
        "Endereco:"
    )

    print(
        "http://127.0.0.1:5001"
    )

    print()

    print(
        "Health:"
    )

    print(
        "GET http://127.0.0.1:5001/health"
    )

    print()

    print(
        "Batch:"
    )

    print(
        "POST http://127.0.0.1:5001/predict/batch"
    )

    print()

    print(
        "Stats:"
    )

    print(
        "GET http://127.0.0.1:5001/stats"
    )

    print()

    print(
        "Limite por batch: "
        f"{LIMITE_BATCH} eventos"
    )

    print()

    print(
        "Pressione CTRL+C para encerrar."
    )

    linha()


    # ========================================================
    # SEGURANCA DO LABORATORIO
    #
    # Somente localhost.
    # Nao expor na rede.
    # Debug desabilitado.
    # ========================================================

    app.run(
        host="127.0.0.1",
        port=5001,
        debug=False,
    )