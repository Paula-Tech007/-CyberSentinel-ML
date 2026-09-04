# ============================================================
# CyberSentinel-ML
# AULA 23 - PIPELINE BINARIO + MULTICLASSE
# ============================================================
#
# OBJETIVO:
# Integrar o detector binario existente ao classificador
# multiclasse otimizado desenvolvido na Aula 22.
#
# FLUXO:
#
# EVENTO
#   |
#   v
# MODELO BINARIO
#   |
#   +---- NORMAL ----------------------> FINALIZA
#   |
#   v
# ATAQUE
#   |
#   v
# CLASSIFICADOR MULTICLASSE
#   |
#   v
# CATEGORIA DO ATAQUE
#   |
#   v
# ALERTA SOC
#
# IMPORTANTE:
# - Nenhum modelo sera treinado nesta aula.
# - Os modelos persistidos serao reutilizados.
# - O modelo binario da V1.0 nao sera sobrescrito.
# - O modelo multiclasse da Aula 22 nao sera sobrescrito.
#
# ============================================================


# ============================================================
# IMPORTACOES
# ============================================================

import sys
import json
from datetime import datetime
from pathlib import Path

import joblib
import numpy as np
import pandas as pd


# ============================================================
# CONFIGURACOES
# ============================================================

PROJETO = "CyberSentinel-ML"
AULA = 23
VERSAO = "Pipeline Binario + Multiclasse"

BASE_DIR = Path(__file__).resolve().parent

PASTA_MODELOS = BASE_DIR / "modelos"
PASTA_ALERTAS = BASE_DIR / "alertas"
PASTA_EVENTOS = BASE_DIR / "eventos"


# ============================================================
# MODELO BINARIO
# ============================================================

ARQUIVO_MODELO_BINARIO = (
    PASTA_MODELOS
    / "unsw_decision_tree.joblib"
)

ARQUIVO_CONFIG_BINARIO = (
    PASTA_MODELOS
    / "configuracao_modelo.joblib"
)


# ============================================================
# MODELO MULTICLASSE
# ============================================================

ARQUIVO_MODELO_MULTICLASSE = (
    PASTA_MODELOS
    / "unsw_attack_multiclass_otimizado.joblib"
)

ARQUIVO_CONFIG_MULTICLASSE = (
    PASTA_MODELOS
    / "configuracao_multiclasse_otimizada_aula_22.joblib"
)


# ============================================================
# ARQUIVOS DE SAIDA
# ============================================================

ARQUIVO_ALERTAS = (
    PASTA_ALERTAS
    / "alertas_pipeline_aula_23.json"
)

ARQUIVO_RELATORIO = (
    PASTA_ALERTAS
    / "relatorio_pipeline_aula_23.json"
)


# ============================================================
# FEATURES OFICIAIS
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


def aviso(texto):
    print(f"[AVISO] {texto}")


# ============================================================
# FUNCAO PARA CONVERTER TIPOS NUMPY PARA JSON
# ============================================================

def converter_json(valor):

    if isinstance(valor, np.integer):
        return int(valor)

    if isinstance(valor, np.floating):
        return float(valor)

    if isinstance(valor, np.ndarray):
        return valor.tolist()

    raise TypeError(
        f"Tipo nao serializavel: {type(valor)}"
    )


# ============================================================
# CABECALHO
# ============================================================

linha()
print("AULA 23 - PIPELINE BINARIO + MULTICLASSE")
print(PROJETO)
print(VERSAO)
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

PASTA_EVENTOS.mkdir(
    parents=True,
    exist_ok=True,
)

sucesso("Diretorio modelos pronto")
sucesso("Diretorio alertas pronto")
sucesso("Diretorio eventos pronto")


# ============================================================
# ETAPA 2 - VALIDANDO ARTEFATOS
# ============================================================

titulo("ETAPA 2 - VALIDANDO ARTEFATOS DE MACHINE LEARNING")


artefatos = {
    "Modelo binario":
        ARQUIVO_MODELO_BINARIO,

    "Configuracao binaria":
        ARQUIVO_CONFIG_BINARIO,

    "Modelo multiclasse":
        ARQUIVO_MODELO_MULTICLASSE,

    "Configuracao multiclasse":
        ARQUIVO_CONFIG_MULTICLASSE,
}


artefatos_ok = True


for nome, caminho in artefatos.items():

    if caminho.exists():

        sucesso(
            f"{nome}: "
            f"{caminho.relative_to(BASE_DIR)}"
        )

    else:

        erro(
            f"{nome} nao encontrado: "
            f"{caminho}"
        )

        artefatos_ok = False


if not artefatos_ok:

    print()
    erro(
        "Pipeline interrompido porque "
        "existem artefatos ausentes."
    )

    sys.exit(1)


# ============================================================
# ETAPA 3 - CARREGANDO MODELOS
# ============================================================

titulo("ETAPA 3 - CARREGANDO MODELOS")


try:

    modelo_binario = joblib.load(
        ARQUIVO_MODELO_BINARIO
    )

    config_binario = joblib.load(
        ARQUIVO_CONFIG_BINARIO
    )

    sucesso(
        "Modelo binario carregado"
    )

    sucesso(
        "Configuracao binaria carregada"
    )


except Exception as exc:

    erro(
        f"Falha ao carregar modelo binario: {exc}"
    )

    sys.exit(1)


try:

    modelo_multiclasse = joblib.load(
        ARQUIVO_MODELO_MULTICLASSE
    )

    config_multiclasse = joblib.load(
        ARQUIVO_CONFIG_MULTICLASSE
    )

    sucesso(
        "Modelo multiclasse carregado"
    )

    sucesso(
        "Configuracao multiclasse carregada"
    )


except Exception as exc:

    erro(
        f"Falha ao carregar modelo multiclasse: {exc}"
    )

    sys.exit(1)


print()
print(
    "Modelo binario:"
)

print(
    type(modelo_binario).__name__
)

print()

print(
    "Modelo multiclasse:"
)

print(
    type(modelo_multiclasse).__name__
)


# ============================================================
# ETAPA 4 - VALIDANDO FEATURES
# ============================================================

titulo("ETAPA 4 - VALIDANDO COMPATIBILIDADE DAS FEATURES")


features_binario = config_binario.get(
    "features",
    FEATURES,
)


features_multiclasse = config_multiclasse.get(
    "features",
    FEATURES,
)


if list(features_binario) != FEATURES:

    erro(
        "As features do modelo binario "
        "nao correspondem ao pipeline."
    )

    print()
    print(
        f"Esperado: {FEATURES}"
    )

    print(
        f"Encontrado: {features_binario}"
    )

    sys.exit(1)


sucesso(
    "Features do modelo binario compativeis"
)


if list(features_multiclasse) != FEATURES:

    erro(
        "As features do modelo multiclasse "
        "nao correspondem ao pipeline."
    )

    print()
    print(
        f"Esperado: {FEATURES}"
    )

    print(
        f"Encontrado: {features_multiclasse}"
    )

    sys.exit(1)


sucesso(
    "Features do modelo multiclasse compativeis"
)


# ============================================================
# ETAPA 5 - CONFIGURACAO DO DETECTOR
# ============================================================

titulo("ETAPA 5 - CONFIGURACAO DO PIPELINE")


threshold = config_binario.get(
    "threshold",
    0.5,
)


try:
    threshold = float(threshold)

except Exception:
    threshold = 0.5


print(
    f"Threshold binario: {threshold:.4f}"
)

print(
    f"Quantidade de features: {len(FEATURES)}"
)


categorias_multiclasse = (
    config_multiclasse.get(
        "categorias",
        []
    )
)


print(
    f"Categorias multiclasse: "
    f"{len(categorias_multiclasse)}"
)


if categorias_multiclasse:

    print()

    for numero, categoria in enumerate(
        categorias_multiclasse,
        start=1,
    ):

        print(
            f"{numero:02d} - {categoria}"
        )


# ============================================================
# ETAPA 6 - CRIANDO EVENTOS DE TESTE
# ============================================================

titulo("ETAPA 6 - PREPARANDO EVENTOS PARA O PIPELINE")


# ============================================================
# Os eventos abaixo sao somente exemplos locais para validar
# a integracao tecnica dos dois modelos.
#
# Eles nao representam trafego real de producao.
# ============================================================


eventos = [

    {
        "id_evento": "EVT-23-001",
        "spkts": 10,
        "dpkts": 8,
        "sbytes": 1200,
        "dbytes": 900,
        "rate": 25.0,
        "sttl": 64,
        "dttl": 64,
        "sload": 5000.0,
        "dload": 4000.0,
    },

    {
        "id_evento": "EVT-23-002",
        "spkts": 2,
        "dpkts": 0,
        "sbytes": 800,
        "dbytes": 0,
        "rate": 5000.0,
        "sttl": 254,
        "dttl": 0,
        "sload": 950000.0,
        "dload": 0.0,
    },

    {
        "id_evento": "EVT-23-003",
        "spkts": 6,
        "dpkts": 2,
        "sbytes": 3500,
        "dbytes": 250,
        "rate": 1500.0,
        "sttl": 254,
        "dttl": 64,
        "sload": 350000.0,
        "dload": 25000.0,
    },

]


sucesso(
    f"{len(eventos)} eventos preparados"
)


for evento in eventos:

    print(
        f"- {evento['id_evento']}"
    )


# ============================================================
# ETAPA 7 - FUNCAO PARA PREPARAR EVENTO
# ============================================================

def preparar_evento(evento):

    valores = {}


    for feature in FEATURES:

        if feature not in evento:

            raise ValueError(
                f"Feature ausente: {feature}"
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
                f"Valor invalido para {feature}: "
                f"{evento[feature]}"
            )


        if not np.isfinite(valor):

            raise ValueError(
                f"Valor nao finito para {feature}"
            )


        valores[feature] = valor


    dataframe = pd.DataFrame(
        [valores],
        columns=FEATURES,
    )


    return dataframe


# ============================================================
# ETAPA 8 - FUNCAO DETECTOR BINARIO
# ============================================================

def detectar_binario(dataframe):

    # ========================================================
    # Preferimos predict_proba porque o modelo da V1.0 possui
    # threshold orientado a seguranca.
    # ========================================================

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
                "Classe de ataque 1 nao encontrada "
                "no modelo binario."
            )


        probabilidade_ataque = float(
            probabilidades[
                0,
                indice_ataque
            ]
        )


        classificacao = (
            1
            if probabilidade_ataque >= threshold
            else 0
        )


        return (
            classificacao,
            probabilidade_ataque,
        )


    # ========================================================
    # FALLBACK
    # ========================================================

    predicao = (
        modelo_binario.predict(
            dataframe
        )[0]
    )


    classificacao = int(
        predicao
    )


    probabilidade_ataque = (
        1.0
        if classificacao == 1
        else 0.0
    )


    return (
        classificacao,
        probabilidade_ataque,
    )


# ============================================================
# ETAPA 9 - FUNCAO MULTICLASSE
# ============================================================

def detectar_categoria(dataframe):

    categoria = (
        modelo_multiclasse.predict(
            dataframe
        )[0]
    )


    categoria = str(
        categoria
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
# ETAPA 10 - FUNCAO DE SEVERIDADE
# ============================================================

def calcular_severidade(
    categoria,
    probabilidade_ataque,
):

    # ========================================================
    # Mapeamento demonstrativo para o laboratorio.
    # Nao representa uma politica universal de SOC.
    # ========================================================

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
# ETAPA 11 - PROCESSANDO PIPELINE
# ============================================================

titulo("ETAPA 11 - EXECUTANDO PIPELINE INTEGRADO")


resultados = []
alertas_soc = []

eventos_normais = 0
eventos_ataque = 0
eventos_erro = 0


for numero, evento in enumerate(
    eventos,
    start=1,
):

    print()
    print("-" * 72)

    print(
        f"PROCESSANDO EVENTO "
        f"{numero}/{len(eventos)}"
    )

    print("-" * 72)


    id_evento = evento.get(
        "id_evento",
        f"EVT-{numero}",
    )


    print(
        f"ID: {id_evento}"
    )


    try:

        # ====================================================
        # PREPARACAO
        # ====================================================

        dataframe = preparar_evento(
            evento
        )


        sucesso(
            "Evento validado"
        )


        # ====================================================
        # DETECCAO BINARIA
        # ====================================================

        (
            classificacao,
            probabilidade_ataque,
        ) = detectar_binario(
            dataframe
        )


        print(
            f"Probabilidade de ataque: "
            f"{probabilidade_ataque * 100:.2f}%"
        )


        # ====================================================
        # NORMAL
        # ====================================================

        if classificacao == 0:

            eventos_normais += 1


            resultado = {

                "id_evento":
                    id_evento,

                "timestamp":
                    datetime.now().isoformat(),

                "classificacao_binaria":
                    "NORMAL",

                "probabilidade_ataque":
                    round(
                        probabilidade_ataque,
                        6,
                    ),

                "categoria_ataque":
                    None,

                "confianca_categoria":
                    None,

                "alerta_soc":
                    False,
            }


            resultados.append(
                resultado
            )


            sucesso(
                "Resultado: NORMAL"
            )

            print(
                "Pipeline finalizado sem alerta SOC."
            )

            continue


        # ====================================================
        # ATAQUE
        # ====================================================

        eventos_ataque += 1


        sucesso(
            "Resultado binario: ATAQUE"
        )


        # ====================================================
        # MULTICLASSE
        # ====================================================

        (
            categoria,
            confianca_categoria,
        ) = detectar_categoria(
            dataframe
        )


        print(
            f"Categoria prevista: "
            f"{categoria}"
        )


        if confianca_categoria is not None:

            print(
                f"Confianca da categoria: "
                f"{confianca_categoria * 100:.2f}%"
            )


        # ====================================================
        # SEVERIDADE
        # ====================================================

        severidade = calcular_severidade(
            categoria,
            probabilidade_ataque,
        )


        print(
            f"Severidade: "
            f"{severidade}"
        )


        # ====================================================
        # ALERTA
        # ====================================================

        alerta_id = (
            f"ALT-23-"
            f"{len(alertas_soc) + 1:03d}"
        )


        alerta = {

            "alerta_id":
                alerta_id,

            "id_evento":
                id_evento,

            "timestamp":
                datetime.now().isoformat(),

            "origem":
                "CyberSentinel-ML",

            "tipo":
                "DETECCAO_ML",

            "classificacao_binaria":
                "ATAQUE",

            "probabilidade_ataque":
                round(
                    probabilidade_ataque,
                    6,
                ),

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

            "severidade":
                severidade,

            "status":
                "NOVO",

            "modelo_binario":
                type(
                    modelo_binario
                ).__name__,

            "modelo_multiclasse":
                type(
                    modelo_multiclasse
                ).__name__,

            "features":
                {
                    feature:
                        evento[feature]

                    for feature in FEATURES
                },
        }


        alertas_soc.append(
            alerta
        )


        resultado = {

            "id_evento":
                id_evento,

            "timestamp":
                datetime.now().isoformat(),

            "classificacao_binaria":
                "ATAQUE",

            "probabilidade_ataque":
                round(
                    probabilidade_ataque,
                    6,
                ),

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

            "severidade":
                severidade,

            "alerta_soc":
                True,

            "alerta_id":
                alerta_id,
        }


        resultados.append(
            resultado
        )


        sucesso(
            f"Alerta SOC criado: "
            f"{alerta_id}"
        )


    except Exception as exc:

        eventos_erro += 1


        erro(
            f"Falha ao processar "
            f"{id_evento}: {exc}"
        )


        resultados.append(
            {
                "id_evento":
                    id_evento,

                "timestamp":
                    datetime.now().isoformat(),

                "status":
                    "ERRO",

                "erro":
                    str(exc),
            }
        )


# ============================================================
# ETAPA 12 - SALVANDO ALERTAS
# ============================================================

titulo("ETAPA 12 - SALVANDO ALERTAS SOC")


try:

    with open(
        ARQUIVO_ALERTAS,
        "w",
        encoding="utf-8",
    ) as arquivo:

        json.dump(
            alertas_soc,
            arquivo,
            indent=4,
            ensure_ascii=False,
            default=converter_json,
        )


    sucesso(
        "Alertas SOC salvos"
    )


    print(
        f"Arquivo: "
        f"{ARQUIVO_ALERTAS.relative_to(BASE_DIR)}"
    )


except Exception as exc:

    erro(
        f"Falha ao salvar alertas: {exc}"
    )

    sys.exit(1)


# ============================================================
# ETAPA 13 - RESUMO DOS ALERTAS
# ============================================================

titulo("ETAPA 13 - RESUMO DOS ALERTAS")


print(
    f"Alertas gerados: "
    f"{len(alertas_soc)}"
)


if alertas_soc:

    print()

    for alerta in alertas_soc:

        print("-" * 72)

        print(
            f"Alerta: "
            f"{alerta['alerta_id']}"
        )

        print(
            f"Evento: "
            f"{alerta['id_evento']}"
        )

        print(
            f"Categoria: "
            f"{alerta['categoria_ataque']}"
        )

        print(
            f"Severidade: "
            f"{alerta['severidade']}"
        )

        print(
            f"Probabilidade ataque: "
            f"{alerta['probabilidade_ataque'] * 100:.2f}%"
        )


        if (
            alerta[
                "confianca_categoria"
            ]
            is not None
        ):

            print(
                f"Confianca categoria: "
                f"{alerta['confianca_categoria'] * 100:.2f}%"
            )


else:

    aviso(
        "Nenhum alerta foi gerado "
        "pelos eventos de teste."
    )


# ============================================================
# ETAPA 14 - RELATORIO DO PIPELINE
# ============================================================

titulo("ETAPA 14 - GERANDO RELATORIO DO PIPELINE")


relatorio = {

    "projeto":
        PROJETO,

    "aula":
        AULA,

    "versao":
        VERSAO,

    "timestamp":
        datetime.now().isoformat(),

    "arquitetura": (
        "EVENTO -> MODELO BINARIO -> "
        "NORMAL/ATAQUE -> "
        "CLASSIFICADOR MULTICLASSE -> "
        "CATEGORIA -> ALERTA SOC"
    ),

    "modelo_binario": {

        "arquivo":
            str(
                ARQUIVO_MODELO_BINARIO.relative_to(
                    BASE_DIR
                )
            ),

        "algoritmo":
            type(
                modelo_binario
            ).__name__,

        "threshold":
            threshold,
    },

    "modelo_multiclasse": {

        "arquivo":
            str(
                ARQUIVO_MODELO_MULTICLASSE.relative_to(
                    BASE_DIR
                )
            ),

        "algoritmo":
            type(
                modelo_multiclasse
            ).__name__,

        "quantidade_categorias":
            len(
                categorias_multiclasse
            ),

        "categorias":
            categorias_multiclasse,
    },

    "features":
        FEATURES,

    "estatisticas": {

        "eventos_processados":
            len(eventos),

        "eventos_normais":
            eventos_normais,

        "eventos_ataque":
            eventos_ataque,

        "eventos_erro":
            eventos_erro,

        "alertas_gerados":
            len(alertas_soc),
    },

    "resultados":
        resultados,
}


try:

    with open(
        ARQUIVO_RELATORIO,
        "w",
        encoding="utf-8",
    ) as arquivo:

        json.dump(
            relatorio,
            arquivo,
            indent=4,
            ensure_ascii=False,
            default=converter_json,
        )


    sucesso(
        "Relatorio do pipeline salvo"
    )


    print(
        f"Arquivo: "
        f"{ARQUIVO_RELATORIO.relative_to(BASE_DIR)}"
    )


except Exception as exc:

    erro(
        f"Falha ao salvar relatorio: {exc}"
    )

    sys.exit(1)


# ============================================================
# ETAPA 15 - VALIDACAO FINAL
# ============================================================

titulo("ETAPA 15 - VALIDACAO FINAL")


validacoes = {

    "Modelo binario encontrado":
        ARQUIVO_MODELO_BINARIO.exists(),

    "Configuracao binaria encontrada":
        ARQUIVO_CONFIG_BINARIO.exists(),

    "Modelo multiclasse encontrado":
        ARQUIVO_MODELO_MULTICLASSE.exists(),

    "Configuracao multiclasse encontrada":
        ARQUIVO_CONFIG_MULTICLASSE.exists(),

    "9 features validadas":
        len(FEATURES) == 9,

    "Eventos processados":
        len(resultados) == len(eventos),

    "Nenhum erro no pipeline":
        eventos_erro == 0,

    "Arquivo de alertas gerado":
        ARQUIVO_ALERTAS.exists(),

    "Relatorio gerado":
        ARQUIVO_RELATORIO.exists(),
}


validacoes_ok = 0


for nome, resultado in validacoes.items():

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


# ============================================================
# ETAPA 16 - RESUMO FINAL
# ============================================================

titulo("RESUMO FINAL DA AULA 23")


print(
    f"Eventos processados: "
    f"{len(eventos)}"
)

print(
    f"Eventos NORMAL: "
    f"{eventos_normais}"
)

print(
    f"Eventos ATAQUE: "
    f"{eventos_ataque}"
)

print(
    f"Alertas SOC: "
    f"{len(alertas_soc)}"
)

print(
    f"Erros: "
    f"{eventos_erro}"
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


if saude == 100:

    status_final = (
        "AULA 23 CONCLUIDA"
    )

else:

    status_final = (
        "AULA 23 COM AJUSTES"
    )


print(
    f"Status: "
    f"{status_final}"
)


# ============================================================
# ARQUITETURA FINAL
# ============================================================

titulo("ARQUITETURA INTEGRADA")


print("EVENTO")
print("  |")
print("  v")
print("DETECTOR BINARIO")
print("  |")
print("  +---- NORMAL -----------------> FINALIZA")
print("  |")
print("  v")
print("ATAQUE")
print("  |")
print("  v")
print("CLASSIFICADOR MULTICLASSE")
print("  |")
print("  v")
print("CATEGORIA DO ATAQUE")
print("  |")
print("  v")
print("SEVERIDADE")
print("  |")
print("  v")
print("ALERTA SOC")


# ============================================================
# FINAL
# ============================================================

titulo("CYBERSENTINEL-ML")

print(
    "AULA 23 - "
    "PIPELINE BINARIO + MULTICLASSE"
)

print(status_final)

linha()