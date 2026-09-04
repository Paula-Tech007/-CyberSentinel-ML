# ============================================================
# CyberSentinel-ML
# AULA 24 - INGESTAO DE EVENTOS EXTERNOS
# JSON / JSONL -> ML -> ALERTA SOC
# ============================================================

import sys
import json
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd


# ============================================================
# CONFIGURACOES
# ============================================================

PROJETO = "CyberSentinel-ML"
AULA = 24
VERSAO = "Ingestao de Eventos Externos JSON/JSONL"

BASE_DIR = Path(__file__).resolve().parent

PASTA_MODELOS = BASE_DIR / "modelos"
PASTA_ALERTAS = BASE_DIR / "alertas"
PASTA_EVENTOS = BASE_DIR / "eventos"

ARQUIVO_MODELO_BINARIO = (
    PASTA_MODELOS / "unsw_decision_tree.joblib"
)

ARQUIVO_CONFIG_BINARIO = (
    PASTA_MODELOS / "configuracao_modelo.joblib"
)

ARQUIVO_MODELO_MULTICLASSE = (
    PASTA_MODELOS / "unsw_attack_multiclass_otimizado.joblib"
)

ARQUIVO_CONFIG_MULTICLASSE = (
    PASTA_MODELOS
    / "configuracao_multiclasse_otimizada_aula_22.joblib"
)

ARQUIVO_EVENTOS_JSON = (
    PASTA_EVENTOS / "eventos_aula_24.json"
)

ARQUIVO_EVENTOS_JSONL = (
    PASTA_EVENTOS / "eventos_aula_24.jsonl"
)

ARQUIVO_ALERTAS = (
    PASTA_ALERTAS / "alertas_pipeline_aula_24.json"
)

ARQUIVO_REJEITADOS = (
    PASTA_ALERTAS / "eventos_rejeitados_aula_24.json"
)

ARQUIVO_RELATORIO = (
    PASTA_ALERTAS / "relatorio_pipeline_aula_24.json"
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


def agora():
    return datetime.now(timezone.utc).isoformat()


# ============================================================
# SERIALIZACAO JSON
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
print("AULA 24 - INGESTAO DE EVENTOS EXTERNOS")
print(PROJETO)
print(VERSAO)
linha()


# ============================================================
# ETAPA 1 - DIRETORIOS
# ============================================================

titulo("ETAPA 1 - PREPARANDO DIRETORIOS")

for pasta in [
    PASTA_MODELOS,
    PASTA_ALERTAS,
    PASTA_EVENTOS,
]:
    pasta.mkdir(
        parents=True,
        exist_ok=True,
    )

sucesso("Diretorio modelos pronto")
sucesso("Diretorio alertas pronto")
sucesso("Diretorio eventos pronto")


# ============================================================
# ETAPA 2 - VALIDANDO MODELOS
# ============================================================

titulo("ETAPA 2 - VALIDANDO ARTEFATOS ML")

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

for nome, caminho in artefatos.items():

    if not caminho.exists():

        erro(
            f"{nome} nao encontrado: {caminho}"
        )

        sys.exit(1)

    sucesso(
        f"{nome}: "
        f"{caminho.relative_to(BASE_DIR)}"
    )


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

    modelo_multiclasse = joblib.load(
        ARQUIVO_MODELO_MULTICLASSE
    )

    config_multiclasse = joblib.load(
        ARQUIVO_CONFIG_MULTICLASSE
    )

except Exception as exc:

    erro(
        f"Falha ao carregar modelos: {exc}"
    )

    sys.exit(1)


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
# ETAPA 4 - CONFIGURACAO
# ============================================================

titulo("ETAPA 4 - VALIDANDO CONFIGURACAO")

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

    erro(
        "Features do modelo binario "
        "nao sao compativeis."
    )

    sys.exit(1)


if features_multiclasse != FEATURES:

    erro(
        "Features do modelo multiclasse "
        "nao sao compativeis."
    )

    sys.exit(1)


sucesso("Features do modelo binario compativeis")
sucesso("Features do modelo multiclasse compativeis")


try:

    threshold = float(
        config_binario.get(
            "threshold",
            0.5,
        )
    )

except Exception:

    threshold = 0.5


categorias = config_multiclasse.get(
    "categorias",
    [],
)


print()
print(
    f"Threshold binario: "
    f"{threshold:.4f}"
)

print(
    f"Quantidade de features: "
    f"{len(FEATURES)}"
)

print(
    f"Categorias multiclasse: "
    f"{len(categorias)}"
)


# ============================================================
# ETAPA 5 - CRIANDO ARQUIVO EXTERNO DE EXEMPLO
# ============================================================

titulo(
    "ETAPA 5 - PREPARANDO FONTE EXTERNA DE EVENTOS"
)


# O arquivo so sera criado automaticamente se ainda nao existir.
# Assim, depois voce pode substituir o conteudo por eventos externos
# sem o programa sobrescrever seus dados.

if (
    not ARQUIVO_EVENTOS_JSON.exists()
    and
    not ARQUIVO_EVENTOS_JSONL.exists()
):

    eventos_exemplo = [

        {
            "id_evento": "EXT-24-001",
            "origem": "LAB_JSON",
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
            "id_evento": "EXT-24-002",
            "origem": "LAB_JSON",
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
            "id_evento": "EXT-24-003",
            "origem": "LAB_JSON",
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

        # Evento propositalmente invalido.
        # Serve para validar a rejeicao de schema.
        {
            "id_evento": "EXT-24-004",
            "origem": "LAB_JSON",
            "spkts": 4,
            "dpkts": 2,
            "sbytes": 1000,
        },
    ]


    try:

        with open(
            ARQUIVO_EVENTOS_JSON,
            "w",
            encoding="utf-8",
        ) as arquivo:

            json.dump(
                eventos_exemplo,
                arquivo,
                indent=4,
                ensure_ascii=False,
            )

        sucesso(
            "Arquivo externo de exemplo criado"
        )

        print(
            f"Arquivo: "
            f"{ARQUIVO_EVENTOS_JSON.relative_to(BASE_DIR)}"
        )

    except Exception as exc:

        erro(
            f"Falha ao criar arquivo de exemplo: {exc}"
        )

        sys.exit(1)

else:

    sucesso(
        "Fonte externa de eventos ja existente"
    )


# ============================================================
# ETAPA 6 - LEITURA JSON
# ============================================================

def carregar_json(caminho):

    with open(
        caminho,
        "r",
        encoding="utf-8",
    ) as arquivo:

        dados = json.load(
            arquivo
        )


    if isinstance(dados, dict):

        if (
            "eventos" in dados
            and
            isinstance(
                dados["eventos"],
                list,
            )
        ):

            dados = dados["eventos"]

        else:

            dados = [dados]


    if not isinstance(
        dados,
        list,
    ):

        raise ValueError(
            "JSON precisa conter um evento "
            "ou uma lista de eventos."
        )


    return dados


# ============================================================
# ETAPA 7 - LEITURA JSONL
# ============================================================

def carregar_jsonl(caminho):

    eventos = []


    with open(
        caminho,
        "r",
        encoding="utf-8",
    ) as arquivo:

        for numero_linha, linha_json in enumerate(
            arquivo,
            start=1,
        ):

            linha_json = linha_json.strip()


            if not linha_json:
                continue


            try:

                evento = json.loads(
                    linha_json
                )

            except json.JSONDecodeError as exc:

                raise ValueError(
                    f"JSON invalido na linha "
                    f"{numero_linha}: {exc}"
                )


            if not isinstance(
                evento,
                dict,
            ):

                raise ValueError(
                    f"Linha {numero_linha} "
                    f"nao contem objeto JSON."
                )


            eventos.append(
                evento
            )


    return eventos


# ============================================================
# ETAPA 8 - LOCALIZANDO FONTE
# ============================================================

titulo(
    "ETAPA 8 - CARREGANDO EVENTOS EXTERNOS"
)


try:

    if ARQUIVO_EVENTOS_JSON.exists():

        arquivo_entrada = (
            ARQUIVO_EVENTOS_JSON
        )

        formato_entrada = "JSON"

        eventos = carregar_json(
            arquivo_entrada
        )


    elif ARQUIVO_EVENTOS_JSONL.exists():

        arquivo_entrada = (
            ARQUIVO_EVENTOS_JSONL
        )

        formato_entrada = "JSONL"

        eventos = carregar_jsonl(
            arquivo_entrada
        )


    else:

        erro(
            "Nenhum arquivo de eventos encontrado."
        )

        sys.exit(1)


except Exception as exc:

    erro(
        f"Falha ao carregar eventos: {exc}"
    )

    sys.exit(1)


sucesso(
    "Eventos externos carregados"
)

print()
print(
    f"Fonte: "
    f"{arquivo_entrada.relative_to(BASE_DIR)}"
)

print(
    f"Formato: "
    f"{formato_entrada}"
)

print(
    f"Eventos recebidos: "
    f"{len(eventos)}"
)


# ============================================================
# ETAPA 9 - VALIDACAO DO EVENTO
# ============================================================

def validar_evento(
    evento,
    indice,
):

    if not isinstance(
        evento,
        dict,
    ):

        raise ValueError(
            "Evento precisa ser um objeto JSON."
        )


    id_evento = evento.get(
        "id_evento"
    )


    if not id_evento:

        id_evento = (
            f"EXT-24-AUTO-{indice:04d}"
        )


    valores = {}


    for feature in FEATURES:

        if feature not in evento:

            raise ValueError(
                f"Feature obrigatoria ausente: "
                f"{feature}"
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
                f"{feature}: "
                f"{evento[feature]}"
            )


        if not np.isfinite(
            valor
        ):

            raise ValueError(
                f"Valor nao finito para "
                f"{feature}"
            )


        valores[feature] = valor


    dataframe = pd.DataFrame(
        [valores],
        columns=FEATURES,
    )


    return (
        str(id_evento),
        dataframe,
    )


# ============================================================
# ETAPA 10 - DETECTOR BINARIO
# ============================================================

def detectar_binario(
    dataframe,
):

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
                "Classe de ataque nao encontrada "
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
            if probabilidade >= threshold
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
# ETAPA 11 - CLASSIFICADOR MULTICLASSE
# ============================================================

def detectar_categoria(
    dataframe,
):

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
# ETAPA 12 - SEVERIDADE
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
# ETAPA 13 - EXECUTANDO PIPELINE
# ============================================================

titulo(
    "ETAPA 13 - PROCESSANDO EVENTOS EXTERNOS"
)


resultados = []
alertas_soc = []
eventos_rejeitados = []

quantidade_normais = 0
quantidade_ataques = 0
quantidade_rejeitados = 0
quantidade_erros_ml = 0


for indice, evento in enumerate(
    eventos,
    start=1,
):

    print()
    print("-" * 72)

    print(
        f"EVENTO "
        f"{indice}/{len(eventos)}"
    )

    print("-" * 72)


    id_evento_original = (
        evento.get(
            "id_evento",
            f"SEM-ID-{indice}",
        )
        if isinstance(
            evento,
            dict,
        )
        else f"INVALIDO-{indice}"
    )


    print(
        f"ID recebido: "
        f"{id_evento_original}"
    )


    # ========================================================
    # VALIDACAO
    # ========================================================

    try:

        (
            id_evento,
            dataframe,
        ) = validar_evento(
            evento,
            indice,
        )


        sucesso(
            "Schema do evento validado"
        )


    except Exception as exc:

        quantidade_rejeitados += 1


        erro(
            f"Evento rejeitado: {exc}"
        )


        rejeitado = {

            "id_evento":
                str(
                    id_evento_original
                ),

            "timestamp":
                agora(),

            "motivo":
                str(exc),

            "evento":
                evento,
        }


        eventos_rejeitados.append(
            rejeitado
        )


        continue


    # ========================================================
    # MACHINE LEARNING
    # ========================================================

    try:

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

            quantidade_normais += 1


            sucesso(
                "Classificacao: NORMAL"
            )


            resultados.append(
                {
                    "id_evento":
                        id_evento,

                    "timestamp":
                        agora(),

                    "classificacao":
                        "NORMAL",

                    "probabilidade_ataque":
                        round(
                            probabilidade_ataque,
                            6,
                        ),

                    "categoria":
                        None,

                    "alerta_soc":
                        False,
                }
            )


            continue


        # ====================================================
        # ATAQUE
        # ====================================================

        quantidade_ataques += 1


        sucesso(
            "Classificacao: ATAQUE"
        )


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


        print(
            f"Categoria: "
            f"{categoria}"
        )


        if (
            confianca_categoria
            is not None
        ):

            print(
                f"Confianca categoria: "
                f"{confianca_categoria * 100:.2f}%"
            )


        print(
            f"Severidade: "
            f"{severidade}"
        )


        alerta_id = (
            f"ALT-24-"
            f"{len(alertas_soc) + 1:04d}"
        )


        alerta = {

            "alerta_id":
                alerta_id,

            "id_evento":
                id_evento,

            "timestamp":
                agora(),

            "origem_evento":
                evento.get(
                    "origem",
                    "EXTERNO",
                ),

            "detector":
                PROJETO,

            "classificacao":
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


        resultados.append(
            {
                "id_evento":
                    id_evento,

                "timestamp":
                    agora(),

                "classificacao":
                    "ATAQUE",

                "probabilidade_ataque":
                    round(
                        probabilidade_ataque,
                        6,
                    ),

                "categoria":
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
        )


        sucesso(
            f"Alerta SOC criado: "
            f"{alerta_id}"
        )


    except Exception as exc:

        quantidade_erros_ml += 1


        erro(
            f"Erro no processamento ML: "
            f"{exc}"
        )


        resultados.append(
            {
                "id_evento":
                    id_evento,

                "timestamp":
                    agora(),

                "status":
                    "ERRO_ML",

                "erro":
                    str(exc),
            }
        )


# ============================================================
# ETAPA 14 - SALVANDO ALERTAS
# ============================================================

titulo(
    "ETAPA 14 - SALVANDO RESULTADOS"
)


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


except Exception as exc:

    erro(
        f"Falha ao salvar alertas: {exc}"
    )

    sys.exit(1)


# ============================================================
# EVENTOS REJEITADOS
# ============================================================

try:

    with open(
        ARQUIVO_REJEITADOS,
        "w",
        encoding="utf-8",
    ) as arquivo:

        json.dump(
            eventos_rejeitados,
            arquivo,
            indent=4,
            ensure_ascii=False,
            default=converter_json,
        )


    sucesso(
        "Eventos rejeitados registrados"
    )


except Exception as exc:

    erro(
        f"Falha ao salvar rejeitados: {exc}"
    )

    sys.exit(1)


print()
print(
    f"Alertas: "
    f"{ARQUIVO_ALERTAS.relative_to(BASE_DIR)}"
)

print(
    f"Rejeitados: "
    f"{ARQUIVO_REJEITADOS.relative_to(BASE_DIR)}"
)


# ============================================================
# ETAPA 15 - RELATORIO
# ============================================================

titulo(
    "ETAPA 15 - GERANDO RELATORIO"
)


relatorio = {

    "projeto":
        PROJETO,

    "aula":
        AULA,

    "versao":
        VERSAO,

    "timestamp":
        agora(),

    "fonte": {

        "arquivo":
            str(
                arquivo_entrada.relative_to(
                    BASE_DIR
                )
            ),

        "formato":
            formato_entrada,
    },

    "pipeline": (
        "JSON/JSONL -> VALIDACAO -> "
        "DETECTOR BINARIO -> "
        "CLASSIFICADOR MULTICLASSE -> "
        "SEVERIDADE -> ALERTA SOC"
    ),

    "modelo_binario": {

        "algoritmo":
            type(
                modelo_binario
            ).__name__,

        "threshold":
            threshold,
    },

    "modelo_multiclasse": {

        "algoritmo":
            type(
                modelo_multiclasse
            ).__name__,

        "categorias":
            categorias,
    },

    "features":
        FEATURES,

    "estatisticas": {

        "eventos_recebidos":
            len(eventos),

        "eventos_validos":
            (
                len(eventos)
                - quantidade_rejeitados
            ),

        "eventos_rejeitados":
            quantidade_rejeitados,

        "eventos_normais":
            quantidade_normais,

        "eventos_ataque":
            quantidade_ataques,

        "erros_ml":
            quantidade_erros_ml,

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
        "Relatorio salvo"
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
# ETAPA 16 - RESUMO DOS ALERTAS
# ============================================================

titulo(
    "ETAPA 16 - RESUMO DOS ALERTAS SOC"
)


print(
    f"Quantidade de alertas: "
    f"{len(alertas_soc)}"
)


for alerta in alertas_soc:

    print()
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


# ============================================================
# ETAPA 17 - VALIDACAO FINAL
# ============================================================

titulo(
    "ETAPA 17 - VALIDACAO FINAL"
)


validacoes = {

    "Modelo binario encontrado":
        ARQUIVO_MODELO_BINARIO.exists(),

    "Modelo multiclasse encontrado":
        ARQUIVO_MODELO_MULTICLASSE.exists(),

    "Configuracoes carregadas":
        (
            config_binario is not None
            and
            config_multiclasse is not None
        ),

    "9 features validadas":
        len(FEATURES) == 9,

    "Arquivo externo carregado":
        arquivo_entrada.exists(),

    "Eventos recebidos":
        len(eventos) > 0,

    "Todos os eventos contabilizados":
        (
            (
                quantidade_normais
                + quantidade_ataques
                + quantidade_rejeitados
                + quantidade_erros_ml
            )
            == len(eventos)
        ),

    "Alertas persistidos":
        ARQUIVO_ALERTAS.exists(),

    "Rejeitados persistidos":
        ARQUIVO_REJEITADOS.exists(),

    "Relatorio persistido":
        ARQUIVO_RELATORIO.exists(),
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


# ============================================================
# ETAPA 18 - RESUMO FINAL
# ============================================================

titulo(
    "RESUMO FINAL DA AULA 24"
)


print(
    f"Eventos recebidos: "
    f"{len(eventos)}"
)

print(
    f"Eventos validos: "
    f"{len(eventos) - quantidade_rejeitados}"
)

print(
    f"Eventos rejeitados: "
    f"{quantidade_rejeitados}"
)

print(
    f"Eventos NORMAL: "
    f"{quantidade_normais}"
)

print(
    f"Eventos ATAQUE: "
    f"{quantidade_ataques}"
)

print(
    f"Erros ML: "
    f"{quantidade_erros_ml}"
)

print(
    f"Alertas SOC: "
    f"{len(alertas_soc)}"
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
        "AULA 24 CONCLUIDA"
    )

else:

    status_final = (
        "AULA 24 COM AJUSTES"
    )


print(
    f"Status: "
    f"{status_final}"
)


# ============================================================
# ARQUITETURA
# ============================================================

titulo(
    "ARQUITETURA DA AULA 24"
)


print("ARQUIVO EXTERNO JSON / JSONL")
print("          |")
print("          v")
print("VALIDACAO DE SCHEMA")
print("          |")
print("          +---- INVALIDO ---> REJEITADOS")
print("          |")
print("          v")
print("DETECTOR BINARIO")
print("          |")
print("          +---- NORMAL ------> FINALIZA")
print("          |")
print("          v")
print("ATAQUE")
print("          |")
print("          v")
print("CLASSIFICADOR MULTICLASSE")
print("          |")
print("          v")
print("CATEGORIA")
print("          |")
print("          v")
print("SEVERIDADE")
print("          |")
print("          v")
print("ALERTA SOC")


# ============================================================
# FINAL
# ============================================================

titulo(
    "CYBERSENTINEL-ML"
)

print(
    "AULA 24 - "
    "INGESTAO DE EVENTOS EXTERNOS"
)

print(
    status_final
)

linha()