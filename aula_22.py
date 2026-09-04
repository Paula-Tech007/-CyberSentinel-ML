# ============================================================
# CyberSentinel-ML
# AULA 22 - CLASSIFICACAO MULTICLASSE DE ATAQUES
# ETAPA 2 - OTIMIZACAO E COMPARACAO DE MODELOS
# ============================================================
#
# OBJETIVO:
# Melhorar a classificacao multiclasse de ataques do UNSW-NB15.
#
# ESTRATEGIA:
# - Utilizar somente eventos classificados como ATAQUE.
# - Manter as mesmas 9 features do CyberSentinel-ML.
# - Comparar diferentes algoritmos/estrategias.
# - Priorizar Macro Recall e Macro F1.
# - Avaliar desempenho por categoria.
# - Salvar o melhor modelo separadamente.
#
# IMPORTANTE:
# Esta aula NAO altera o detector binario da V1.0.
#
# ============================================================


# ============================================================
# IMPORTACOES
# ============================================================

import sys
import json
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import (
    RandomForestClassifier,
    ExtraTreesClassifier,
)

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix,
)


# ============================================================
# CONFIGURACOES
# ============================================================

PROJETO = "CyberSentinel-ML"
AULA = 22
VERSAO = "Etapa 2 - Otimizacao Multiclasse"

BASE_DIR = Path(__file__).resolve().parent

DATASET_DIR = (
    BASE_DIR
    / "datasets"
    / "UNSW_NB15-Complete-dataset"
)

ARQUIVO_TREINO = (
    DATASET_DIR
    / "UNSW_NB15_training-set.csv"
)

ARQUIVO_TESTE = (
    DATASET_DIR
    / "UNSW_NB15_testing-set.csv"
)

PASTA_MODELOS = BASE_DIR / "modelos"
PASTA_ALERTAS = BASE_DIR / "alertas"

ARQUIVO_MODELO_VENCEDOR = (
    PASTA_MODELOS
    / "unsw_attack_multiclass_otimizado.joblib"
)

ARQUIVO_CONFIGURACAO = (
    PASTA_MODELOS
    / "configuracao_multiclasse_otimizada_aula_22.joblib"
)

ARQUIVO_RELATORIO = (
    PASTA_ALERTAS
    / "comparacao_multiclasse_aula_22.json"
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

TARGET_BINARIO = "label"
TARGET_MULTICLASSE = "attack_cat"


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


# ============================================================
# CABECALHO
# ============================================================

linha()
print("AULA 22 - OTIMIZACAO DA CLASSIFICACAO MULTICLASSE")
print(PROJETO)
print(VERSAO)
linha()


# ============================================================
# ETAPA 1 - VALIDANDO AMBIENTE
# ============================================================

titulo("ETAPA 1 - VALIDANDO AMBIENTE")

PASTA_MODELOS.mkdir(
    parents=True,
    exist_ok=True,
)

PASTA_ALERTAS.mkdir(
    parents=True,
    exist_ok=True,
)

sucesso("Pasta modelos pronta")
sucesso("Pasta alertas pronta")


if not ARQUIVO_TREINO.exists():
    erro("Dataset de treinamento nao encontrado")
    print(ARQUIVO_TREINO)
    sys.exit(1)


if not ARQUIVO_TESTE.exists():
    erro("Dataset de teste nao encontrado")
    print(ARQUIVO_TESTE)
    sys.exit(1)


sucesso("Dataset de treinamento encontrado")
sucesso("Dataset de teste encontrado")


# ============================================================
# ETAPA 2 - CARREGANDO DATASETS
# ============================================================

titulo("ETAPA 2 - CARREGANDO DATASETS")

try:
    treino = pd.read_csv(ARQUIVO_TREINO)
    teste = pd.read_csv(ARQUIVO_TESTE)

except Exception as exc:
    erro(f"Falha ao carregar datasets: {exc}")
    sys.exit(1)


sucesso("Dataset de treinamento carregado")
sucesso("Dataset de teste carregado")

print()
print(f"Treinamento total: {len(treino):,}")
print(f"Teste total:       {len(teste):,}")
print(f"Colunas treino:    {len(treino.columns)}")
print(f"Colunas teste:     {len(teste.columns)}")


# ============================================================
# ETAPA 3 - VALIDANDO COLUNAS
# ============================================================

titulo("ETAPA 3 - VALIDANDO FEATURES E TARGETS")

COLUNAS_NECESSARIAS = (
    FEATURES
    + [
        TARGET_BINARIO,
        TARGET_MULTICLASSE,
    ]
)


faltando_treino = [
    coluna
    for coluna in COLUNAS_NECESSARIAS
    if coluna not in treino.columns
]


faltando_teste = [
    coluna
    for coluna in COLUNAS_NECESSARIAS
    if coluna not in teste.columns
]


if faltando_treino:
    erro("Colunas ausentes no treinamento")

    for coluna in faltando_treino:
        print(f" - {coluna}")

    sys.exit(1)


if faltando_teste:
    erro("Colunas ausentes no teste")

    for coluna in faltando_teste:
        print(f" - {coluna}")

    sys.exit(1)


sucesso("9 features encontradas")
sucesso("Target binario encontrado")
sucesso("Target multiclasse encontrado")

print()
print("Features:")

for numero, feature in enumerate(
    FEATURES,
    start=1,
):
    print(f"{numero:02d} - {feature}")


# ============================================================
# ETAPA 4 - SELECIONANDO APENAS ATAQUES
# ============================================================

titulo("ETAPA 4 - SELECIONANDO EVENTOS DE ATAQUE")

treino_ataques = treino[
    treino[TARGET_BINARIO] == 1
].copy()

teste_ataques = teste[
    teste[TARGET_BINARIO] == 1
].copy()


if treino_ataques.empty:
    erro("Nenhum ataque encontrado no treinamento")
    sys.exit(1)


if teste_ataques.empty:
    erro("Nenhum ataque encontrado no teste")
    sys.exit(1)


sucesso("Eventos de ataque selecionados")

print()
print(
    f"Ataques treinamento: "
    f"{len(treino_ataques):,}"
)

print(
    f"Ataques teste:       "
    f"{len(teste_ataques):,}"
)


# ============================================================
# ETAPA 5 - NORMALIZANDO TARGET
# ============================================================

titulo("ETAPA 5 - PREPARANDO CATEGORIAS")

treino_ataques[TARGET_MULTICLASSE] = (
    treino_ataques[TARGET_MULTICLASSE]
    .astype(str)
    .str.strip()
)

teste_ataques[TARGET_MULTICLASSE] = (
    teste_ataques[TARGET_MULTICLASSE]
    .astype(str)
    .str.strip()
)


categorias = sorted(
    treino_ataques[
        TARGET_MULTICLASSE
    ]
    .unique()
    .tolist()
)


categorias_teste = sorted(
    teste_ataques[
        TARGET_MULTICLASSE
    ]
    .unique()
    .tolist()
)


categorias_desconhecidas = (
    set(categorias_teste)
    - set(categorias)
)


if categorias_desconhecidas:
    erro(
        "Existem categorias no teste "
        "ausentes no treinamento"
    )

    for categoria in sorted(
        categorias_desconhecidas
    ):
        print(f" - {categoria}")

    sys.exit(1)


sucesso(
    f"{len(categorias)} categorias encontradas"
)

sucesso(
    "Todas as categorias de teste "
    "existem no treinamento"
)

print()

for numero, categoria in enumerate(
    categorias,
    start=1,
):
    print(
        f"{numero:02d} - {categoria}"
    )


# ============================================================
# ETAPA 6 - DISTRIBUICAO DAS CLASSES
# ============================================================

titulo("ETAPA 6 - DISTRIBUICAO DAS CATEGORIAS")

distribuicao_treino = (
    treino_ataques[
        TARGET_MULTICLASSE
    ]
    .value_counts()
)


print("TREINAMENTO")
print("-" * 72)

for categoria, quantidade in (
    distribuicao_treino.items()
):

    percentual = (
        quantidade
        / len(treino_ataques)
        * 100
    )

    print(
        f"{categoria:<20}"
        f"{quantidade:>10,}"
        f"{percentual:>10.2f}%"
    )


print()
print("TESTE")
print("-" * 72)


distribuicao_teste = (
    teste_ataques[
        TARGET_MULTICLASSE
    ]
    .value_counts()
)


for categoria, quantidade in (
    distribuicao_teste.items()
):

    percentual = (
        quantidade
        / len(teste_ataques)
        * 100
    )

    print(
        f"{categoria:<20}"
        f"{quantidade:>10,}"
        f"{percentual:>10.2f}%"
    )


# ============================================================
# ETAPA 7 - PREPARANDO X E Y
# ============================================================

titulo("ETAPA 7 - PREPARANDO DADOS")

X_train = treino_ataques[
    FEATURES
].copy()

X_test = teste_ataques[
    FEATURES
].copy()

y_train = treino_ataques[
    TARGET_MULTICLASSE
].copy()

y_test = teste_ataques[
    TARGET_MULTICLASSE
].copy()


for coluna in FEATURES:

    X_train[coluna] = pd.to_numeric(
        X_train[coluna],
        errors="coerce",
    )

    X_test[coluna] = pd.to_numeric(
        X_test[coluna],
        errors="coerce",
    )


X_train = X_train.replace(
    [np.inf, -np.inf],
    np.nan,
)

X_test = X_test.replace(
    [np.inf, -np.inf],
    np.nan,
)


nulos_treino = int(
    X_train.isnull().sum().sum()
)

nulos_teste = int(
    X_test.isnull().sum().sum()
)


print(
    f"Valores invalidos treinamento: "
    f"{nulos_treino}"
)

print(
    f"Valores invalidos teste: "
    f"{nulos_teste}"
)


X_train = X_train.fillna(0)
X_test = X_test.fillna(0)


sucesso("Dados preparados")

print()
print(f"X_train: {X_train.shape}")
print(f"X_test:  {X_test.shape}")
print(f"y_train: {y_train.shape}")
print(f"y_test:  {y_test.shape}")


# ============================================================
# ETAPA 8 - CONFIGURANDO MODELOS
# ============================================================

titulo("ETAPA 8 - CONFIGURANDO MODELOS")


modelos = {

    "Random Forest Baseline":

        RandomForestClassifier(
            n_estimators=200,
            random_state=42,
            n_jobs=-1,
            class_weight="balanced_subsample",
        ),


    "Random Forest Balanced":

        RandomForestClassifier(
            n_estimators=300,
            random_state=42,
            n_jobs=-1,
            class_weight="balanced",
            max_features="sqrt",
        ),


    "Extra Trees Balanced":

        ExtraTreesClassifier(
            n_estimators=300,
            random_state=42,
            n_jobs=-1,
            class_weight="balanced",
            max_features="sqrt",
        ),


    "Decision Tree Balanced":

        DecisionTreeClassifier(
            random_state=42,
            class_weight="balanced",
            max_depth=None,
            min_samples_leaf=2,
        ),
}


for numero, nome in enumerate(
    modelos.keys(),
    start=1,
):
    print(
        f"{numero:02d} - {nome}: PRONTO"
    )


# ============================================================
# ETAPA 9 - TREINANDO E AVALIANDO
# ============================================================

titulo("ETAPA 9 - TREINANDO E AVALIANDO MODELOS")


resultados = []

modelos_treinados = {}


for numero, (
    nome,
    modelo,
) in enumerate(
    modelos.items(),
    start=1,
):

    print()
    print("-" * 72)
    print(
        f"MODELO {numero}/{len(modelos)}: "
        f"{nome}"
    )
    print("-" * 72)


    # ========================================================
    # TREINAMENTO
    # ========================================================

    print("Treinando...")

    inicio_treinamento = (
        time.perf_counter()
    )

    try:
        modelo.fit(
            X_train,
            y_train,
        )

    except Exception as exc:
        erro(
            f"Falha no treinamento: {exc}"
        )
        continue


    tempo_treinamento = (
        time.perf_counter()
        - inicio_treinamento
    )

    sucesso("Treinamento concluido")

    print(
        f"Tempo: "
        f"{tempo_treinamento:.4f}s"
    )


    # ========================================================
    # PREDICAO
    # ========================================================

    print("Executando predicoes...")

    inicio_predicao = (
        time.perf_counter()
    )

    try:
        y_pred = modelo.predict(
            X_test
        )

    except Exception as exc:
        erro(
            f"Falha na predicao: {exc}"
        )
        continue


    tempo_predicao = (
        time.perf_counter()
        - inicio_predicao
    )

    sucesso("Predicoes concluidas")

    print(
        f"Tempo: "
        f"{tempo_predicao:.4f}s"
    )


    # ========================================================
    # METRICAS
    # ========================================================

    accuracy = accuracy_score(
        y_test,
        y_pred,
    )

    precision_macro = precision_score(
        y_test,
        y_pred,
        average="macro",
        zero_division=0,
    )

    recall_macro = recall_score(
        y_test,
        y_pred,
        average="macro",
        zero_division=0,
    )

    f1_macro = f1_score(
        y_test,
        y_pred,
        average="macro",
        zero_division=0,
    )

    precision_weighted = precision_score(
        y_test,
        y_pred,
        average="weighted",
        zero_division=0,
    )

    recall_weighted = recall_score(
        y_test,
        y_pred,
        average="weighted",
        zero_division=0,
    )

    f1_weighted = f1_score(
        y_test,
        y_pred,
        average="weighted",
        zero_division=0,
    )


    print()
    print("RESULTADO GERAL")
    print()

    print(
        f"Accuracy:           "
        f"{accuracy * 100:.2f}%"
    )

    print(
        f"Precision Macro:    "
        f"{precision_macro * 100:.2f}%"
    )

    print(
        f"Recall Macro:       "
        f"{recall_macro * 100:.2f}%"
    )

    print(
        f"F1 Macro:           "
        f"{f1_macro * 100:.2f}%"
    )

    print(
        f"F1 Weighted:        "
        f"{f1_weighted * 100:.2f}%"
    )


    # ========================================================
    # RESULTADOS POR CATEGORIA
    # ========================================================

    relatorio_categoria = (
        classification_report(
            y_test,
            y_pred,
            labels=categorias,
            output_dict=True,
            zero_division=0,
        )
    )


    resultados_por_categoria = []


    print()
    print("DESEMPENHO POR CATEGORIA")
    print()

    print(
        f"{'CATEGORIA':<20}"
        f"{'PRECISION':>12}"
        f"{'RECALL':>12}"
        f"{'F1':>12}"
        f"{'SUPORTE':>12}"
    )

    print("-" * 68)


    for categoria in categorias:

        dados = (
            relatorio_categoria[
                categoria
            ]
        )

        precision_categoria = float(
            dados["precision"]
        )

        recall_categoria = float(
            dados["recall"]
        )

        f1_categoria = float(
            dados["f1-score"]
        )

        suporte = int(
            dados["support"]
        )


        print(
            f"{categoria:<20}"
            f"{precision_categoria * 100:>11.2f}%"
            f"{recall_categoria * 100:>11.2f}%"
            f"{f1_categoria * 100:>11.2f}%"
            f"{suporte:>12,}"
        )


        resultados_por_categoria.append(
            {
                "categoria":
                    categoria,

                "precision_percentual":
                    round(
                        precision_categoria
                        * 100,
                        4,
                    ),

                "recall_percentual":
                    round(
                        recall_categoria
                        * 100,
                        4,
                    ),

                "f1_percentual":
                    round(
                        f1_categoria
                        * 100,
                        4,
                    ),

                "suporte":
                    suporte,
            }
        )


    # ========================================================
    # MATRIZ
    # ========================================================

    matriz = confusion_matrix(
        y_test,
        y_pred,
        labels=categorias,
    )


    # ========================================================
    # SALVANDO RESULTADO
    # ========================================================

    resultado = {

        "modelo":
            nome,

        "accuracy_percentual":
            round(
                float(
                    accuracy * 100
                ),
                4,
            ),

        "precision_macro_percentual":
            round(
                float(
                    precision_macro * 100
                ),
                4,
            ),

        "recall_macro_percentual":
            round(
                float(
                    recall_macro * 100
                ),
                4,
            ),

        "f1_macro_percentual":
            round(
                float(
                    f1_macro * 100
                ),
                4,
            ),

        "precision_weighted_percentual":
            round(
                float(
                    precision_weighted * 100
                ),
                4,
            ),

        "recall_weighted_percentual":
            round(
                float(
                    recall_weighted * 100
                ),
                4,
            ),

        "f1_weighted_percentual":
            round(
                float(
                    f1_weighted * 100
                ),
                4,
            ),

        "tempo_treinamento_segundos":
            round(
                tempo_treinamento,
                4,
            ),

        "tempo_predicao_segundos":
            round(
                tempo_predicao,
                4,
            ),

        "categorias":
            resultados_por_categoria,

        "matriz_confusao":
            matriz.tolist(),
    }


    resultados.append(
        resultado
    )

    modelos_treinados[
        nome
    ] = modelo


# ============================================================
# ETAPA 10 - VALIDANDO TREINAMENTOS
# ============================================================

titulo("ETAPA 10 - VALIDANDO TREINAMENTOS")


if len(resultados) == 0:
    erro(
        "Nenhum modelo foi treinado "
        "com sucesso"
    )
    sys.exit(1)


sucesso(
    f"{len(resultados)} modelos "
    f"avaliados com sucesso"
)


# ============================================================
# ETAPA 11 - RANKING
# ============================================================

titulo("ETAPA 11 - RANKING DOS MODELOS")


# ============================================================
# CRITERIO SOC:
#
# 1 - Maior Macro F1
# 2 - Maior Macro Recall
# 3 - Maior Weighted F1
# 4 - Maior Accuracy
#
# O Macro F1 recebe prioridade porque todas as categorias
# precisam ter peso semelhante na avaliacao.
# ============================================================


ranking = sorted(
    resultados,
    key=lambda item: (
        item[
            "f1_macro_percentual"
        ],
        item[
            "recall_macro_percentual"
        ],
        item[
            "f1_weighted_percentual"
        ],
        item[
            "accuracy_percentual"
        ],
    ),
    reverse=True,
)


for posicao, resultado in enumerate(
    ranking,
    start=1,
):

    print()
    print(
        f"{posicao} lugar - "
        f"{resultado['modelo']}"
    )

    print(
        f"Macro F1:     "
        f"{resultado['f1_macro_percentual']:.2f}%"
    )

    print(
        f"Macro Recall: "
        f"{resultado['recall_macro_percentual']:.2f}%"
    )

    print(
        f"Weighted F1:  "
        f"{resultado['f1_weighted_percentual']:.2f}%"
    )

    print(
        f"Accuracy:     "
        f"{resultado['accuracy_percentual']:.2f}%"
    )


# ============================================================
# ETAPA 12 - MODELO VENCEDOR
# ============================================================

titulo("ETAPA 12 - MODELO VENCEDOR")


vencedor = ranking[0]

nome_vencedor = (
    vencedor["modelo"]
)

modelo_vencedor = (
    modelos_treinados[
        nome_vencedor
    ]
)


print(
    f"Modelo: "
    f"{nome_vencedor}"
)

print(
    f"Accuracy: "
    f"{vencedor['accuracy_percentual']:.2f}%"
)

print(
    f"Macro Precision: "
    f"{vencedor['precision_macro_percentual']:.2f}%"
)

print(
    f"Macro Recall: "
    f"{vencedor['recall_macro_percentual']:.2f}%"
)

print(
    f"Macro F1: "
    f"{vencedor['f1_macro_percentual']:.2f}%"
)

print(
    f"Weighted F1: "
    f"{vencedor['f1_weighted_percentual']:.2f}%"
)


# ============================================================
# ETAPA 13 - ANALISE DAS CATEGORIAS DO VENCEDOR
# ============================================================

titulo(
    "ETAPA 13 - ANALISE DAS CATEGORIAS DO VENCEDOR"
)


categorias_vencedor = (
    vencedor["categorias"]
)


ranking_categorias = sorted(
    categorias_vencedor,
    key=lambda item:
        item["f1_percentual"],
    reverse=True,
)


print("MELHORES CATEGORIAS")
print()


for posicao, item in enumerate(
    ranking_categorias[:5],
    start=1,
):

    print(
        f"{posicao}. "
        f"{item['categoria']} "
        f"| Recall="
        f"{item['recall_percentual']:.2f}% "
        f"| F1="
        f"{item['f1_percentual']:.2f}%"
    )


print()
print("CATEGORIAS MAIS DIFICEIS")
print()


piores_categorias = sorted(
    categorias_vencedor,
    key=lambda item:
        item["f1_percentual"],
)


for posicao, item in enumerate(
    piores_categorias[:5],
    start=1,
):

    print(
        f"{posicao}. "
        f"{item['categoria']} "
        f"| Recall="
        f"{item['recall_percentual']:.2f}% "
        f"| F1="
        f"{item['f1_percentual']:.2f}%"
    )


# ============================================================
# ETAPA 14 - COMPARACAO COM BASELINE DA PRIMEIRA EXECUCAO
# ============================================================

titulo(
    "ETAPA 14 - COMPARACAO COM BASELINE MULTICLASSE"
)


BASELINE_ACCURACY = 72.95
BASELINE_RECALL_MACRO = 52.86
BASELINE_F1_MACRO = 52.05
BASELINE_F1_WEIGHTED = 75.47


ganho_accuracy = (
    vencedor[
        "accuracy_percentual"
    ]
    - BASELINE_ACCURACY
)


ganho_recall_macro = (
    vencedor[
        "recall_macro_percentual"
    ]
    - BASELINE_RECALL_MACRO
)


ganho_f1_macro = (
    vencedor[
        "f1_macro_percentual"
    ]
    - BASELINE_F1_MACRO
)


ganho_f1_weighted = (
    vencedor[
        "f1_weighted_percentual"
    ]
    - BASELINE_F1_WEIGHTED
)


print("BASELINE ANTERIOR")
print()

print(
    f"Accuracy:      "
    f"{BASELINE_ACCURACY:.2f}%"
)

print(
    f"Macro Recall:  "
    f"{BASELINE_RECALL_MACRO:.2f}%"
)

print(
    f"Macro F1:      "
    f"{BASELINE_F1_MACRO:.2f}%"
)

print(
    f"Weighted F1:   "
    f"{BASELINE_F1_WEIGHTED:.2f}%"
)


print()
print("MODELO VENCEDOR")
print()

print(
    f"Accuracy:      "
    f"{vencedor['accuracy_percentual']:.2f}%"
)

print(
    f"Macro Recall:  "
    f"{vencedor['recall_macro_percentual']:.2f}%"
)

print(
    f"Macro F1:      "
    f"{vencedor['f1_macro_percentual']:.2f}%"
)

print(
    f"Weighted F1:   "
    f"{vencedor['f1_weighted_percentual']:.2f}%"
)


print()
print("DIFERENCA")
print()

print(
    f"Accuracy:      "
    f"{ganho_accuracy:+.2f} p.p."
)

print(
    f"Macro Recall:  "
    f"{ganho_recall_macro:+.2f} p.p."
)

print(
    f"Macro F1:      "
    f"{ganho_f1_macro:+.2f} p.p."
)

print(
    f"Weighted F1:   "
    f"{ganho_f1_weighted:+.2f} p.p."
)


melhorou_macro_f1 = (
    vencedor[
        "f1_macro_percentual"
    ]
    > BASELINE_F1_MACRO
)


if melhorou_macro_f1:
    sucesso(
        "O modelo vencedor superou "
        "o baseline em Macro F1"
    )
else:
    print(
        "[AVISO] O vencedor nao superou "
        "o baseline anterior em Macro F1"
    )


# ============================================================
# ETAPA 15 - SALVANDO MODELO VENCEDOR
# ============================================================

titulo(
    "ETAPA 15 - SALVANDO MODELO VENCEDOR"
)


try:

    joblib.dump(
        modelo_vencedor,
        ARQUIVO_MODELO_VENCEDOR,
    )

    sucesso(
        "Modelo vencedor salvo"
    )

except Exception as exc:

    erro(
        f"Falha ao salvar modelo: {exc}"
    )

    sys.exit(1)


# ============================================================
# CONFIGURACAO
# ============================================================

configuracao = {

    "projeto":
        PROJETO,

    "aula":
        AULA,

    "versao":
        VERSAO,

    "modelo_vencedor":
        nome_vencedor,

    "features":
        FEATURES,

    "quantidade_features":
        len(FEATURES),

    "target":
        TARGET_MULTICLASSE,

    "categorias":
        categorias,

    "quantidade_categorias":
        len(categorias),

    "criterio_selecao": [
        "Macro F1",
        "Macro Recall",
        "Weighted F1",
        "Accuracy",
    ],

    "metricas_vencedor": {

        "accuracy_percentual":
            vencedor[
                "accuracy_percentual"
            ],

        "precision_macro_percentual":
            vencedor[
                "precision_macro_percentual"
            ],

        "recall_macro_percentual":
            vencedor[
                "recall_macro_percentual"
            ],

        "f1_macro_percentual":
            vencedor[
                "f1_macro_percentual"
            ],

        "f1_weighted_percentual":
            vencedor[
                "f1_weighted_percentual"
            ],
    },

    "baseline": {

        "accuracy_percentual":
            BASELINE_ACCURACY,

        "recall_macro_percentual":
            BASELINE_RECALL_MACRO,

        "f1_macro_percentual":
            BASELINE_F1_MACRO,

        "f1_weighted_percentual":
            BASELINE_F1_WEIGHTED,
    },

    "ganhos_pontos_percentuais": {

        "accuracy":
            round(
                ganho_accuracy,
                4,
            ),

        "recall_macro":
            round(
                ganho_recall_macro,
                4,
            ),

        "f1_macro":
            round(
                ganho_f1_macro,
                4,
            ),

        "f1_weighted":
            round(
                ganho_f1_weighted,
                4,
            ),
    },
}


try:

    joblib.dump(
        configuracao,
        ARQUIVO_CONFIGURACAO,
    )

    sucesso(
        "Configuracao salva"
    )

except Exception as exc:

    erro(
        f"Falha ao salvar configuracao: {exc}"
    )

    sys.exit(1)


print()

print(
    "Modelo:"
)

print(
    ARQUIVO_MODELO_VENCEDOR.relative_to(
        BASE_DIR
    )
)

print()

print(
    "Configuracao:"
)

print(
    ARQUIVO_CONFIGURACAO.relative_to(
        BASE_DIR
    )
)


# ============================================================
# ETAPA 16 - TESTANDO MODELO SALVO
# ============================================================

titulo(
    "ETAPA 16 - VALIDANDO MODELO PERSISTIDO"
)


try:

    modelo_carregado = joblib.load(
        ARQUIVO_MODELO_VENCEDOR
    )

    configuracao_carregada = joblib.load(
        ARQUIVO_CONFIGURACAO
    )

    sucesso(
        "Modelo recarregado"
    )

    sucesso(
        "Configuracao recarregada"
    )

except Exception as exc:

    erro(
        f"Falha ao recarregar artefatos: {exc}"
    )

    sys.exit(1)


# ============================================================
# TESTE RAPIDO
# ============================================================

evento_teste = X_test.iloc[
    [0]
]

categoria_real = y_test.iloc[
    0
]

categoria_prevista = (
    modelo_carregado.predict(
        evento_teste
    )[0]
)


print()
print(
    f"Categoria real:     "
    f"{categoria_real}"
)

print(
    f"Categoria prevista: "
    f"{categoria_prevista}"
)


# ============================================================
# ETAPA 17 - SALVANDO RELATORIO COMPLETO
# ============================================================

titulo(
    "ETAPA 17 - SALVANDO RELATORIO"
)


relatorio_final = {

    "projeto":
        PROJETO,

    "aula":
        AULA,

    "versao":
        VERSAO,

    "dataset":
        "UNSW-NB15",

    "eventos_treinamento":
        int(
            len(X_train)
        ),

    "eventos_teste":
        int(
            len(X_test)
        ),

    "features":
        FEATURES,

    "categorias":
        categorias,

    "quantidade_categorias":
        len(categorias),

    "criterio_ranking": [
        "Macro F1",
        "Macro Recall",
        "Weighted F1",
        "Accuracy",
    ],

    "resultados":
        resultados,

    "ranking": [
        {
            "posicao":
                posicao,

            "modelo":
                item["modelo"],

            "macro_f1":
                item[
                    "f1_macro_percentual"
                ],

            "macro_recall":
                item[
                    "recall_macro_percentual"
                ],

            "weighted_f1":
                item[
                    "f1_weighted_percentual"
                ],

            "accuracy":
                item[
                    "accuracy_percentual"
                ],
        }

        for posicao, item in enumerate(
            ranking,
            start=1,
        )
    ],

    "modelo_vencedor":
        nome_vencedor,

    "resultado_vencedor":
        vencedor,

    "comparacao_baseline": {

        "baseline_macro_f1":
            BASELINE_F1_MACRO,

        "novo_macro_f1":
            vencedor[
                "f1_macro_percentual"
            ],

        "ganho_macro_f1":
            round(
                ganho_f1_macro,
                4,
            ),

        "baseline_macro_recall":
            BASELINE_RECALL_MACRO,

        "novo_macro_recall":
            vencedor[
                "recall_macro_percentual"
            ],

        "ganho_macro_recall":
            round(
                ganho_recall_macro,
                4,
            ),
    },

    "modelo_salvo":
        str(
            ARQUIVO_MODELO_VENCEDOR.relative_to(
                BASE_DIR
            )
        ),

    "configuracao_salva":
        str(
            ARQUIVO_CONFIGURACAO.relative_to(
                BASE_DIR
            )
        ),

    "integracao_pipeline":
        False,
}


try:

    with open(
        ARQUIVO_RELATORIO,
        "w",
        encoding="utf-8",
    ) as arquivo:

        json.dump(
            relatorio_final,
            arquivo,
            indent=4,
            ensure_ascii=False,
        )

    sucesso(
        "Relatorio salvo"
    )

except Exception as exc:

    erro(
        f"Falha ao salvar relatorio: {exc}"
    )

    sys.exit(1)


print()
print(
    f"Arquivo: "
    f"{ARQUIVO_RELATORIO.relative_to(BASE_DIR)}"
)


# ============================================================
# ETAPA 18 - VALIDACAO FINAL
# ============================================================

titulo(
    "ETAPA 18 - VALIDACAO FINAL"
)


validacoes = {

    "Dataset carregado":
        True,

    "Somente ataques utilizados":
        (
            len(X_train)
            < len(treino)
        ),

    "9 features utilizadas":
        (
            len(FEATURES)
            == 9
        ),

    "Multiplas categorias":
        (
            len(categorias)
            > 1
        ),

    "Modelos configurados":
        (
            len(modelos)
            == 4
        ),

    "Modelos avaliados":
        (
            len(resultados)
            == len(modelos)
        ),

    "Ranking criado":
        (
            len(ranking)
            > 0
        ),

    "Modelo vencedor definido":
        (
            nome_vencedor
            in modelos_treinados
        ),

    "Modelo salvo":
        (
            ARQUIVO_MODELO_VENCEDOR.exists()
        ),

    "Configuracao salva":
        (
            ARQUIVO_CONFIGURACAO.exists()
        ),

    "Relatorio salvo":
        (
            ARQUIVO_RELATORIO.exists()
        ),
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
# RESUMO FINAL
# ============================================================

titulo(
    "RESUMO FINAL DA AULA 22"
)


print(
    f"Modelos avaliados: "
    f"{len(resultados)}"
)

print(
    f"Categorias: "
    f"{len(categorias)}"
)

print()

print(
    f"Modelo vencedor: "
    f"{nome_vencedor}"
)

print(
    f"Accuracy: "
    f"{vencedor['accuracy_percentual']:.2f}%"
)

print(
    f"Macro Recall: "
    f"{vencedor['recall_macro_percentual']:.2f}%"
)

print(
    f"Macro F1: "
    f"{vencedor['f1_macro_percentual']:.2f}%"
)

print(
    f"Weighted F1: "
    f"{vencedor['f1_weighted_percentual']:.2f}%"
)

print()

print(
    f"Ganho Macro Recall: "
    f"{ganho_recall_macro:+.2f} p.p."
)

print(
    f"Ganho Macro F1: "
    f"{ganho_f1_macro:+.2f} p.p."
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
        "AULA 22 - ETAPA 2 CONCLUIDA"
    )
else:
    status_final = (
        "AULA 22 - ETAPA 2 COM AJUSTES"
    )


print(
    f"Status: "
    f"{status_final}"
)


# ============================================================
# ARQUITETURA
# ============================================================

titulo(
    "ARQUITETURA CYBERSENTINEL-ML"
)


print(
    "EVENTO"
)

print(
    "  |"
)

print(
    "  v"
)

print(
    "DETECCAO BINARIA"
)

print(
    "  |"
)

print(
    "  +---- NORMAL ----> FINALIZA"
)

print(
    "  |"
)

print(
    "  v"
)

print(
    "ATAQUE"
)

print(
    "  |"
)

print(
    "  v"
)

print(
    "CLASSIFICADOR MULTICLASSE"
)

print(
    "  |"
)

print(
    "  v"
)

print(
    "CATEGORIA DO ATAQUE"
)

print(
    "  |"
)

print(
    "  v"
)

print(
    "ALERTA SOC"
)


# ============================================================
# FINAL
# ============================================================

titulo(
    "CYBERSENTINEL-ML"
)

print(
    "AULA 22"
)

print(
    "OTIMIZACAO MULTICLASSE"
)

print(
    status_final
)

linha()