# ============================================================
# CyberSentinel-ML
# AULA 21 - COMPARACAO ENTRE MODELOS DE MACHINE LEARNING
# ============================================================

import sys
import json
import time
from pathlib import Path

import numpy as np
import pandas as pd

from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
)


# ============================================================
# CONFIGURACAO GERAL
# ============================================================

PROJETO = "CyberSentinel-ML"

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

DIRETORIO_ALERTAS = BASE_DIR / "alertas"

ARQUIVO_RESULTADO = (
    DIRETORIO_ALERTAS
    / "comparacao_modelos_aula_21.json"
)


# ============================================================
# FEATURES OFICIAIS DO CYBERSENTINEL-ML
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

TARGET = "label"


# ============================================================
# FUNCOES AUXILIARES
# ============================================================

def linha():
    print("=" * 60)


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
print("AULA 21 - COMPARACAO ENTRE MODELOS ML")
print(PROJETO)
linha()


# ============================================================
# ETAPA 1 - VALIDANDO AMBIENTE
# ============================================================

titulo("ETAPA 1 - VALIDANDO AMBIENTE")

sucesso("NumPy carregado")
sucesso("Pandas carregado")
sucesso("Scikit-learn carregado")

print()
print("Modelos que serao avaliados:")
print("01 - Decision Tree")
print("02 - Random Forest")
print("03 - Logistic Regression")


# ============================================================
# ETAPA 2 - LOCALIZANDO DATASET
# ============================================================

titulo("ETAPA 2 - LOCALIZANDO DATASET UNSW-NB15")

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
# ETAPA 3 - CARREGANDO DATASETS
# ============================================================

titulo("ETAPA 3 - CARREGANDO DATASETS")

try:
    treino = pd.read_csv(ARQUIVO_TREINO)
    teste = pd.read_csv(ARQUIVO_TESTE)

except Exception as exc:
    erro(f"Falha ao carregar datasets: {exc}")
    sys.exit(1)

sucesso("Dataset de treinamento carregado")
sucesso("Dataset de teste carregado")

print()
print(f"Treinamento: {len(treino):,} registros")
print(f"Teste: {len(teste):,} registros")


# ============================================================
# ETAPA 4 - VALIDANDO FEATURES
# ============================================================

titulo("ETAPA 4 - VALIDANDO FEATURES")

COLUNAS_NECESSARIAS = FEATURES + [TARGET]

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
    erro(
        "Colunas ausentes no treinamento: "
        f"{faltando_treino}"
    )
    sys.exit(1)

if faltando_teste:
    erro(
        "Colunas ausentes no teste: "
        f"{faltando_teste}"
    )
    sys.exit(1)

sucesso("9 features encontradas")
sucesso("Target encontrado")

print()

for numero, feature in enumerate(FEATURES, start=1):
    print(f"{numero:02d} - {feature}")


# ============================================================
# ETAPA 5 - PREPARANDO DADOS
# ============================================================

titulo("ETAPA 5 - PREPARANDO DADOS")

X_train = treino[FEATURES].copy()
X_test = teste[FEATURES].copy()

y_train = treino[TARGET].copy()
y_test = teste[TARGET].copy()


# Conversao numerica

for coluna in FEATURES:

    X_train[coluna] = pd.to_numeric(
        X_train[coluna],
        errors="coerce",
    )

    X_test[coluna] = pd.to_numeric(
        X_test[coluna],
        errors="coerce",
    )


# Tratamento de infinito

X_train = X_train.replace(
    [np.inf, -np.inf],
    np.nan,
)

X_test = X_test.replace(
    [np.inf, -np.inf],
    np.nan,
)


# Tratamento de nulos

X_train = X_train.fillna(0)
X_test = X_test.fillna(0)


# Target

try:
    y_train = y_train.astype(int)
    y_test = y_test.astype(int)

except Exception as exc:
    erro(f"Falha ao converter target: {exc}")
    sys.exit(1)


if not set(y_train.unique()).issubset({0, 1}):
    erro("Target de treinamento nao e binario")
    sys.exit(1)

if not set(y_test.unique()).issubset({0, 1}):
    erro("Target de teste nao e binario")
    sys.exit(1)


sucesso("Dados preparados")
sucesso("Classificacao binaria confirmada")

print()
print(f"X_train: {X_train.shape}")
print(f"X_test:  {X_test.shape}")


# ============================================================
# DISTRIBUICAO DOS DADOS
# ============================================================

titulo("DISTRIBUICAO DAS CLASSES")

print("TREINAMENTO")

for classe, quantidade in (
    y_train.value_counts().sort_index().items()
):

    nome = "NORMAL" if classe == 0 else "ATAQUE"

    percentual = (
        quantidade / len(y_train)
    ) * 100

    print(
        f"{classe} - {nome}: "
        f"{quantidade:,} "
        f"({percentual:.2f}%)"
    )


print()
print("TESTE")

for classe, quantidade in (
    y_test.value_counts().sort_index().items()
):

    nome = "NORMAL" if classe == 0 else "ATAQUE"

    percentual = (
        quantidade / len(y_test)
    ) * 100

    print(
        f"{classe} - {nome}: "
        f"{quantidade:,} "
        f"({percentual:.2f}%)"
    )


# ============================================================
# ETAPA 6 - CONFIGURANDO MODELOS
# ============================================================

titulo("ETAPA 6 - CONFIGURANDO MODELOS")


# Decision Tree - baseline v1.0

decision_tree = DecisionTreeClassifier(
    max_depth=5,
    random_state=42,
)


# Random Forest

random_forest = RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    n_jobs=-1,
)


# Logistic Regression
#
# StandardScaler e utilizado porque Logistic Regression
# e sensivel a escalas muito diferentes entre as features.

logistic_regression = Pipeline(
    steps=[
        (
            "scaler",
            StandardScaler(),
        ),
        (
            "modelo",
            LogisticRegression(
                max_iter=2000,
                random_state=42,
            ),
        ),
    ]
)


modelos = {
    "Decision Tree": decision_tree,
    "Random Forest": random_forest,
    "Logistic Regression": logistic_regression,
}


for nome in modelos:
    sucesso(f"{nome} configurado")


# ============================================================
# ETAPA 7 - TREINAMENTO E AVALIACAO
# ============================================================

titulo("ETAPA 7 - TREINANDO E AVALIANDO MODELOS")

resultados = []


for numero, (nome, modelo) in enumerate(
    modelos.items(),
    start=1,
):

    print()
    print("-" * 60)
    print(
        f"MODELO {numero}/{len(modelos)}: "
        f"{nome}"
    )
    print("-" * 60)

    try:

        # ----------------------------------------------------
        # TREINAMENTO
        # ----------------------------------------------------

        print("Treinando modelo...")

        inicio_treino = time.perf_counter()

        modelo.fit(
            X_train,
            y_train,
        )

        fim_treino = time.perf_counter()

        tempo_treinamento = (
            fim_treino - inicio_treino
        )

        sucesso("Treinamento concluido")

        print(
            f"Tempo de treinamento: "
            f"{tempo_treinamento:.4f}s"
        )


        # ----------------------------------------------------
        # PREDICAO
        # ----------------------------------------------------

        print("Executando predicoes...")

        inicio_predicao = time.perf_counter()

        y_pred = modelo.predict(X_test)

        fim_predicao = time.perf_counter()

        tempo_predicao = (
            fim_predicao - inicio_predicao
        )

        sucesso("Predicoes concluidas")

        print(
            f"Tempo de predicao: "
            f"{tempo_predicao:.4f}s"
        )


        # ----------------------------------------------------
        # METRICAS
        # ----------------------------------------------------

        accuracy = accuracy_score(
            y_test,
            y_pred,
        )

        precision = precision_score(
            y_test,
            y_pred,
            zero_division=0,
        )

        recall = recall_score(
            y_test,
            y_pred,
            zero_division=0,
        )

        f1 = f1_score(
            y_test,
            y_pred,
            zero_division=0,
        )


        # ----------------------------------------------------
        # MATRIZ DE CONFUSAO
        # ----------------------------------------------------

        matriz = confusion_matrix(
            y_test,
            y_pred,
            labels=[0, 1],
        )

        tn, fp, fn, tp = matriz.ravel()


        # ----------------------------------------------------
        # RESULTADO
        # ----------------------------------------------------

        resultado = {
            "modelo": nome,
            "accuracy": round(
                float(accuracy * 100),
                4,
            ),
            "precision": round(
                float(precision * 100),
                4,
            ),
            "recall": round(
                float(recall * 100),
                4,
            ),
            "f1_score": round(
                float(f1 * 100),
                4,
            ),
            "verdadeiros_negativos": int(tn),
            "falsos_positivos": int(fp),
            "falsos_negativos": int(fn),
            "verdadeiros_positivos": int(tp),
            "tempo_treinamento_segundos": round(
                tempo_treinamento,
                4,
            ),
            "tempo_predicao_segundos": round(
                tempo_predicao,
                4,
            ),
        }

        resultados.append(resultado)


        # ----------------------------------------------------
        # EXIBICAO
        # ----------------------------------------------------

        print()
        print("RESULTADO:")

        print(
            f"Accuracy:  "
            f"{accuracy * 100:.2f}%"
        )

        print(
            f"Precision: "
            f"{precision * 100:.2f}%"
        )

        print(
            f"Recall:    "
            f"{recall * 100:.2f}%"
        )

        print(
            f"F1-Score:  "
            f"{f1 * 100:.2f}%"
        )

        print()
        print("Matriz de confusao:")

        print(
            f"Verdadeiros Negativos: "
            f"{tn:,}"
        )

        print(
            f"Falsos Positivos:      "
            f"{fp:,}"
        )

        print(
            f"Falsos Negativos:      "
            f"{fn:,}"
        )

        print(
            f"Verdadeiros Positivos: "
            f"{tp:,}"
        )


    except Exception as exc:

        erro(
            f"Falha no modelo {nome}: "
            f"{exc}"
        )


# ============================================================
# VALIDACAO DOS TREINAMENTOS
# ============================================================

if len(resultados) != len(modelos):

    titulo("ERRO NA COMPARACAO")

    erro(
        "Nem todos os modelos foram avaliados."
    )

    print(
        f"Esperados: {len(modelos)}"
    )

    print(
        f"Concluidos: {len(resultados)}"
    )

    sys.exit(1)


# ============================================================
# ETAPA 8 - TABELA COMPARATIVA
# ============================================================

titulo("ETAPA 8 - COMPARACAO FINAL")

df_resultados = pd.DataFrame(resultados)

colunas_tabela = [
    "modelo",
    "accuracy",
    "precision",
    "recall",
    "f1_score",
    "falsos_positivos",
    "falsos_negativos",
]

print(
    df_resultados[
        colunas_tabela
    ].to_string(
        index=False
    )
)


# ============================================================
# ETAPA 9 - RANKING
# ============================================================

titulo("ETAPA 9 - RANKING DOS MODELOS")

# Para o laboratorio SOC:
#
# 1 - menor quantidade de falsos negativos
# 2 - maior recall
# 3 - maior F1
# 4 - maior precision
#
# O objetivo e priorizar a capacidade de detectar ataques
# sem ignorar a qualidade geral da classificacao.

ranking = sorted(
    resultados,
    key=lambda item: (
        item["falsos_negativos"],
        -item["recall"],
        -item["f1_score"],
        -item["precision"],
    ),
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
        f"Recall: "
        f"{resultado['recall']:.2f}%"
    )

    print(
        f"F1-Score: "
        f"{resultado['f1_score']:.2f}%"
    )

    print(
        f"Falsos Negativos: "
        f"{resultado['falsos_negativos']:,}"
    )

    print(
        f"Falsos Positivos: "
        f"{resultado['falsos_positivos']:,}"
    )


# ============================================================
# ETAPA 10 - MODELO VENCEDOR
# ============================================================

titulo("ETAPA 10 - MODELO VENCEDOR")

vencedor = ranking[0]

print(
    f"Modelo: "
    f"{vencedor['modelo']}"
)

print(
    f"Accuracy: "
    f"{vencedor['accuracy']:.2f}%"
)

print(
    f"Precision: "
    f"{vencedor['precision']:.2f}%"
)

print(
    f"Recall: "
    f"{vencedor['recall']:.2f}%"
)

print(
    f"F1-Score: "
    f"{vencedor['f1_score']:.2f}%"
)

print(
    f"Falsos Negativos: "
    f"{vencedor['falsos_negativos']:,}"
)

print(
    f"Falsos Positivos: "
    f"{vencedor['falsos_positivos']:,}"
)


# ============================================================
# COMPARACAO COM BASELINE
# ============================================================

titulo("COMPARACAO COM O BASELINE V1.0")

baseline = next(
    item
    for item in resultados
    if item["modelo"] == "Decision Tree"
)

print("Baseline:")
print("Decision Tree | max_depth=5")

print()

if vencedor["modelo"] == "Decision Tree":

    print(
        "A Decision Tree permaneceu como melhor "
        "candidata segundo o criterio SOC utilizado."
    )

else:

    print(
        f"O modelo {vencedor['modelo']} apresentou "
        "melhor resultado segundo o criterio SOC."
    )

    print()
    print(
        "Isso NAO substitui automaticamente o "
        "modelo atual."
    )

    print(
        "A substituicao devera ser validada antes "
        "de alterar a API do CyberSentinel-ML."
    )


# ============================================================
# ETAPA 11 - SALVANDO RELATORIO
# ============================================================

titulo("ETAPA 11 - SALVANDO RELATORIO")

DIRETORIO_ALERTAS.mkdir(
    parents=True,
    exist_ok=True,
)

relatorio = {
    "projeto": PROJETO,
    "aula": 21,
    "objetivo": (
        "Comparacao entre modelos de Machine Learning "
        "para deteccao binaria de trafego."
    ),
    "dataset": "UNSW-NB15",
    "quantidade_treinamento": int(
        len(X_train)
    ),
    "quantidade_teste": int(
        len(X_test)
    ),
    "quantidade_features": len(FEATURES),
    "features": FEATURES,
    "target": TARGET,
    "baseline": {
        "modelo": "Decision Tree",
        "max_depth": 5,
    },
    "criterio_ranking": [
        "Menor quantidade de falsos negativos",
        "Maior Recall",
        "Maior F1-Score",
        "Maior Precision",
    ],
    "resultados": resultados,
    "ranking": [
        {
            "posicao": posicao,
            "modelo": item["modelo"],
            "recall": item["recall"],
            "f1_score": item["f1_score"],
            "falsos_negativos": (
                item["falsos_negativos"]
            ),
            "falsos_positivos": (
                item["falsos_positivos"]
            ),
        }
        for posicao, item in enumerate(
            ranking,
            start=1,
        )
    ],
    "modelo_vencedor": vencedor["modelo"],
    "substituicao_automatica_modelo": False,
}

try:

    with open(
        ARQUIVO_RESULTADO,
        "w",
        encoding="utf-8",
    ) as arquivo:

        json.dump(
            relatorio,
            arquivo,
            indent=4,
            ensure_ascii=False,
        )

    sucesso("Relatorio salvo")

    print(
        f"Arquivo: "
        f"{ARQUIVO_RESULTADO.relative_to(BASE_DIR)}"
    )

except Exception as exc:

    erro(
        f"Falha ao salvar relatorio: {exc}"
    )

    sys.exit(1)


# ============================================================
# ETAPA 12 - VALIDACAO FINAL
# ============================================================

titulo("ETAPA 12 - VALIDACAO FINAL")

validacoes = {
    "Dataset carregado": True,
    "9 features utilizadas": (
        len(FEATURES) == 9
    ),
    "Decision Tree treinada": (
        any(
            item["modelo"] == "Decision Tree"
            for item in resultados
        )
    ),
    "Random Forest treinada": (
        any(
            item["modelo"] == "Random Forest"
            for item in resultados
        )
    ),
    "Logistic Regression treinada": (
        any(
            item["modelo"] == "Logistic Regression"
            for item in resultados
        )
    ),
    "Metricas calculadas": (
        len(resultados) == 3
    ),
    "Ranking criado": (
        len(ranking) == 3
    ),
    "Relatorio gerado": (
        ARQUIVO_RESULTADO.exists()
    ),
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
# RESUMO FINAL
# ============================================================

titulo("RESUMO FINAL DA AULA 21")

print(
    f"Modelos avaliados: "
    f"{len(resultados)}"
)

print(
    f"Validacoes: "
    f"{validacoes_ok}/{len(validacoes)}"
)

print(
    f"Saude: "
    f"{saude:.2f}%"
)

print(
    f"Modelo vencedor: "
    f"{vencedor['modelo']}"
)

print(
    f"Recall vencedor: "
    f"{vencedor['recall']:.2f}%"
)

print(
    f"F1-Score vencedor: "
    f"{vencedor['f1_score']:.2f}%"
)

print(
    f"Falsos Negativos: "
    f"{vencedor['falsos_negativos']:,}"
)

print()
print(
    "O modelo vencedor NAO substituiu "
    "automaticamente o modelo da v1.0."
)


if saude == 100:

    status = "AULA 21 CONCLUIDA"

else:

    status = "AULA 21 COM AJUSTES"


print()
print(f"Status: {status}")


# ============================================================
# FINAL
# ============================================================

titulo("CYBERSENTINEL-ML")

print("AULA 21 - COMPARACAO ENTRE MODELOS ML")
print(status)

linha()