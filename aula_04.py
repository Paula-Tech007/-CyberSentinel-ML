import os
import joblib
import pandas as pd

from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    recall_score,
    precision_score,
    f1_score,
    classification_report
)

# ==========================================================
# AULA 04
# MODELO FINAL - DETECÇÃO DE ATAQUES
# DATASET UNSW-NB15
# ==========================================================

print("\n========================================")
print("AULA 04 - MODELO FINAL")
print("DETECÇÃO DE ATAQUES COM MACHINE LEARNING")
print("========================================")

# ==========================================================
# 1. ARQUIVOS
# ==========================================================

arquivo_treino = (
    "datasets/UNSW_NB15-Complete-dataset/"
    "UNSW_NB15_training-set.csv"
)

arquivo_teste = (
    "datasets/UNSW_NB15-Complete-dataset/"
    "UNSW_NB15_testing-set.csv"
)

# ==========================================================
# 2. CARREGANDO DATASETS
# ==========================================================

treino = pd.read_csv(arquivo_treino)
teste = pd.read_csv(arquivo_teste)

print("\n========================================")
print("DATASET CARREGADO")
print("========================================")

print(f"Eventos de treino: {len(treino)}")
print(f"Eventos de teste: {len(teste)}")

# ==========================================================
# 3. FEATURES FINAIS
# ==========================================================

features = [
    "spkts",
    "dpkts",
    "sbytes",
    "dbytes",
    "rate",
    "sttl",
    "dttl",
    "sload",
    "dload"
]

print("\n========================================")
print("FEATURES DO MODELO")
print("========================================")

for numero, feature in enumerate(features, start=1):
    print(f"{numero:02d} - {feature}")

X_train = treino[features].copy()
y_train = treino["label"].copy()

X_test = teste[features].copy()
y_test = teste["label"].copy()

# ==========================================================
# 4. CONFIGURAÇÃO FINAL
# ==========================================================

MAX_DEPTH = 5
THRESHOLD = 0.099
RANDOM_STATE = 42

print("\n========================================")
print("CONFIGURAÇÃO FINAL")
print("========================================")

print("Algoritmo: Decision Tree")
print(f"max_depth: {MAX_DEPTH}")
print(f"threshold: {THRESHOLD}")
print(f"random_state: {RANDOM_STATE}")

# ==========================================================
# 5. TREINANDO MODELO
# ==========================================================

print("\n========================================")
print("TREINANDO MODELO")
print("========================================")

modelo = DecisionTreeClassifier(
    max_depth=MAX_DEPTH,
    random_state=RANDOM_STATE
)

modelo.fit(
    X_train,
    y_train
)

print("Modelo treinado com sucesso!")

# ==========================================================
# 6. CALCULANDO PROBABILIDADES
# ==========================================================

probabilidades = modelo.predict_proba(
    X_test
)[:, 1]

# ==========================================================
# 7. APLICANDO THRESHOLD FINAL
# ==========================================================

previsoes = (
    probabilidades >= THRESHOLD
).astype(int)

# ==========================================================
# 8. MÉTRICAS
# ==========================================================

acuracia = accuracy_score(
    y_test,
    previsoes
)

recall = recall_score(
    y_test,
    previsoes
)

precision = precision_score(
    y_test,
    previsoes,
    zero_division=0
)

f1 = f1_score(
    y_test,
    previsoes,
    zero_division=0
)

matriz = confusion_matrix(
    y_test,
    previsoes
)

tn, fp, fn, tp = matriz.ravel()

# ==========================================================
# 9. RESULTADO FINAL
# ==========================================================

print("\n========================================")
print("RESULTADO FINAL")
print("========================================")

print(f"Acurácia:  {acuracia * 100:.2f}%")
print(f"Recall:    {recall * 100:.2f}%")
print(f"Precision: {precision * 100:.2f}%")
print(f"F1-Score:  {f1 * 100:.2f}%")

print("\nMATRIZ DE CONFUSÃO:")
print(matriz)

print("\nDETALHAMENTO:")

print(f"Verdadeiros Negativos: {tn}")
print(f"Falsos Positivos:      {fp}")
print(f"Falsos Negativos:      {fn}")
print(f"Verdadeiros Positivos: {tp}")

# ==========================================================
# 10. RELATÓRIO DE CLASSIFICAÇÃO
# ==========================================================

print("\n========================================")
print("RELATÓRIO DE CLASSIFICAÇÃO")
print("========================================")

print(
    classification_report(
        y_test,
        previsoes,
        target_names=[
            "NORMAL",
            "ATAQUE"
        ],
        zero_division=0
    )
)

# ==========================================================
# 11. DETECÇÃO POR CATEGORIA
# ==========================================================

print("\n========================================")
print("DETECÇÃO POR CATEGORIA")
print("========================================")

analise = teste.copy()

analise["previsao"] = previsoes

analise[
    "probabilidade_ataque"
] = probabilidades

ataques = analise[
    analise["label"] == 1
]

categorias = (
    ataques["attack_cat"]
    .value_counts()
)

for categoria, total in categorias.items():

    dados_categoria = ataques[
        ataques["attack_cat"] == categoria
    ]

    detectados = (
        dados_categoria["previsao"] == 1
    ).sum()

    nao_detectados = (
        dados_categoria["previsao"] == 0
    ).sum()

    taxa = (
        detectados /
        total
    ) * 100

    print(f"\n{categoria}")

    print(
        f"Total: {total}"
    )

    print(
        f"Detectados: {detectados}"
    )

    print(
        f"Não detectados: {nao_detectados}"
    )

    print(
        f"Taxa de detecção: {taxa:.2f}%"
    )

# ==========================================================
# 12. IMPORTÂNCIA DAS FEATURES
# ==========================================================

print("\n========================================")
print("IMPORTÂNCIA DAS FEATURES")
print("========================================")

importancias = pd.DataFrame({
    "feature": features,
    "importancia":
        modelo.feature_importances_
})

importancias = importancias.sort_values(
    by="importancia",
    ascending=False
)

for _, linha in importancias.iterrows():

    print(
        f"{linha['feature']}: "
        f"{linha['importancia'] * 100:.2f}%"
    )

# ==========================================================
# 13. SALVANDO O MODELO
# ==========================================================

print("\n========================================")
print("SALVANDO MODELO")
print("========================================")

os.makedirs(
    "modelos",
    exist_ok=True
)

arquivo_modelo = (
    "modelos/"
    "unsw_decision_tree.joblib"
)

joblib.dump(
    modelo,
    arquivo_modelo
)

print(
    f"Modelo salvo em: "
    f"{arquivo_modelo}"
)

# ==========================================================
# 14. SALVANDO CONFIGURAÇÃO
# ==========================================================

configuracao = {
    "features": features,
    "threshold": THRESHOLD,
    "max_depth": MAX_DEPTH,
    "random_state": RANDOM_STATE
}

arquivo_config = (
    "modelos/"
    "configuracao_modelo.joblib"
)

joblib.dump(
    configuracao,
    arquivo_config
)

print(
    f"Configuração salva em: "
    f"{arquivo_config}"
)

# ==========================================================
# 15. TESTANDO CARREGAMENTO DO MODELO
# ==========================================================

print("\n========================================")
print("TESTANDO MODELO SALVO")
print("========================================")

modelo_carregado = joblib.load(
    arquivo_modelo
)

config_carregada = joblib.load(
    arquivo_config
)

print("Modelo carregado com sucesso!")

print(
    f"Threshold carregado: "
    f"{config_carregada['threshold']}"
)

# ==========================================================
# 16. TESTANDO UM EVENTO REAL DO DATASET
# ==========================================================

print("\n========================================")
print("TESTE COM UM NOVO EVENTO")
print("========================================")

evento = X_test.iloc[[0]]

print("\nEvento:")

print(
    evento.to_string(
        index=False
    )
)

probabilidade_evento = (
    modelo_carregado
    .predict_proba(
        evento
    )[0][1]
)

resultado_evento = int(
    probabilidade_evento >=
    config_carregada["threshold"]
)

print(
    f"\nProbabilidade de ataque: "
    f"{probabilidade_evento * 100:.2f}%"
)

if resultado_evento == 1:

    print(
        "Classificação do modelo: ATAQUE"
    )

else:

    print(
        "Classificação do modelo: NORMAL"
    )

label_real = int(
    y_test.iloc[0]
)

if label_real == 1:

    print(
        "Classificação real: ATAQUE"
    )

else:

    print(
        "Classificação real: NORMAL"
    )

# ==========================================================
# 17. RESUMO PARA O PROJETO
# ==========================================================

print("\n========================================")
print("RESUMO DO MODELO")
print("========================================")

print("Dataset: UNSW-NB15")
print("Algoritmo: Decision Tree")

print(
    f"Profundidade: "
    f"{MAX_DEPTH}"
)

print(
    f"Threshold: "
    f"{THRESHOLD}"
)

print(
    f"Features: "
    f"{len(features)}"
)

print(
    f"Acurácia: "
    f"{acuracia * 100:.2f}%"
)

print(
    f"Recall: "
    f"{recall * 100:.2f}%"
)

print(
    f"Precision: "
    f"{precision * 100:.2f}%"
)

print(
    f"F1-Score: "
    f"{f1 * 100:.2f}%"
)

print(
    f"Falsos Negativos: "
    f"{fn}"
)

print(
    f"Falsos Positivos: "
    f"{fp}"
)

# ==========================================================
# FINAL
# ==========================================================

print("\n========================================")
print("AULA 04 CONCLUÍDA")
print("MODELO TREINADO E SALVO")
print("========================================")