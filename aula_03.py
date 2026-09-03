import pandas as pd

from sklearn.tree import DecisionTreeClassifier, export_text
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    recall_score,
    precision_score,
    f1_score
)

# ==========================================================
# 1. DATASET
# ==========================================================

dados = {
    "failed_logins": [
        1, 2, 3, 4, 2,
        5, 3, 6, 7, 4,
        8, 10, 12, 14, 9,
        15, 18, 20, 22, 25,
        28, 16, 30, 35, 12,
        40, 17, 45, 21, 11,
        3, 14
    ],

    "login_frequency": [
        1, 2, 2, 3, 1,
        4, 4, 5, 6, 3,
        7, 8, 9, 11, 8,
        10, 12, 15, 16, 20,
        21, 13, 25, 28, 10,
        30, 14, 35, 17, 9,
        12, 7
    ],

    "ip_changed": [
        0, 0, 0, 0, 1,
        0, 1, 0, 1, 0,
        0, 1, 0, 1, 0,
        1, 0, 1, 1, 1,
        1, 0, 1, 1, 1,
        1, 0, 1, 0, 1,
        0, 1
    ],

    "label": [
        0, 0, 0, 0, 0,
        0, 0, 0, 0, 0,
        0, 0, 0, 0, 0,
        1, 1, 1, 1, 1,
        1, 1, 1, 1, 1,
        1, 1, 1, 1, 1,
        0, 1
    ]
}

df = pd.DataFrame(dados)

# ==========================================================
# 2. NOVOS EXEMPLOS
# Objetivo: ensinar que IP alterado também pode ser relevante
# mesmo quando os outros valores não são altos.
# ==========================================================

novos_eventos = pd.DataFrame({
    "failed_logins": [4, 6, 8, 5],
    "login_frequency": [5, 6, 7, 4],
    "ip_changed": [1, 1, 1, 1],
    "label": [1, 1, 1, 1]
})

df = pd.concat(
    [df, novos_eventos],
    ignore_index=True
)

print("\nDATASET COMPLETO:")
print(df)

print("\nTOTAL DE EVENTOS:")
print(len(df))

# ==========================================================
# 3. ANALISANDO IP_CHANGED X LABEL
# ==========================================================

print("\nIP_CHANGED X LABEL:")

tabela_ip = pd.crosstab(
    df["ip_changed"],
    df["label"],
    margins=True
)

print(tabela_ip)

# ==========================================================
# 4. FEATURES E LABEL
# ==========================================================

X = df[
    [
        "failed_logins",
        "login_frequency",
        "ip_changed"
    ]
]

y = df["label"]

print("\nFEATURES:")
print(X)

print("\nLABEL:")
print(y)

# ==========================================================
# 5. TREINO E TESTE
# ==========================================================

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

print("\nDADOS DE TREINO:")
print(X_train)

print("\nDADOS DE TESTE:")
print(X_test)

# ==========================================================
# 6. MODELO
# ==========================================================

modelo = DecisionTreeClassifier(
    max_depth=2,
    random_state=42
)

# ==========================================================
# 7. VALIDAÇÃO CRUZADA - ACURÁCIA
# ==========================================================

resultados_cv = cross_val_score(
    modelo,
    X,
    y,
    cv=5,
    scoring="accuracy"
)

print("\nACURÁCIA NA VALIDAÇÃO CRUZADA:")
print(resultados_cv)

print("\nACURÁCIA MÉDIA:")
print(f"{resultados_cv.mean() * 100:.2f}%")

# ==========================================================
# 8. COMPARANDO PROFUNDIDADES
# ==========================================================

print("\nCOMPARANDO PROFUNDIDADES:")

for profundidade in range(1, 6):

    modelo_teste = DecisionTreeClassifier(
        max_depth=profundidade,
        random_state=42
    )

    resultados = cross_val_score(
        modelo_teste,
        X,
        y,
        cv=5,
        scoring="accuracy"
    )

    print(
        f"max_depth={profundidade} "
        f"-> média: {resultados.mean() * 100:.2f}%"
    )

# ==========================================================
# 9. RECALL NA VALIDAÇÃO CRUZADA
# ==========================================================

resultados_recall = cross_val_score(
    modelo,
    X,
    y,
    cv=5,
    scoring="recall"
)

print("\nRECALL NA VALIDAÇÃO CRUZADA:")
print(resultados_recall)

print("\nRECALL MÉDIO:")
print(f"{resultados_recall.mean() * 100:.2f}%")

# ==========================================================
# 10. PRECISION NA VALIDAÇÃO CRUZADA
# ==========================================================

resultados_precision = cross_val_score(
    modelo,
    X,
    y,
    cv=5,
    scoring="precision"
)

print("\nPRECISION NA VALIDAÇÃO CRUZADA:")
print(resultados_precision)

print("\nPRECISION MÉDIA:")
print(f"{resultados_precision.mean() * 100:.2f}%")

# ==========================================================
# 11. F1-SCORE NA VALIDAÇÃO CRUZADA
# ==========================================================

resultados_f1 = cross_val_score(
    modelo,
    X,
    y,
    cv=5,
    scoring="f1"
)

print("\nF1-SCORE NA VALIDAÇÃO CRUZADA:")
print(resultados_f1)

print("\nF1-SCORE MÉDIO:")
print(f"{resultados_f1.mean() * 100:.2f}%")

# ==========================================================
# 12. TREINAMENTO
# ==========================================================

modelo.fit(
    X_train,
    y_train
)

print("\nModelo treinado com sucesso!")

# ==========================================================
# 13. REGRA APRENDIDA
# ==========================================================

regras_arvore = export_text(
    modelo,
    feature_names=list(X.columns)
)

print("\nREGRA APRENDIDA PELA ÁRVORE:")
print(regras_arvore)

# ==========================================================
# 14. IMPORTÂNCIA DAS FEATURES
# ==========================================================

importancias = modelo.feature_importances_

print("\nIMPORTÂNCIA DAS FEATURES:")

for feature, importancia in zip(
    X.columns,
    importancias
):
    print(
        f"{feature}: "
        f"{importancia * 100:.2f}%"
    )

# ==========================================================
# 15. ACURÁCIA NO TREINO
# ==========================================================

previsoes_treino = modelo.predict(X_train)

acuracia_treino = accuracy_score(
    y_train,
    previsoes_treino
)

print("\nACURÁCIA NO TREINO:")
print(f"{acuracia_treino * 100:.2f}%")

# ==========================================================
# 16. PREVISÕES NO TESTE
# ==========================================================

previsoes = modelo.predict(X_test)

print("\nPREVISÕES DO MODELO:")
print(previsoes)

print("\nRESPOSTAS REAIS:")
print(y_test.values)

# ==========================================================
# 17. ACURÁCIA NO TESTE
# ==========================================================

acuracia = accuracy_score(
    y_test,
    previsoes
)

print("\nACURÁCIA NO TESTE:")
print(f"{acuracia * 100:.2f}%")

# ==========================================================
# 18. MATRIZ DE CONFUSÃO
# ==========================================================

matriz = confusion_matrix(
    y_test,
    previsoes
)

print("\nMATRIZ DE CONFUSÃO:")
print(matriz)

# ==========================================================
# 19. RECALL NO TESTE
# ==========================================================

recall = recall_score(
    y_test,
    previsoes,
    zero_division=0
)

print("\nRECALL NO TESTE:")
print(f"{recall * 100:.2f}%")

# ==========================================================
# 20. PRECISION NO TESTE
# ==========================================================

precision = precision_score(
    y_test,
    previsoes,
    zero_division=0
)

print("\nPRECISION NO TESTE:")
print(f"{precision * 100:.2f}%")

# ==========================================================
# 21. F1-SCORE NO TESTE
# ==========================================================

f1 = f1_score(
    y_test,
    previsoes,
    zero_division=0
)

print("\nF1-SCORE NO TESTE:")
print(f"{f1 * 100:.2f}%")

# ==========================================================
# 22. RESUMO
# ==========================================================

print("\n========================================")
print("RESUMO DO MODELO")
print("========================================")

print(
    f"Acurácia média (Cross-Validation): "
    f"{resultados_cv.mean() * 100:.2f}%"
)

print(
    f"Recall médio (Cross-Validation): "
    f"{resultados_recall.mean() * 100:.2f}%"
)

print(
    f"Precision média (Cross-Validation): "
    f"{resultados_precision.mean() * 100:.2f}%"
)

print(
    f"F1-Score médio (Cross-Validation): "
    f"{resultados_f1.mean() * 100:.2f}%"
)

print(
    f"Acurácia no treino: "
    f"{acuracia_treino * 100:.2f}%"
)

print(
    f"Acurácia no teste: "
    f"{acuracia * 100:.2f}%"
)

print(
    f"Recall no teste: "
    f"{recall * 100:.2f}%"
)

# ==========================================================
# 23. NOVO EVENTO
# ==========================================================

novo_evento = pd.DataFrame(
    [[18, 12, 1]],
    columns=[
        "failed_logins",
        "login_frequency",
        "ip_changed"
    ]
)

previsao = modelo.predict(novo_evento)

if previsao[0] == 1:
    print("\nResultado do novo evento: SUSPEITO")
else:
    print("\nResultado do novo evento: NORMAL")

    