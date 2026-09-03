import joblib
import pandas as pd

# ==========================================================
# AULA 05.2
# DETECTOR DE ATAQUES EM LOTE
# USANDO O MODELO TREINADO NA AULA 04
# ==========================================================

print("\n========================================")
print("AULA 05.2 - DETECTOR EM LOTE")
print("========================================")

# ==========================================================
# 1. CAMINHOS DOS ARQUIVOS
# ==========================================================

arquivo_modelo = "modelos/unsw_decision_tree.joblib"

arquivo_configuracao = (
    "modelos/configuracao_modelo.joblib"
)

arquivo_teste = (
    "datasets/UNSW_NB15-Complete-dataset/"
    "UNSW_NB15_testing-set.csv"
)

# ==========================================================
# 2. CARREGANDO MODELO E CONFIGURAÇÃO
# ==========================================================

print("\n========================================")
print("CARREGANDO MODELO")
print("========================================")

modelo = joblib.load(
    arquivo_modelo
)

configuracao = joblib.load(
    arquivo_configuracao
)

threshold = configuracao["threshold"]
features = configuracao["features"]

print("Modelo carregado com sucesso!")
print(f"Threshold: {threshold}")
print(f"Quantidade de features: {len(features)}")

# ==========================================================
# 3. FEATURES ESPERADAS
# ==========================================================

print("\n========================================")
print("FEATURES ESPERADAS")
print("========================================")

for numero, feature in enumerate(
    features,
    start=1
):
    print(
        f"{numero:02d} - {feature}"
    )

# ==========================================================
# 4. CARREGANDO EVENTOS DO DATASET
# ==========================================================

print("\n========================================")
print("CARREGANDO EVENTOS")
print("========================================")

dados = pd.read_csv(
    arquivo_teste
)

print(
    f"Eventos disponíveis: {len(dados)}"
)

# ==========================================================
# 5. SELECIONANDO EVENTOS PARA ANÁLISE
# ==========================================================
#
# Nesta etapa analisaremos 100 eventos.
#
# Usamos sample() em vez de head() para pegar eventos
# espalhados pelo dataset.
#
# random_state=42 garante que a amostra seja sempre igual.
#
# ==========================================================

QUANTIDADE_EVENTOS = 100

eventos = dados.sample(
    n=QUANTIDADE_EVENTOS,
    random_state=42
).copy()

eventos = eventos.reset_index(
    drop=True
)

print(
    f"Eventos selecionados: {len(eventos)}"
)

# ==========================================================
# 6. PREPARANDO AS FEATURES
# ==========================================================

X_eventos = eventos[
    features
].copy()

# ==========================================================
# 7. EXECUTANDO O MODELO
# ==========================================================

print("\n========================================")
print("EXECUTANDO DETECTOR")
print("========================================")

probabilidades = modelo.predict_proba(
    X_eventos
)[:, 1]

# ==========================================================
# 8. APLICANDO THRESHOLD
# ==========================================================

previsoes = (
    probabilidades >= threshold
).astype(int)

# ==========================================================
# 9. ADICIONANDO RESULTADOS
# ==========================================================

eventos[
    "probabilidade_ataque"
] = probabilidades

eventos[
    "probabilidade_percentual"
] = (
    probabilidades * 100
).round(2)

eventos[
    "previsao"
] = previsoes

eventos[
    "classificacao"
] = eventos[
    "previsao"
].map({
    0: "NORMAL",
    1: "ATAQUE"
})

# ==========================================================
# 10. DEFININDO NÍVEL DE RISCO
# ==========================================================

def calcular_risco(probabilidade):

    # Evento abaixo do threshold
    if probabilidade < threshold:
        return "NORMAL"

    # Evento classificado como ataque
    if probabilidade >= 0.90:
        return "CRITICO"

    elif probabilidade >= 0.70:
        return "ALTO"

    elif probabilidade >= 0.30:
        return "MEDIO"

    else:
        return "BAIXO"


eventos[
    "nivel_risco"
] = eventos[
    "probabilidade_ataque"
].apply(
    calcular_risco
)

# ==========================================================
# 11. COMPARANDO COM O RESULTADO REAL
# ==========================================================
#
# Isso é possível porque ainda estamos trabalhando
# com o dataset de laboratório.
#
# Em produção não teremos o label real no momento
# em que o evento chegar.
#
# ==========================================================

def avaliar_resultado(linha):

    real = int(
        linha["label"]
    )

    previsao = int(
        linha["previsao"]
    )

    if real == 1 and previsao == 1:
        return "VERDADEIRO_POSITIVO"

    elif real == 0 and previsao == 0:
        return "VERDADEIRO_NEGATIVO"

    elif real == 0 and previsao == 1:
        return "FALSO_POSITIVO"

    elif real == 1 and previsao == 0:
        return "FALSO_NEGATIVO"

    return "DESCONHECIDO"


eventos[
    "resultado_deteccao"
] = eventos.apply(
    avaliar_resultado,
    axis=1
)

# ==========================================================
# 12. CONTANDO CLASSIFICAÇÕES
# ==========================================================

total_eventos = len(
    eventos
)

total_ataques = (
    eventos["previsao"] == 1
).sum()

total_normais = (
    eventos["previsao"] == 0
).sum()

verdadeiros_positivos = (
    eventos["resultado_deteccao"]
    == "VERDADEIRO_POSITIVO"
).sum()

verdadeiros_negativos = (
    eventos["resultado_deteccao"]
    == "VERDADEIRO_NEGATIVO"
).sum()

falsos_positivos = (
    eventos["resultado_deteccao"]
    == "FALSO_POSITIVO"
).sum()

falsos_negativos = (
    eventos["resultado_deteccao"]
    == "FALSO_NEGATIVO"
).sum()

# ==========================================================
# 13. RESUMO DA DETECÇÃO
# ==========================================================

print("\n========================================")
print("RESUMO DA DETECÇÃO")
print("========================================")

print(
    f"Eventos analisados: "
    f"{total_eventos}"
)

print(
    f"Classificados como ATAQUE: "
    f"{total_ataques}"
)

print(
    f"Classificados como NORMAL: "
    f"{total_normais}"
)

print("\nCOMPARAÇÃO COM O LABEL REAL:")

print(
    f"Verdadeiros Positivos: "
    f"{verdadeiros_positivos}"
)

print(
    f"Verdadeiros Negativos: "
    f"{verdadeiros_negativos}"
)

print(
    f"Falsos Positivos: "
    f"{falsos_positivos}"
)

print(
    f"Falsos Negativos: "
    f"{falsos_negativos}"
)

# ==========================================================
# 14. DISTRIBUIÇÃO DOS NÍVEIS DE RISCO
# ==========================================================

print("\n========================================")
print("DISTRIBUIÇÃO DE RISCO")
print("========================================")

distribuicao_risco = eventos[
    "nivel_risco"
].value_counts()

print(
    distribuicao_risco
)

# ==========================================================
# 15. MOSTRANDO OS PRIMEIROS RESULTADOS
# ==========================================================

print("\n========================================")
print("PRIMEIROS 20 RESULTADOS")
print("========================================")

colunas_resultado = [
    "attack_cat",
    "label",
    "probabilidade_percentual",
    "classificacao",
    "nivel_risco",
    "resultado_deteccao"
]

print(
    eventos[
        colunas_resultado
    ].head(20).to_string(
        index=False
    )
)

# ==========================================================
# 16. SEPARANDO OS ALERTAS
# ==========================================================

alertas = eventos[
    eventos["previsao"] == 1
].copy()

print("\n========================================")
print("ALERTAS")
print("========================================")

print(
    f"Total de alertas gerados: "
    f"{len(alertas)}"
)

# ==========================================================
# 17. EVENTOS CRÍTICOS
# ==========================================================

eventos_criticos = eventos[
    eventos["nivel_risco"]
    == "CRITICO"
].copy()

print(
    f"Alertas críticos: "
    f"{len(eventos_criticos)}"
)

# ==========================================================
# 18. SALVANDO RESULTADO COMPLETO
# ==========================================================

arquivo_resultado = (
    "resultado_detector.csv"
)

eventos[
    colunas_resultado
].to_csv(
    arquivo_resultado,
    index=False
)

# ==========================================================
# 19. SALVANDO SOMENTE OS ALERTAS
# ==========================================================

arquivo_alertas = (
    "alertas_detectados.csv"
)

alertas[
    colunas_resultado
].to_csv(
    arquivo_alertas,
    index=False
)

# ==========================================================
# 20. CONFIRMANDO ARQUIVOS GERADOS
# ==========================================================

print("\n========================================")
print("ARQUIVOS GERADOS")
print("========================================")

print(
    f"Resultado completo: "
    f"{arquivo_resultado}"
)

print(
    f"Somente alertas: "
    f"{arquivo_alertas}"
)

# ==========================================================
# FINAL
# ==========================================================

print("\n========================================")
print("AULA 05.2 CONCLUÍDA")
print("DETECÇÃO EM LOTE EXECUTADA")
print("========================================")