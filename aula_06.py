import os
import json
import joblib
import pandas as pd
from datetime import datetime

# ==========================================================
# AULA 06 - PIPELINE DE DETECCAO DE ATAQUES
# MACHINE LEARNING + ALERTAS DE SEGURANCA
# ==========================================================

print("\n========================================")
print("AULA 06 - PIPELINE DE DETECCAO")
print("MACHINE LEARNING PARA SOC")
print("========================================")

# ==========================================================
# 1. CAMINHOS
# ==========================================================

caminho_modelo = "modelos/unsw_decision_tree.joblib"
caminho_config = "modelos/configuracao_modelo.joblib"

arquivo_eventos = (
    "datasets/UNSW_NB15-Complete-dataset/"
    "UNSW_NB15_testing-set.csv"
)

pasta_saida = "alertas"

arquivo_alertas_csv = os.path.join(
    pasta_saida,
    "alertas_soc.csv"
)

arquivo_alertas_json = os.path.join(
    pasta_saida,
    "alertas_soc.json"
)

# ==========================================================
# 2. CRIANDO PASTA DE ALERTAS
# ==========================================================

os.makedirs(
    pasta_saida,
    exist_ok=True
)

print("\n========================================")
print("CARREGANDO MODELO")
print("========================================")

# ==========================================================
# 3. CARREGANDO MODELO E CONFIGURACAO
# ==========================================================

modelo = joblib.load(
    caminho_modelo
)

configuracao = joblib.load(
    caminho_config
)

threshold = configuracao["threshold"]
features = configuracao["features"]

print("Modelo carregado com sucesso!")
print(f"Threshold: {threshold}")
print(f"Quantidade de features: {len(features)}")

print("\n========================================")
print("FEATURES DO MODELO")
print("========================================")

for numero, feature in enumerate(
    features,
    start=1
):
    print(
        f"{numero:02d} - {feature}"
    )

# ==========================================================
# 4. CARREGANDO EVENTOS
# ==========================================================

print("\n========================================")
print("CARREGANDO EVENTOS DE REDE")
print("========================================")

dados = pd.read_csv(
    arquivo_eventos
)

print(
    f"Eventos disponíveis: {len(dados)}"
)

# ==========================================================
# 5. SELECIONANDO EVENTOS PARA SIMULACAO
# ==========================================================

quantidade_eventos = 500

if quantidade_eventos > len(dados):
    quantidade_eventos = len(dados)

eventos = dados.sample(
    n=quantidade_eventos,
    random_state=42
).copy()

print(
    f"Eventos selecionados para análise: "
    f"{len(eventos)}"
)

# ==========================================================
# 6. PREPARANDO FEATURES
# ==========================================================

X = eventos[features]

# ==========================================================
# 7. CALCULANDO PROBABILIDADE DE ATAQUE
# ==========================================================

print("\n========================================")
print("EXECUTANDO MODELO")
print("========================================")

probabilidades = modelo.predict_proba(
    X
)[:, 1]

eventos[
    "probabilidade_ataque"
] = probabilidades

eventos[
    "probabilidade_percentual"
] = (
    eventos["probabilidade_ataque"] * 100
).round(2)

# ==========================================================
# 8. CLASSIFICACAO PELO THRESHOLD
# ==========================================================

eventos[
    "classificacao"
] = eventos[
    "probabilidade_ataque"
].apply(
    lambda probabilidade:
    "ATAQUE"
    if probabilidade >= threshold
    else "NORMAL"
)

# ==========================================================
# 9. FUNCAO DE NIVEL DE RISCO
# ==========================================================

def calcular_risco(probabilidade):

    if probabilidade < threshold:
        return "NORMAL"

    if probabilidade < 0.30:
        return "BAIXO"

    if probabilidade < 0.70:
        return "MEDIO"

    if probabilidade < 0.90:
        return "ALTO"

    return "CRITICO"


eventos[
    "nivel_risco"
] = eventos[
    "probabilidade_ataque"
].apply(
    calcular_risco
)

# ==========================================================
# 10. COMPARANDO COM O LABEL REAL
# ==========================================================

def resultado_deteccao(linha):

    real = linha["label"]
    classificacao = linha["classificacao"]

    if real == 1 and classificacao == "ATAQUE":
        return "VERDADEIRO_POSITIVO"

    if real == 0 and classificacao == "NORMAL":
        return "VERDADEIRO_NEGATIVO"

    if real == 0 and classificacao == "ATAQUE":
        return "FALSO_POSITIVO"

    return "FALSO_NEGATIVO"


eventos[
    "resultado_deteccao"
] = eventos.apply(
    resultado_deteccao,
    axis=1
)

# ==========================================================
# 11. CRIANDO ALERTAS
# ==========================================================

alertas = eventos[
    eventos["classificacao"] == "ATAQUE"
].copy()

# ==========================================================
# 12. ADICIONANDO INFORMACOES DO ALERTA
# ==========================================================

data_execucao = datetime.now().strftime(
    "%Y-%m-%d %H:%M:%S"
)

alertas[
    "timestamp_alerta"
] = data_execucao

alertas[
    "tipo_alerta"
] = "ML_NETWORK_ATTACK"

alertas[
    "origem"
] = "UNSW-NB15"

alertas[
    "modelo"
] = "DecisionTreeClassifier"

alertas[
    "threshold_modelo"
] = threshold

# ==========================================================
# 13. RESUMO DA DETECCAO
# ==========================================================

print("\n========================================")
print("RESUMO DA DETECCAO")
print("========================================")

total = len(eventos)

ataques = (
    eventos["classificacao"] == "ATAQUE"
).sum()

normais = (
    eventos["classificacao"] == "NORMAL"
).sum()

vp = (
    eventos["resultado_deteccao"]
    == "VERDADEIRO_POSITIVO"
).sum()

vn = (
    eventos["resultado_deteccao"]
    == "VERDADEIRO_NEGATIVO"
).sum()

fp = (
    eventos["resultado_deteccao"]
    == "FALSO_POSITIVO"
).sum()

fn = (
    eventos["resultado_deteccao"]
    == "FALSO_NEGATIVO"
).sum()

print(f"Eventos analisados: {total}")
print(f"Ataques detectados: {ataques}")
print(f"Eventos normais: {normais}")

print("\nCOMPARAÇÃO COM O LABEL REAL:")

print(f"Verdadeiros Positivos: {vp}")
print(f"Verdadeiros Negativos: {vn}")
print(f"Falsos Positivos: {fp}")
print(f"Falsos Negativos: {fn}")

# ==========================================================
# 14. DISTRIBUICAO DOS NIVEIS DE RISCO
# ==========================================================

print("\n========================================")
print("DISTRIBUICAO DE RISCO")
print("========================================")

print(
    eventos[
        "nivel_risco"
    ].value_counts()
)

# ==========================================================
# 15. ALERTAS POR CATEGORIA
# ==========================================================

print("\n========================================")
print("ALERTAS POR CATEGORIA")
print("========================================")

if len(alertas) > 0:

    print(
        alertas[
            "attack_cat"
        ].value_counts()
    )

else:

    print(
        "Nenhum alerta foi gerado."
    )

# ==========================================================
# 16. ALERTAS CRITICOS
# ==========================================================

alertas_criticos = alertas[
    alertas["nivel_risco"] == "CRITICO"
]

print("\n========================================")
print("ALERTAS CRITICOS")
print("========================================")

print(
    f"Total de alertas críticos: "
    f"{len(alertas_criticos)}"
)

# ==========================================================
# 17. EXIBINDO PRIMEIROS ALERTAS
# ==========================================================

print("\n========================================")
print("PRIMEIROS 20 ALERTAS")
print("========================================")

colunas_exibicao = [
    "attack_cat",
    "label",
    "probabilidade_percentual",
    "nivel_risco",
    "resultado_deteccao"
]

if len(alertas) > 0:

    print(
        alertas[
            colunas_exibicao
        ].head(20).to_string(
            index=False
        )
    )

else:

    print(
        "Nenhum alerta disponível."
    )

# ==========================================================
# 18. SALVANDO ALERTAS EM CSV
# ==========================================================

alertas.to_csv(
    arquivo_alertas_csv,
    index=False
)

# ==========================================================
# 19. PREPARANDO ALERTAS PARA JSON
# ==========================================================

colunas_json = [
    "timestamp_alerta",
    "tipo_alerta",
    "origem",
    "modelo",
    "threshold_modelo",
    "attack_cat",
    "probabilidade_ataque",
    "probabilidade_percentual",
    "nivel_risco",
    "resultado_deteccao"
]

alertas_json = alertas[
    colunas_json
].to_dict(
    orient="records"
)

# ==========================================================
# 20. SALVANDO JSON
# ==========================================================

with open(
    arquivo_alertas_json,
    "w",
    encoding="utf-8"
) as arquivo:

    json.dump(
        alertas_json,
        arquivo,
        indent=4,
        ensure_ascii=False
    )

# ==========================================================
# 21. EXEMPLO DE ALERTA SOC
# ==========================================================

print("\n========================================")
print("EXEMPLO DE ALERTA SOC")
print("========================================")

if len(alertas_json) > 0:

    print(
        json.dumps(
            alertas_json[0],
            indent=4,
            ensure_ascii=False
        )
    )

else:

    print(
        "Nenhum alerta disponível."
    )

# ==========================================================
# 22. ARQUIVOS GERADOS
# ==========================================================

print("\n========================================")
print("ARQUIVOS GERADOS")
print("========================================")

print(
    f"CSV: {arquivo_alertas_csv}"
)

print(
    f"JSON: {arquivo_alertas_json}"
)

# ==========================================================
# FINAL
# ==========================================================

print("\n========================================")
print("AULA 06 CONCLUIDA")
print("PIPELINE DE DETECCAO EXECUTADO")
print("========================================")