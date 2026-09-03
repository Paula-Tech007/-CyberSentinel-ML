import json
import os
from datetime import datetime

import joblib
import pandas as pd


# ==========================================================
# AULA 07 - DETECTOR DE EVENTOS EXTERNOS
# MACHINE LEARNING PARA SOC
# ==========================================================

print("\n========================================")
print("AULA 07 - DETECTOR DE EVENTOS EXTERNOS")
print("MACHINE LEARNING PARA SOC")
print("========================================")


# ==========================================================
# 1. CAMINHOS
# ==========================================================

caminho_modelo = "modelos/unsw_decision_tree.joblib"
caminho_configuracao = "modelos/configuracao_modelo.joblib"
caminho_evento = "evento.json"

pasta_alertas = "alertas"

os.makedirs(
    pasta_alertas,
    exist_ok=True
)


# ==========================================================
# 2. CARREGANDO MODELO
# ==========================================================

print("\n========================================")
print("CARREGANDO MODELO")
print("========================================")

modelo = joblib.load(
    caminho_modelo
)

configuracao = joblib.load(
    caminho_configuracao
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

for indice, feature in enumerate(
    features,
    start=1
):
    print(
        f"{indice:02d} - {feature}"
    )


# ==========================================================
# 4. CARREGANDO EVENTO JSON
# ==========================================================

print("\n========================================")
print("CARREGANDO EVENTO EXTERNO")
print("========================================")

if not os.path.exists(caminho_evento):

    print(
        f"ERRO: arquivo {caminho_evento} não encontrado."
    )

    raise SystemExit


with open(
    caminho_evento,
    "r",
    encoding="utf-8"
) as arquivo:

    evento = json.load(
        arquivo
    )


print("Evento JSON carregado com sucesso!")


# ==========================================================
# 5. EXIBINDO EVENTO RECEBIDO
# ==========================================================

print("\n========================================")
print("EVENTO RECEBIDO")
print("========================================")

print(
    json.dumps(
        evento,
        indent=4,
        ensure_ascii=False
    )
)


# ==========================================================
# 6. VALIDANDO FEATURES
# ==========================================================

print("\n========================================")
print("VALIDANDO EVENTO")
print("========================================")

features_ausentes = []

for feature in features:

    if feature not in evento:

        features_ausentes.append(
            feature
        )


if features_ausentes:

    print("ERRO: evento inválido.")

    print(
        "Features ausentes:"
    )

    for feature in features_ausentes:

        print(
            f"- {feature}"
        )

    raise SystemExit


print("Todas as features obrigatórias estão presentes.")


# ==========================================================
# 7. PREPARANDO EVENTO PARA O MODELO
# ==========================================================

dados_evento = {}

for feature in features:

    dados_evento[feature] = [
        evento[feature]
    ]


evento_df = pd.DataFrame(
    dados_evento
)


print("\n========================================")
print("EVENTO PREPARADO PARA O MODELO")
print("========================================")

print(
    evento_df.to_string(
        index=False
    )
)


# ==========================================================
# 8. CALCULANDO PROBABILIDADE
# ==========================================================

probabilidades = modelo.predict_proba(
    evento_df
)

probabilidade_ataque = probabilidades[0][1]

probabilidade_percentual = (
    probabilidade_ataque * 100
)


# ==========================================================
# 9. CLASSIFICAÇÃO
# ==========================================================

if probabilidade_ataque >= threshold:

    classificacao = "ATAQUE"

else:

    classificacao = "NORMAL"


# ==========================================================
# 10. NÍVEL DE RISCO
# ==========================================================

if classificacao == "NORMAL":

    nivel_risco = "NORMAL"

elif probabilidade_ataque >= 0.90:

    nivel_risco = "CRITICO"

elif probabilidade_ataque >= 0.70:

    nivel_risco = "ALTO"

elif probabilidade_ataque >= 0.40:

    nivel_risco = "MEDIO"

else:

    nivel_risco = "BAIXO"


# ==========================================================
# 11. RESULTADO
# ==========================================================

print("\n========================================")
print("RESULTADO DA ANALISE")
print("========================================")

print(
    f"Probabilidade de ataque: "
    f"{probabilidade_percentual:.2f}%"
)

print(
    f"Threshold de segurança: "
    f"{threshold}"
)

print(
    f"Classificação: "
    f"{classificacao}"
)

print(
    f"Nível de risco: "
    f"{nivel_risco}"
)


# ==========================================================
# 12. CRIANDO ALERTA SOC
# ==========================================================

alerta = {

    "timestamp_alerta":
        datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        ),

    "tipo_alerta":
        "ML_NETWORK_ATTACK",

    "origem":
        "EVENTO_EXTERNO_JSON",

    "modelo":
        "DecisionTreeClassifier",

    "threshold_modelo":
        threshold,

    "probabilidade_ataque":
        float(probabilidade_ataque),

    "probabilidade_percentual":
        round(
            probabilidade_percentual,
            2
        ),

    "classificacao":
        classificacao,

    "nivel_risco":
        nivel_risco,

    "evento":
        evento
}


# ==========================================================
# 13. EXIBINDO ALERTA
# ==========================================================

print("\n========================================")
print("ALERTA SOC")
print("========================================")

print(
    json.dumps(
        alerta,
        indent=4,
        ensure_ascii=False
    )
)


# ==========================================================
# 14. SALVANDO RESULTADO
# ==========================================================

timestamp_arquivo = datetime.now().strftime(
    "%Y%m%d_%H%M%S"
)

nome_arquivo = (
    f"alerta_evento_{timestamp_arquivo}.json"
)

caminho_alerta = os.path.join(
    pasta_alertas,
    nome_arquivo
)


with open(
    caminho_alerta,
    "w",
    encoding="utf-8"
) as arquivo:

    json.dump(
        alerta,
        arquivo,
        indent=4,
        ensure_ascii=False
    )


print("\n========================================")
print("ARQUIVO GERADO")
print("========================================")

print(
    f"Alerta salvo em: {caminho_alerta}"
)


# ==========================================================
# 15. RESUMO
# ==========================================================

print("\n========================================")
print("RESUMO DA DETECCAO")
print("========================================")

print(
    f"Classificação: {classificacao}"
)

print(
    f"Probabilidade: "
    f"{probabilidade_percentual:.2f}%"
)

print(
    f"Threshold: {threshold}"
)

print(
    f"Risco: {nivel_risco}"
)


# ==========================================================
# FINAL
# ==========================================================

print("\n========================================")
print("AULA 07 CONCLUIDA")
print("EVENTO EXTERNO PROCESSADO")
print("========================================")