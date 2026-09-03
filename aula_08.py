import joblib
import pandas as pd

from fastapi import FastAPI
from pydantic import BaseModel


# ==========================================================
# AULA 08
# API DE DETECCAO DE ATAQUES COM MACHINE LEARNING
# ==========================================================

app = FastAPI(
    title="ML Cyber Detector",
    description="API de deteccao de ataques usando Machine Learning",
    version="1.0"
)


# ==========================================================
# 1. CARREGANDO MODELO
# ==========================================================

caminho_modelo = (
    "modelos/"
    "unsw_decision_tree.joblib"
)

caminho_configuracao = (
    "modelos/"
    "configuracao_modelo.joblib"
)


modelo = joblib.load(
    caminho_modelo
)

configuracao = joblib.load(
    caminho_configuracao
)

features = configuracao[
    "features"
]

threshold = configuracao[
    "threshold"
]


print("\n========================================")
print("AULA 08 - API ML CYBER DETECTOR")
print("========================================")

print("Modelo carregado com sucesso!")
print(f"Threshold: {threshold}")
print(f"Features: {len(features)}")


# ==========================================================
# 2. ESTRUTURA DO EVENTO
# ==========================================================

class EventoRede(BaseModel):

    spkts: float
    dpkts: float
    sbytes: float
    dbytes: float
    rate: float
    sttl: float
    dttl: float
    sload: float
    dload: float


# ==========================================================
# 3. FUNCAO DE RISCO
# ==========================================================

def calcular_risco(
    probabilidade
):

    if probabilidade < threshold:

        return "NORMAL"

    elif probabilidade >= 0.90:

        return "CRITICO"

    elif probabilidade >= 0.70:

        return "ALTO"

    elif probabilidade >= 0.40:

        return "MEDIO"

    else:

        return "BAIXO"


# ==========================================================
# 4. ROTA PRINCIPAL
# ==========================================================

@app.get("/")
def inicio():

    return {
        "servico": "ML Cyber Detector",
        "status": "online",
        "modelo": "DecisionTreeClassifier",
        "threshold": threshold,
        "features": len(features)
    }


# ==========================================================
# 5. ROTA DE SAUDE
# ==========================================================

@app.get("/health")
def health():

    return {
        "status": "ok",
        "modelo_carregado": True
    }


# ==========================================================
# 6. ROTA DE DETECCAO
# ==========================================================

@app.post("/detectar")
def detectar(
    evento: EventoRede
):

    # ======================================================
    # CONVERTENDO EVENTO
    # ======================================================

    dados = evento.model_dump()

    evento_df = pd.DataFrame(
        [dados]
    )

    evento_df = evento_df[
        features
    ]

    # ======================================================
    # PROBABILIDADE DE ATAQUE
    # ======================================================

    probabilidade = (
        modelo
        .predict_proba(
            evento_df
        )[0][1]
    )

    # ======================================================
    # CLASSIFICACAO
    # ======================================================

    if probabilidade >= threshold:

        classificacao = "ATAQUE"

    else:

        classificacao = "NORMAL"

    # ======================================================
    # NIVEL DE RISCO
    # ======================================================

    nivel_risco = calcular_risco(
        probabilidade
    )

    # ======================================================
    # RESPOSTA
    # ======================================================

    resultado = {

        "classificacao":
            classificacao,

        "probabilidade_ataque":
            round(
                float(probabilidade),
                6
            ),

        "probabilidade_percentual":
            round(
                float(
                    probabilidade * 100
                ),
                2
            ),

        "threshold":
            threshold,

        "nivel_risco":
            nivel_risco,

        "modelo":
            "DecisionTreeClassifier"
    }

    return resultado


# ==========================================================
# FINAL
# ==========================================================

print("\nAPI pronta.")

print(
    "Endpoint de deteccao: "
    "POST /detectar"
)

print(
    "Documentacao automatica: "
    "/docs"
)