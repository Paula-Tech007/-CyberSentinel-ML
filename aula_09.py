import json
import requests
from datetime import datetime

# ==========================================================
# AULA 09 - CLIENTE DA API ML CYBER DETECTOR
# CONSUMINDO A API DA AULA 08
# ==========================================================

print("\n========================================")
print("AULA 09 - CLIENTE DA API")
print("ML CYBER DETECTOR")
print("========================================")

# ==========================================================
# 1. CONFIGURACAO DA API
# ==========================================================

URL_API = "http://127.0.0.1:8000"
ENDPOINT_HEALTH = f"{URL_API}/health"
ENDPOINT_DETECTAR = f"{URL_API}/detectar"

print("\n========================================")
print("CONFIGURACAO")
print("========================================")

print(f"API: {URL_API}")
print(f"Endpoint de deteccao: {ENDPOINT_DETECTAR}")

# ==========================================================
# 2. VERIFICANDO SE A API ESTA ONLINE
# ==========================================================

print("\n========================================")
print("VERIFICANDO API")
print("========================================")

try:

    resposta_health = requests.get(
        ENDPOINT_HEALTH,
        timeout=5
    )

    if resposta_health.status_code == 200:

        print("API esta ONLINE!")
        print(f"Status HTTP: {resposta_health.status_code}")

    else:

        print("API respondeu, mas apresentou problema.")
        print(f"Status HTTP: {resposta_health.status_code}")

        exit()

except requests.exceptions.RequestException as erro:

    print("ERRO: nao foi possivel conectar na API.")
    print(erro)

    print("\nVerifique se a Aula 08 esta executando:")
    print("uvicorn aula_08:app --reload")

    exit()

# ==========================================================
# 3. EVENTOS EXTERNOS PARA ANALISE
# ==========================================================

eventos = [

    {
        "id_evento": "EVT-001",
        "spkts": 10,
        "dpkts": 2,
        "sbytes": 1500,
        "dbytes": 200,
        "rate": 120.0,
        "sttl": 254,
        "dttl": 64,
        "sload": 50000.0,
        "dload": 3000.0
    },

    {
        "id_evento": "EVT-002",
        "spkts": 6,
        "dpkts": 4,
        "sbytes": 258,
        "dbytes": 172,
        "rate": 74.08749,
        "sttl": 252,
        "dttl": 254,
        "sload": 14158.94238,
        "dload": 8495.365234
    },

    {
        "id_evento": "EVT-003",
        "spkts": 2,
        "dpkts": 2,
        "sbytes": 130,
        "dbytes": 162,
        "rate": 15.0,
        "sttl": 31,
        "dttl": 29,
        "sload": 1500.0,
        "dload": 900.0
    }

]

print("\n========================================")
print("EVENTOS PREPARADOS")
print("========================================")

print(f"Quantidade de eventos: {len(eventos)}")

# ==========================================================
# 4. ENVIANDO EVENTOS PARA A API
# ==========================================================

resultados = []

print("\n========================================")
print("ENVIANDO EVENTOS PARA O MODELO")
print("========================================")

for evento in eventos:

    id_evento = evento["id_evento"]

    # A API espera somente as 9 features.
    payload = {
        "spkts": evento["spkts"],
        "dpkts": evento["dpkts"],
        "sbytes": evento["sbytes"],
        "dbytes": evento["dbytes"],
        "rate": evento["rate"],
        "sttl": evento["sttl"],
        "dttl": evento["dttl"],
        "sload": evento["sload"],
        "dload": evento["dload"]
    }

    print("\n----------------------------------------")
    print(f"EVENTO: {id_evento}")
    print("----------------------------------------")

    try:

        resposta = requests.post(
            ENDPOINT_DETECTAR,
            json=payload,
            timeout=10
        )

        print(f"Status HTTP: {resposta.status_code}")

        if resposta.status_code == 200:

            resultado = resposta.json()

            print(
                "Classificacao:",
                resultado["classificacao"]
            )

            print(
                "Probabilidade:",
                f"{resultado['probabilidade_percentual']:.2f}%"
            )

            print(
                "Nivel de risco:",
                resultado["nivel_risco"]
            )

            registro = {
                "timestamp": datetime.now().isoformat(),
                "id_evento": id_evento,
                "status_http": resposta.status_code,
                "evento": payload,
                "resultado": resultado
            }

            resultados.append(registro)

        else:

            print("Erro retornado pela API:")
            print(resposta.text)

    except requests.exceptions.RequestException as erro:

        print("Falha ao enviar evento.")
        print(erro)

# ==========================================================
# 5. RESUMO
# ==========================================================

print("\n========================================")
print("RESUMO DA ANALISE")
print("========================================")

total_analisados = len(resultados)

total_ataques = sum(
    1
    for resultado in resultados
    if resultado["resultado"]["classificacao"] == "ATAQUE"
)

total_normais = sum(
    1
    for resultado in resultados
    if resultado["resultado"]["classificacao"] == "NORMAL"
)

print(f"Eventos enviados: {len(eventos)}")
print(f"Eventos analisados: {total_analisados}")
print(f"Ataques detectados: {total_ataques}")
print(f"Eventos normais: {total_normais}")

# ==========================================================
# 6. DISTRIBUICAO POR RISCO
# ==========================================================

print("\n========================================")
print("DISTRIBUICAO DE RISCO")
print("========================================")

niveis = [
    "NORMAL",
    "BAIXO",
    "MEDIO",
    "ALTO",
    "CRITICO"
]

for nivel in niveis:

    quantidade = sum(
        1
        for resultado in resultados
        if resultado["resultado"]["nivel_risco"] == nivel
    )

    print(
        f"{nivel}: {quantidade}"
    )

# ==========================================================
# 7. MOSTRANDO RESULTADOS COMPLETOS
# ==========================================================

print("\n========================================")
print("RESULTADOS RECEBIDOS DA API")
print("========================================")

for resultado in resultados:

    dados = resultado["resultado"]

    print("\n----------------------------------------")

    print(
        f"Evento: {resultado['id_evento']}"
    )

    print(
        f"Classificacao: {dados['classificacao']}"
    )

    print(
        f"Probabilidade: "
        f"{dados['probabilidade_percentual']:.2f}%"
    )

    print(
        f"Threshold: {dados['threshold']}"
    )

    print(
        f"Risco: {dados['nivel_risco']}"
    )

    print(
        f"Modelo: {dados['modelo']}"
    )

# ==========================================================
# 8. GERANDO ALERTAS SOC
# ==========================================================

alertas_soc = []

for resultado in resultados:

    dados = resultado["resultado"]

    if dados["classificacao"] == "ATAQUE":

        alerta = {

            "timestamp_alerta": datetime.now().isoformat(),

            "id_evento": resultado["id_evento"],

            "tipo_alerta": "ML_NETWORK_ATTACK",

            "origem": "API_ML_CYBER_DETECTOR",

            "modelo": dados["modelo"],

            "threshold_modelo": dados["threshold"],

            "probabilidade_ataque":
                dados["probabilidade_ataque"],

            "probabilidade_percentual":
                dados["probabilidade_percentual"],

            "nivel_risco":
                dados["nivel_risco"],

            "evento":
                resultado["evento"]
        }

        alertas_soc.append(alerta)

# ==========================================================
# 9. EXIBINDO ALERTAS
# ==========================================================

print("\n========================================")
print("ALERTAS SOC GERADOS")
print("========================================")

print(
    f"Total de alertas: {len(alertas_soc)}"
)

for alerta in alertas_soc:

    print("\n----------------------------------------")

    print(
        json.dumps(
            alerta,
            indent=4,
            ensure_ascii=False
        )
    )

# ==========================================================
# 10. SALVANDO RESULTADOS
# ==========================================================

arquivo_resultados = "alertas/resultados_api.json"

arquivo_alertas = "alertas/alertas_api.json"

try:

    with open(
        arquivo_resultados,
        "w",
        encoding="utf-8"
    ) as arquivo:

        json.dump(
            resultados,
            arquivo,
            indent=4,
            ensure_ascii=False
        )

    with open(
        arquivo_alertas,
        "w",
        encoding="utf-8"
    ) as arquivo:

        json.dump(
            alertas_soc,
            arquivo,
            indent=4,
            ensure_ascii=False
        )

    print("\n========================================")
    print("ARQUIVOS GERADOS")
    print("========================================")

    print(
        f"Resultados: {arquivo_resultados}"
    )

    print(
        f"Alertas SOC: {arquivo_alertas}"
    )

except Exception as erro:

    print("\nErro ao salvar arquivos:")
    print(erro)

# ==========================================================
# 11. RESUMO FINAL
# ==========================================================

print("\n========================================")
print("RESUMO FINAL")
print("========================================")

print(f"API utilizada: {URL_API}")
print(f"Eventos enviados: {len(eventos)}")
print(f"Eventos processados: {total_analisados}")
print(f"Ataques detectados: {total_ataques}")
print(f"Eventos normais: {total_normais}")
print(f"Alertas SOC gerados: {len(alertas_soc)}")

print("\n========================================")
print("AULA 09 CONCLUIDA")
print("CLIENTE CONSUMIU A API DE MACHINE LEARNING")
print("========================================")