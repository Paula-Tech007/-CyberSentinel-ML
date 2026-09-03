import requests
import time
import json
import os
from datetime import datetime

# ==========================================================
# AULA 10 - MONITOR CONTINUO DE EVENTOS
# MACHINE LEARNING PARA SOC
# ==========================================================

print("\n========================================")
print("AULA 10 - MONITOR CONTINUO DE EVENTOS")
print("MACHINE LEARNING PARA SOC")
print("========================================")

# ==========================================================
# 1. CONFIGURACAO DA API
# ==========================================================

API_URL = "http://127.0.0.1:8000"
ENDPOINT_HEALTH = f"{API_URL}/health"
ENDPOINT_DETECCAO = f"{API_URL}/detectar"

INTERVALO_SEGUNDOS = 2

print("\n========================================")
print("CONFIGURACAO")
print("========================================")

print(f"API: {API_URL}")
print(f"Endpoint: {ENDPOINT_DETECCAO}")
print(f"Intervalo entre eventos: {INTERVALO_SEGUNDOS} segundos")

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
    print(f"Detalhes: {erro}")

    print("\nCertifique-se de que a API esteja rodando.")
    print("Exemplo:")
    print("uvicorn aula_08:app --reload")

    exit()

# ==========================================================
# 3. EVENTOS SIMULADOS
# ==========================================================

eventos = [

    {
        "id_evento": "SOC-EVT-001",
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
        "id_evento": "SOC-EVT-002",
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
        "id_evento": "SOC-EVT-003",
        "spkts": 4,
        "dpkts": 4,
        "sbytes": 500,
        "dbytes": 500,
        "rate": 1.0,
        "sttl": 31,
        "dttl": 29,
        "sload": 1000.0,
        "dload": 1000.0
    },

    {
        "id_evento": "SOC-EVT-004",
        "spkts": 20,
        "dpkts": 5,
        "sbytes": 5000,
        "dbytes": 300,
        "rate": 300.0,
        "sttl": 254,
        "dttl": 64,
        "sload": 90000.0,
        "dload": 5000.0
    },

    {
        "id_evento": "SOC-EVT-005",
        "spkts": 3,
        "dpkts": 3,
        "sbytes": 200,
        "dbytes": 250,
        "rate": 2.0,
        "sttl": 31,
        "dttl": 29,
        "sload": 800.0,
        "dload": 900.0
    }

]

print("\n========================================")
print("EVENTOS CARREGADOS")
print("========================================")

print(f"Quantidade de eventos: {len(eventos)}")

# ==========================================================
# 4. CRIANDO DIRETORIO DE ALERTAS
# ==========================================================

os.makedirs(
    "alertas",
    exist_ok=True
)

# ==========================================================
# 5. CONTADORES
# ==========================================================

total_processados = 0
total_ataques = 0
total_normais = 0
total_erros = 0

distribuicao_risco = {
    "NORMAL": 0,
    "BAIXO": 0,
    "MEDIO": 0,
    "ALTO": 0,
    "CRITICO": 0
}

resultados_monitoramento = []
alertas_soc = []

# ==========================================================
# 6. INICIANDO MONITORAMENTO
# ==========================================================

print("\n========================================")
print("INICIANDO MONITORAMENTO")
print("========================================")

print("Monitor SOC iniciado.")
print("Eventos serao enviados automaticamente para a API.")

# ==========================================================
# 7. PROCESSANDO EVENTOS
# ==========================================================

for numero, evento in enumerate(eventos, start=1):

    print("\n========================================")
    print(f"EVENTO {numero}/{len(eventos)}")
    print("========================================")

    id_evento = evento["id_evento"]

    print(f"ID: {id_evento}")
    print(
        f"Horario: "
        f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    )

    # ------------------------------------------------------
    # Removemos o ID porque a API espera somente as features
    # ------------------------------------------------------

    dados_modelo = {
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

    print("\nEnviando evento para o modelo...")

    try:

        resposta = requests.post(
            ENDPOINT_DETECCAO,
            json=dados_modelo,
            timeout=10
        )

        print(f"Status HTTP: {resposta.status_code}")

        if resposta.status_code != 200:

            print("ERRO ao processar evento.")
            print(resposta.text)

            total_erros += 1

            continue

        # ==================================================
        # 8. RECEBENDO RESULTADO
        # ==================================================

        resultado = resposta.json()

        classificacao = resultado.get(
            "classificacao",
            "DESCONHECIDO"
        )

        probabilidade = resultado.get(
            "probabilidade_ataque",
            0
        )

        probabilidade_percentual = resultado.get(
            "probabilidade_percentual",
            0
        )

        threshold = resultado.get(
            "threshold",
            0
        )

        nivel_risco = resultado.get(
            "nivel_risco",
            "DESCONHECIDO"
        )

        modelo = resultado.get(
            "modelo",
            "DESCONHECIDO"
        )

        total_processados += 1

        # ==================================================
        # 9. ATUALIZANDO CONTADORES
        # ==================================================

        if classificacao == "ATAQUE":

            total_ataques += 1

        elif classificacao == "NORMAL":

            total_normais += 1

        if nivel_risco in distribuicao_risco:

            distribuicao_risco[nivel_risco] += 1

        # ==================================================
        # 10. MOSTRANDO RESULTADO
        # ==================================================

        print("\nRESULTADO:")

        print(f"Classificacao: {classificacao}")
        print(
            f"Probabilidade: "
            f"{probabilidade_percentual:.2f}%"
        )
        print(f"Threshold: {threshold}")
        print(f"Nivel de risco: {nivel_risco}")

        # ==================================================
        # 11. REGISTRANDO RESULTADO
        # ==================================================

        registro = {

            "timestamp": datetime.now().isoformat(),

            "id_evento": id_evento,

            "classificacao": classificacao,

            "probabilidade_ataque": probabilidade,

            "probabilidade_percentual":
                probabilidade_percentual,

            "threshold": threshold,

            "nivel_risco": nivel_risco,

            "modelo": modelo,

            "evento": dados_modelo

        }

        resultados_monitoramento.append(
            registro
        )

        # ==================================================
        # 12. GERANDO ALERTA SOC
        # ==================================================

        if classificacao == "ATAQUE":

            alerta = {

                "timestamp_alerta":
                    datetime.now().isoformat(),

                "id_evento":
                    id_evento,

                "tipo_alerta":
                    "ML_NETWORK_ATTACK",

                "origem":
                    "MONITOR_CONTINUO",

                "modelo":
                    modelo,

                "threshold_modelo":
                    threshold,

                "probabilidade_ataque":
                    probabilidade,

                "probabilidade_percentual":
                    probabilidade_percentual,

                "nivel_risco":
                    nivel_risco,

                "evento":
                    dados_modelo

            }

            alertas_soc.append(
                alerta
            )

            print("\n>>> ALERTA SOC GERADO <<<")

            if nivel_risco == "CRITICO":

                print(">>> ALERTA CRITICO <<<")

        else:

            print("\nEvento considerado NORMAL.")

    except requests.exceptions.RequestException as erro:

        print("\nERRO DE COMUNICACAO COM A API")
        print(f"Detalhes: {erro}")

        total_erros += 1

    except ValueError as erro:

        print("\nERRO AO PROCESSAR JSON")
        print(f"Detalhes: {erro}")

        total_erros += 1

    # ======================================================
    # 13. SIMULANDO CHEGADA CONTINUA
    # ======================================================

    if numero < len(eventos):

        print(
            f"\nAguardando "
            f"{INTERVALO_SEGUNDOS} segundos..."
        )

        time.sleep(
            INTERVALO_SEGUNDOS
        )

# ==========================================================
# 14. SALVANDO RESULTADOS
# ==========================================================

arquivo_resultados = (
    "alertas/resultados_monitoramento.json"
)

arquivo_alertas = (
    "alertas/alertas_monitor_continuo.json"
)

with open(
    arquivo_resultados,
    "w",
    encoding="utf-8"
) as arquivo:

    json.dump(
        resultados_monitoramento,
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

# ==========================================================
# 15. RESUMO DO MONITORAMENTO
# ==========================================================

print("\n========================================")
print("RESUMO DO MONITORAMENTO")
print("========================================")

print(f"Eventos disponíveis: {len(eventos)}")
print(f"Eventos processados: {total_processados}")
print(f"Ataques detectados: {total_ataques}")
print(f"Eventos normais: {total_normais}")
print(f"Erros: {total_erros}")

# ==========================================================
# 16. DISTRIBUICAO DE RISCO
# ==========================================================

print("\n========================================")
print("DISTRIBUICAO DE RISCO")
print("========================================")

for nivel, quantidade in distribuicao_risco.items():

    print(
        f"{nivel}: "
        f"{quantidade}"
    )

# ==========================================================
# 17. ALERTAS SOC
# ==========================================================

print("\n========================================")
print("ALERTAS SOC")
print("========================================")

print(
    f"Total de alertas gerados: "
    f"{len(alertas_soc)}"
)

for alerta in alertas_soc:

    print("\n----------------------------------------")

    print(
        f"Evento: "
        f"{alerta['id_evento']}"
    )

    print(
        f"Probabilidade: "
        f"{alerta['probabilidade_percentual']:.2f}%"
    )

    print(
        f"Risco: "
        f"{alerta['nivel_risco']}"
    )

# ==========================================================
# 18. ARQUIVOS GERADOS
# ==========================================================

print("\n========================================")
print("ARQUIVOS GERADOS")
print("========================================")

print(
    f"Resultados: "
    f"{arquivo_resultados}"
)

print(
    f"Alertas SOC: "
    f"{arquivo_alertas}"
)

# ==========================================================
# 19. RESUMO DA ARQUITETURA
# ==========================================================

print("\n========================================")
print("PIPELINE EXECUTADO")
print("========================================")

print(
    "EVENTO -> MONITOR -> API -> "
    "MODELO ML -> CLASSIFICACAO -> ALERTA SOC"
)

# ==========================================================
# FINAL
# ==========================================================

print("\n========================================")
print("AULA 10 CONCLUIDA")
print("MONITOR CONTINUO EXECUTADO")
print("========================================")