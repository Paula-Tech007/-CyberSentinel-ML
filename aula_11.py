import json
import time
import os
from datetime import datetime

import requests


# ==========================================================
# AULA 11 - MONITOR DE LOGS EM TEMPO REAL
# MACHINE LEARNING PARA SOC
# ==========================================================

print("\n========================================")
print("AULA 11 - MONITOR DE LOGS EM TEMPO REAL")
print("MACHINE LEARNING PARA SOC")
print("========================================")


# ==========================================================
# 1. CONFIGURACAO
# ==========================================================

API_URL = "http://127.0.0.1:8000"
ENDPOINT_DETECCAO = f"{API_URL}/detectar"

ARQUIVO_EVENTOS = "eventos/eventos_rede.jsonl"

PASTA_ALERTAS = "alertas"

ARQUIVO_RESULTADOS = os.path.join(
    PASTA_ALERTAS,
    "resultados_aula_11.json"
)

ARQUIVO_ALERTAS = os.path.join(
    PASTA_ALERTAS,
    "alertas_aula_11.json"
)

INTERVALO = 1


print("\n========================================")
print("CONFIGURACAO")
print("========================================")

print(f"API: {API_URL}")
print(f"Endpoint: {ENDPOINT_DETECCAO}")
print(f"Arquivo monitorado: {ARQUIVO_EVENTOS}")
print(f"Intervalo: {INTERVALO} segundo")


# ==========================================================
# 2. CRIANDO DIRETORIOS
# ==========================================================

os.makedirs(
    "eventos",
    exist_ok=True
)

os.makedirs(
    PASTA_ALERTAS,
    exist_ok=True
)


# ==========================================================
# 3. CRIANDO ARQUIVO DE EVENTOS DE EXEMPLO
# ==========================================================

if not os.path.exists(ARQUIVO_EVENTOS):

    eventos_exemplo = [

        {
            "id_evento": "LOG-001",
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
            "id_evento": "LOG-002",
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
            "id_evento": "LOG-003",
            "spkts": 4,
            "dpkts": 4,
            "sbytes": 300,
            "dbytes": 300,
            "rate": 5.0,
            "sttl": 31,
            "dttl": 29,
            "sload": 1000.0,
            "dload": 1000.0
        },

        {
            "id_evento": "LOG-004",
            "spkts": 20,
            "dpkts": 5,
            "sbytes": 5000,
            "dbytes": 500,
            "rate": 250.0,
            "sttl": 254,
            "dttl": 64,
            "sload": 80000.0,
            "dload": 5000.0
        },

        {
            "id_evento": "LOG-005",
            "spkts": 3,
            "dpkts": 3,
            "sbytes": 200,
            "dbytes": 250,
            "rate": 3.0,
            "sttl": 31,
            "dttl": 29,
            "sload": 800.0,
            "dload": 900.0
        }
    ]

    with open(
        ARQUIVO_EVENTOS,
        "w",
        encoding="utf-8"
    ) as arquivo:

        for evento in eventos_exemplo:

            arquivo.write(
                json.dumps(evento) + "\n"
            )

    print("\n========================================")
    print("ARQUIVO DE EVENTOS CRIADO")
    print("========================================")

    print(
        f"Arquivo criado em: {ARQUIVO_EVENTOS}"
    )

    print(
        f"Eventos adicionados: {len(eventos_exemplo)}"
    )


# ==========================================================
# 4. VERIFICANDO API
# ==========================================================

print("\n========================================")
print("VERIFICANDO API")
print("========================================")

try:

    resposta = requests.get(
        f"{API_URL}/health",
        timeout=5
    )

    if resposta.status_code == 200:

        print("API esta ONLINE!")
        print(
            f"Status HTTP: {resposta.status_code}"
        )

    else:

        print("API respondeu com erro.")
        print(
            f"Status HTTP: {resposta.status_code}"
        )

        exit()

except requests.exceptions.RequestException as erro:

    print("Nao foi possivel conectar com a API.")
    print(f"Erro: {erro}")

    print("\nExecute a API em outro terminal:")
    print("uvicorn api:app --reload")

    exit()


# ==========================================================
# 5. CARREGANDO EVENTOS DO ARQUIVO
# ==========================================================

print("\n========================================")
print("LENDO ARQUIVO DE EVENTOS")
print("========================================")

eventos = []

with open(
    ARQUIVO_EVENTOS,
    "r",
    encoding="utf-8"
) as arquivo:

    for numero_linha, linha in enumerate(
        arquivo,
        start=1
    ):

        linha = linha.strip()

        if not linha:
            continue

        try:

            evento = json.loads(linha)

            eventos.append(evento)

        except json.JSONDecodeError:

            print(
                f"Linha {numero_linha} possui JSON invalido."
            )


print(f"Eventos encontrados: {len(eventos)}")


# ==========================================================
# 6. VARIAVEIS DO MONITORAMENTO
# ==========================================================

resultados = []

alertas = []

eventos_processados = 0

ataques_detectados = 0

eventos_normais = 0

erros = 0


distribuicao_risco = {

    "NORMAL": 0,
    "BAIXO": 0,
    "MEDIO": 0,
    "ALTO": 0,
    "CRITICO": 0

}


# ==========================================================
# 7. INICIANDO MONITORAMENTO
# ==========================================================

print("\n========================================")
print("INICIANDO MONITORAMENTO")
print("========================================")

print("Monitor de logs iniciado.")
print("Eventos serao enviados para a API.")
print("")


# ==========================================================
# 8. PROCESSANDO EVENTOS
# ==========================================================

for indice, evento_original in enumerate(
    eventos,
    start=1
):

    print("\n========================================")
    print(
        f"EVENTO {indice}/{len(eventos)}"
    )
    print("========================================")

    id_evento = evento_original.get(
        "id_evento",
        f"LOG-{indice:03d}"
    )

    print(f"ID: {id_evento}")

    print(
        "Horario:",
        datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )
    )


    # ======================================================
    # PREPARANDO EVENTO PARA A API
    # ======================================================

    evento_modelo = {

        "spkts": evento_original.get("spkts"),
        "dpkts": evento_original.get("dpkts"),
        "sbytes": evento_original.get("sbytes"),
        "dbytes": evento_original.get("dbytes"),
        "rate": evento_original.get("rate"),
        "sttl": evento_original.get("sttl"),
        "dttl": evento_original.get("dttl"),
        "sload": evento_original.get("sload"),
        "dload": evento_original.get("dload")

    }


    print("\nEnviando evento para o modelo...")


    # ======================================================
    # ENVIANDO EVENTO PARA API
    # ======================================================

    try:

        resposta = requests.post(
            ENDPOINT_DETECCAO,
            json=evento_modelo,
            timeout=10
        )

        print(
            f"Status HTTP: {resposta.status_code}"
        )


        if resposta.status_code != 200:

            print("Erro ao processar evento.")

            try:

                print(
                    json.dumps(
                        resposta.json(),
                        indent=4,
                        ensure_ascii=False
                    )
                )

            except Exception:

                print(resposta.text)

            erros += 1

            continue


        # ==================================================
        # RESULTADO DA API
        # ==================================================

        resultado_api = resposta.json()

        classificacao = resultado_api.get(
            "classificacao"
        )

        probabilidade = resultado_api.get(
            "probabilidade_ataque",
            0
        )

        probabilidade_percentual = resultado_api.get(
            "probabilidade_percentual",
            0
        )

        threshold = resultado_api.get(
            "threshold"
        )

        nivel_risco = resultado_api.get(
            "nivel_risco",
            "DESCONHECIDO"
        )

        modelo = resultado_api.get(
            "modelo",
            "DESCONHECIDO"
        )


        eventos_processados += 1


        # ==================================================
        # CONTADORES
        # ==================================================

        if classificacao == "ATAQUE":

            ataques_detectados += 1

        else:

            eventos_normais += 1


        if nivel_risco in distribuicao_risco:

            distribuicao_risco[nivel_risco] += 1


        # ==================================================
        # EXIBINDO RESULTADO
        # ==================================================

        print("\nRESULTADO:")

        print(
            f"Classificacao: {classificacao}"
        )

        print(
            f"Probabilidade: "
            f"{probabilidade_percentual:.2f}%"
        )

        print(
            f"Threshold: {threshold}"
        )

        print(
            f"Nivel de risco: {nivel_risco}"
        )


        # ==================================================
        # REGISTRANDO RESULTADO
        # ==================================================

        registro_resultado = {

            "timestamp": datetime.now().isoformat(),

            "id_evento": id_evento,

            "classificacao": classificacao,

            "probabilidade_ataque": probabilidade,

            "probabilidade_percentual":
                probabilidade_percentual,

            "threshold": threshold,

            "nivel_risco": nivel_risco,

            "modelo": modelo,

            "evento": evento_modelo

        }

        resultados.append(
            registro_resultado
        )


        # ==================================================
        # GERANDO ALERTA SOC
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
                    "MONITOR_JSONL",

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
                    evento_modelo

            }


            alertas.append(
                alerta
            )


            print(
                "\n>>> ALERTA SOC GERADO <<<"
            )


            if nivel_risco == "CRITICO":

                print(
                    ">>> ALERTA CRITICO <<<"
                )


        else:

            print(
                "\nEvento considerado NORMAL."
            )


    except requests.exceptions.RequestException as erro:

        erros += 1

        print(
            "\nErro de comunicacao com a API."
        )

        print(
            f"Detalhes: {erro}"
        )


    # ======================================================
    # SIMULANDO CHEGADA CONTINUA DOS LOGS
    # ======================================================

    if indice < len(eventos):

        print(
            f"\nAguardando {INTERVALO} segundo..."
        )

        time.sleep(
            INTERVALO
        )


# ==========================================================
# 9. SALVANDO RESULTADOS
# ==========================================================

with open(
    ARQUIVO_RESULTADOS,
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
    ARQUIVO_ALERTAS,
    "w",
    encoding="utf-8"
) as arquivo:

    json.dump(
        alertas,
        arquivo,
        indent=4,
        ensure_ascii=False
    )


# ==========================================================
# 10. RESUMO DO MONITORAMENTO
# ==========================================================

print("\n========================================")
print("RESUMO DO MONITORAMENTO")
print("========================================")

print(
    f"Eventos encontrados: {len(eventos)}"
)

print(
    f"Eventos processados: {eventos_processados}"
)

print(
    f"Ataques detectados: {ataques_detectados}"
)

print(
    f"Eventos normais: {eventos_normais}"
)

print(
    f"Erros: {erros}"
)


# ==========================================================
# 11. DISTRIBUICAO DE RISCO
# ==========================================================

print("\n========================================")
print("DISTRIBUICAO DE RISCO")
print("========================================")

for nivel, quantidade in distribuicao_risco.items():

    print(
        f"{nivel}: {quantidade}"
    )


# ==========================================================
# 12. ALERTAS SOC
# ==========================================================

print("\n========================================")
print("ALERTAS SOC")
print("========================================")

print(
    f"Total de alertas gerados: {len(alertas)}"
)


for alerta in alertas:

    print("\n----------------------------------------")

    print(
        f"Evento: {alerta['id_evento']}"
    )

    print(
        f"Probabilidade: "
        f"{alerta['probabilidade_percentual']:.2f}%"
    )

    print(
        f"Risco: {alerta['nivel_risco']}"
    )


# ==========================================================
# 13. ARQUIVOS GERADOS
# ==========================================================

print("\n========================================")
print("ARQUIVOS GERADOS")
print("========================================")

print(
    f"Resultados: {ARQUIVO_RESULTADOS}"
)

print(
    f"Alertas SOC: {ARQUIVO_ALERTAS}"
)


# ==========================================================
# 14. PIPELINE
# ==========================================================

print("\n========================================")
print("PIPELINE EXECUTADO")
print("========================================")

print(
    "JSONL -> MONITOR -> API -> MODELO ML "
    "-> CLASSIFICACAO -> ALERTA SOC"
)


# ==========================================================
# FINAL
# ==========================================================

print("\n========================================")
print("AULA 11 CONCLUIDA")
print("MONITOR DE LOGS EXECUTADO")
print("========================================")