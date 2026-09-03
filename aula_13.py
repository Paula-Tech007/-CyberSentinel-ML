import json
import os
from datetime import datetime
from collections import Counter, defaultdict

import requests


# ============================================================
# CONFIGURACAO
# ============================================================

API_URL = "http://127.0.0.1:8000"
ENDPOINT_DETECCAO = f"{API_URL}/detectar"

PASTA_ALERTAS = "alertas"
ARQUIVO_SAIDA = os.path.join(
    PASTA_ALERTAS,
    "incidentes_aula_13.json"
)

os.makedirs(PASTA_ALERTAS, exist_ok=True)


# ============================================================
# CABECALHO
# ============================================================

print("\n========================================")
print("AULA 13 - CORRELACAO DE EVENTOS")
print("MACHINE LEARNING PARA SOC")
print("========================================")


# ============================================================
# VERIFICAR API
# ============================================================

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
        print(f"Status HTTP: {resposta.status_code}")
    else:
        print("API respondeu, mas apresentou problema.")
        print(f"Status HTTP: {resposta.status_code}")
        raise SystemExit

except requests.exceptions.RequestException as erro:
    print("ERRO: nao foi possivel conectar com a API.")
    print(erro)
    print("\nInicie a API da Aula 08 primeiro:")
    print("uvicorn aula_08:app --reload")
    raise SystemExit


# ============================================================
# EVENTOS SIMULADOS
# ============================================================

eventos = [

    {
        "id_evento": "CORR-001",
        "ip_origem": "192.168.1.50",
        "ip_destino": "10.0.0.10",
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
        "id_evento": "CORR-002",
        "ip_origem": "192.168.1.50",
        "ip_destino": "10.0.0.20",
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
        "id_evento": "CORR-003",
        "ip_origem": "192.168.1.50",
        "ip_destino": "10.0.0.30",
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
        "id_evento": "CORR-004",
        "ip_origem": "172.16.0.25",
        "ip_destino": "10.0.0.40",
        "spkts": 2,
        "dpkts": 2,
        "sbytes": 100,
        "dbytes": 100,
        "rate": 1.0,
        "sttl": 64,
        "dttl": 64,
        "sload": 100.0,
        "dload": 100.0
    },

    {
        "id_evento": "CORR-005",
        "ip_origem": "192.168.1.50",
        "ip_destino": "10.0.0.50",
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
        "id_evento": "CORR-006",
        "ip_origem": "10.10.10.77",
        "ip_destino": "10.0.0.60",
        "spkts": 10,
        "dpkts": 2,
        "sbytes": 1500,
        "dbytes": 200,
        "rate": 120.0,
        "sttl": 254,
        "dttl": 64,
        "sload": 50000.0,
        "dload": 3000.0
    }
]


print("\n========================================")
print("EVENTOS PREPARADOS")
print("========================================")

print(f"Quantidade de eventos: {len(eventos)}")


# ============================================================
# FEATURES DO MODELO
# ============================================================

features_modelo = [
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


# ============================================================
# PROCESSAR EVENTOS
# ============================================================

resultados = []

print("\n========================================")
print("ENVIANDO EVENTOS PARA O MODELO")
print("========================================")


for evento in eventos:

    print("\n----------------------------------------")
    print(f"EVENTO: {evento['id_evento']}")
    print(f"IP origem: {evento['ip_origem']}")
    print(f"IP destino: {evento['ip_destino']}")
    print("----------------------------------------")

    dados_modelo = {
        feature: evento[feature]
        for feature in features_modelo
    }

    try:

        resposta = requests.post(
            ENDPOINT_DETECCAO,
            json=dados_modelo,
            timeout=5
        )

        print(f"Status HTTP: {resposta.status_code}")

        if resposta.status_code != 200:
            print("Erro retornado pela API.")
            continue

        resultado_api = resposta.json()

        resultado = {
            "timestamp": datetime.now().isoformat(),
            "id_evento": evento["id_evento"],
            "ip_origem": evento["ip_origem"],
            "ip_destino": evento["ip_destino"],
            "classificacao": resultado_api["classificacao"],
            "probabilidade_ataque":
                resultado_api["probabilidade_ataque"],
            "probabilidade_percentual":
                resultado_api["probabilidade_percentual"],
            "threshold":
                resultado_api["threshold"],
            "nivel_risco":
                resultado_api["nivel_risco"]
        }

        resultados.append(resultado)

        print(
            f"Classificacao: "
            f"{resultado['classificacao']}"
        )

        print(
            f"Probabilidade: "
            f"{resultado['probabilidade_percentual']:.2f}%"
        )

        print(
            f"Risco: "
            f"{resultado['nivel_risco']}"
        )

    except requests.exceptions.RequestException as erro:

        print("Erro ao enviar evento para API:")
        print(erro)


# ============================================================
# FILTRAR ALERTAS
# ============================================================

alertas = [
    resultado
    for resultado in resultados
    if resultado["classificacao"] == "ATAQUE"
]


print("\n========================================")
print("RESUMO DAS DETECCOES")
print("========================================")

print(f"Eventos processados: {len(resultados)}")
print(f"Alertas detectados: {len(alertas)}")
print(
    f"Eventos normais: "
    f"{len(resultados) - len(alertas)}"
)


# ============================================================
# AGRUPAR ALERTAS POR IP DE ORIGEM
# ============================================================

alertas_por_ip = defaultdict(list)

for alerta in alertas:

    ip = alerta["ip_origem"]

    alertas_por_ip[ip].append(alerta)


print("\n========================================")
print("CORRELACAO POR IP DE ORIGEM")
print("========================================")


for ip, lista_alertas in alertas_por_ip.items():

    print("\n----------------------------------------")
    print(f"IP origem: {ip}")
    print(f"Quantidade de alertas: {len(lista_alertas)}")

    destinos = {
        alerta["ip_destino"]
        for alerta in lista_alertas
    }

    print(f"Destinos diferentes: {len(destinos)}")

    riscos = Counter(
        alerta["nivel_risco"]
        for alerta in lista_alertas
    )

    print(f"Distribuicao de risco: {dict(riscos)}")


# ============================================================
# MOTOR DE CORRELACAO
# ============================================================

print("\n========================================")
print("EXECUTANDO CORRELATION ENGINE")
print("========================================")


incidentes = []


for ip, lista_alertas in alertas_por_ip.items():

    quantidade_alertas = len(lista_alertas)

    destinos = list(
        {
            alerta["ip_destino"]
            for alerta in lista_alertas
        }
    )

    quantidade_destinos = len(destinos)

    probabilidades = [
        alerta["probabilidade_percentual"]
        for alerta in lista_alertas
    ]

    probabilidade_media = (
        sum(probabilidades)
        / len(probabilidades)
    )

    riscos = [
        alerta["nivel_risco"]
        for alerta in lista_alertas
    ]

    quantidade_criticos = riscos.count("CRITICO")

    # --------------------------------------------------------
    # REGRA DE CORRELACAO
    #
    # 3 ou mais alertas vindos do mesmo IP
    # OU
    # 2 ou mais alertas e pelo menos um CRITICO
    # --------------------------------------------------------

    correlacionado = False
    motivo = None

    if quantidade_alertas >= 3:

        correlacionado = True

        motivo = (
            "MULTIPLOS_ALERTAS_MESMA_ORIGEM"
        )

    elif (
        quantidade_alertas >= 2
        and quantidade_criticos >= 1
    ):

        correlacionado = True

        motivo = (
            "MULTIPLOS_ALERTAS_COM_EVENTO_CRITICO"
        )

    if not correlacionado:
        continue


    # ========================================================
    # DEFINIR SEVERIDADE DO INCIDENTE
    # ========================================================

    if (
        quantidade_alertas >= 4
        or quantidade_criticos >= 2
    ):
        severidade = "CRITICO"

    elif (
        quantidade_alertas >= 3
        or quantidade_criticos >= 1
    ):
        severidade = "ALTO"

    else:
        severidade = "MEDIO"


    incidente = {

        "id_incidente":
            f"INC-{len(incidentes) + 1:03d}",

        "timestamp_incidente":
            datetime.now().isoformat(),

        "tipo_incidente":
            "ML_CORRELATED_NETWORK_ATTACK",

        "ip_origem":
            ip,

        "quantidade_alertas":
            quantidade_alertas,

        "quantidade_destinos":
            quantidade_destinos,

        "destinos":
            destinos,

        "probabilidade_media":
            round(probabilidade_media, 2),

        "alertas_criticos":
            quantidade_criticos,

        "severidade":
            severidade,

        "regra_correlacao":
            motivo,

        "eventos_relacionados": [
            alerta["id_evento"]
            for alerta in lista_alertas
        ]
    }

    incidentes.append(incidente)


# ============================================================
# MOSTRAR INCIDENTES
# ============================================================

print("\n========================================")
print("INCIDENTES SOC CORRELACIONADOS")
print("========================================")

print(
    f"Total de incidentes: "
    f"{len(incidentes)}"
)


if not incidentes:

    print("Nenhum incidente correlacionado.")

else:

    for incidente in incidentes:

        print("\n----------------------------------------")

        print(
            f"Incidente: "
            f"{incidente['id_incidente']}"
        )

        print(
            f"IP origem: "
            f"{incidente['ip_origem']}"
        )

        print(
            f"Alertas relacionados: "
            f"{incidente['quantidade_alertas']}"
        )

        print(
            f"Destinos diferentes: "
            f"{incidente['quantidade_destinos']}"
        )

        print(
            f"Probabilidade media: "
            f"{incidente['probabilidade_media']:.2f}%"
        )

        print(
            f"Alertas criticos: "
            f"{incidente['alertas_criticos']}"
        )

        print(
            f"Severidade: "
            f"{incidente['severidade']}"
        )

        print(
            f"Regra: "
            f"{incidente['regra_correlacao']}"
        )

        print(
            "Eventos: "
            + ", ".join(
                incidente["eventos_relacionados"]
            )
        )


# ============================================================
# ESTATISTICAS
# ============================================================

print("\n========================================")
print("ESTATISTICAS DA CORRELACAO")
print("========================================")

ips_com_alertas = len(alertas_por_ip)

print(
    f"IPs com alertas: "
    f"{ips_com_alertas}"
)

print(
    f"Alertas analisados: "
    f"{len(alertas)}"
)

print(
    f"Incidentes gerados: "
    f"{len(incidentes)}"
)


if incidentes:

    distribuicao_severidade = Counter(
        incidente["severidade"]
        for incidente in incidentes
    )

    print("\nDISTRIBUICAO DE SEVERIDADE:")

    for nivel in [
        "MEDIO",
        "ALTO",
        "CRITICO"
    ]:

        print(
            f"{nivel}: "
            f"{distribuicao_severidade.get(nivel, 0)}"
        )


# ============================================================
# SALVAR INCIDENTES
# ============================================================

with open(
    ARQUIVO_SAIDA,
    "w",
    encoding="utf-8"
) as arquivo:

    json.dump(
        incidentes,
        arquivo,
        indent=4,
        ensure_ascii=False
    )


print("\n========================================")
print("ARQUIVO GERADO")
print("========================================")

print(
    f"Incidentes SOC: "
    f"{ARQUIVO_SAIDA}"
)


# ============================================================
# MOSTRAR JSON DO PRIMEIRO INCIDENTE
# ============================================================

if incidentes:

    print("\n========================================")
    print("EXEMPLO DE INCIDENTE SOC")
    print("========================================")

    print(
        json.dumps(
            incidentes[0],
            indent=4,
            ensure_ascii=False
        )
    )


# ============================================================
# PIPELINE
# ============================================================

print("\n========================================")
print("PIPELINE EXECUTADO")
print("========================================")

print(
    "EVENTOS -> API ML -> ALERTAS -> "
    "CORRELACAO -> INCIDENTE SOC"
)


# ============================================================
# FINAL
# ============================================================

print("\n========================================")
print("AULA 13 CONCLUIDA")
print("CORRELACAO DE EVENTOS EXECUTADA")
print("========================================")