import json
import os
from datetime import datetime


# ============================================================
# AULA 15 - PLAYBOOK DE RESPOSTA A INCIDENTES SOC
# RESPOSTA AUTOMATIZADA SIMULADA
# ============================================================

print("\n========================================")
print("AULA 15 - PLAYBOOK DE RESPOSTA SOC")
print("========================================")


# ============================================================
# 1. CAMINHOS
# ============================================================

PASTA_ALERTAS = "alertas"

ARQUIVO_INCIDENTES = os.path.join(
    PASTA_ALERTAS,
    "incidentes_priorizados_aula_14.json"
)

ARQUIVO_RESPOSTAS = os.path.join(
    PASTA_ALERTAS,
    "respostas_aula_15.json"
)


# ============================================================
# 2. VERIFICANDO ARQUIVO
# ============================================================

print("\n========================================")
print("CARREGANDO INCIDENTES PRIORIZADOS")
print("========================================")


if not os.path.exists(ARQUIVO_INCIDENTES):

    print(
        "ERRO: arquivo da Aula 14 nao encontrado."
    )

    print(
        f"Arquivo esperado: {ARQUIVO_INCIDENTES}"
    )

    raise SystemExit


with open(
    ARQUIVO_INCIDENTES,
    "r",
    encoding="utf-8"
) as arquivo:

    incidentes = json.load(
        arquivo
    )


print(
    f"Incidentes carregados: {len(incidentes)}"
)


# ============================================================
# 3. PLAYBOOK POR PRIORIDADE
# ============================================================

def executar_playbook(
    incidente
):

    prioridade = incidente.get(
        "prioridade",
        "P4"
    )

    ip_origem = incidente.get(
        "ip_origem",
        "DESCONHECIDO"
    )

    id_incidente = incidente.get(
        "id_incidente",
        "SEM_ID"
    )

    risk_score = incidente.get(
        "risk_score",
        0
    )


    # ========================================================
    # PRIORIDADE P1
    # ========================================================

    if prioridade == "P1":

        acao = (
            "ESCALONAR IMEDIATAMENTE PARA INCIDENT RESPONSE"
        )

        recomendacoes = [

            "Isolar o ativo relacionado ao incidente",

            "Validar bloqueio temporario do IP de origem",

            "Coletar logs adicionais",

            "Preservar evidencias",

            "Acionar equipe de resposta a incidentes"

        ]

        sla_minutos = 15

        nivel_resposta = "EMERGENCIAL"


    # ========================================================
    # PRIORIDADE P2
    # ========================================================

    elif prioridade == "P2":

        acao = (
            "ABRIR INVESTIGACAO PRIORITARIA NO SOC"
        )

        recomendacoes = [

            "Validar reputacao do IP de origem",

            "Correlacionar eventos adicionais",

            "Verificar outros destinos relacionados",

            "Pesquisar atividade anterior do IP",

            "Escalar para resposta a incidente se confirmado"

        ]

        sla_minutos = 30

        nivel_resposta = "PRIORITARIO"


    # ========================================================
    # PRIORIDADE P3
    # ========================================================

    elif prioridade == "P3":

        acao = (
            "CRIAR CASO PARA ANALISE DO SOC"
        )

        recomendacoes = [

            "Revisar logs relacionados",

            "Verificar comportamento do ativo",

            "Comparar com eventos anteriores",

            "Manter monitoramento reforcado"

        ]

        sla_minutos = 120

        nivel_resposta = "ANALISE"


    # ========================================================
    # PRIORIDADE P4
    # ========================================================

    else:

        acao = (
            "MANTER EM MONITORAMENTO"
        )

        recomendacoes = [

            "Registrar incidente",

            "Monitorar recorrencia",

            "Aguardar novos eventos relacionados"

        ]

        sla_minutos = 480

        nivel_resposta = "MONITORAMENTO"


    # ========================================================
    # RESPOSTA ESTRUTURADA
    # ========================================================

    resposta = {

        "timestamp_resposta":
            datetime.now().isoformat(),

        "id_incidente":
            id_incidente,

        "ip_origem":
            ip_origem,

        "risk_score":
            risk_score,

        "prioridade":
            prioridade,

        "nivel_resposta":
            nivel_resposta,

        "acao_principal":
            acao,

        "sla_minutos":
            sla_minutos,

        "recomendacoes":
            recomendacoes,

        "execucao_real":
            False,

        "modo":
            "SIMULACAO_SOC"

    }


    return resposta


# ============================================================
# 4. EXECUTANDO PLAYBOOKS
# ============================================================

print("\n========================================")
print("EXECUTANDO PLAYBOOKS")
print("========================================")


respostas = []


for incidente in incidentes:

    resposta = executar_playbook(
        incidente
    )

    respostas.append(
        resposta
    )


# ============================================================
# 5. MOSTRANDO RESPOSTAS
# ============================================================

print("\n========================================")
print("RESPOSTAS GERADAS")
print("========================================")


if not respostas:

    print(
        "Nenhuma resposta foi gerada."
    )


for resposta in respostas:

    print("\n----------------------------------------")

    print(
        f"Incidente: "
        f"{resposta['id_incidente']}"
    )

    print(
        f"IP origem: "
        f"{resposta['ip_origem']}"
    )

    print(
        f"Risk Score: "
        f"{resposta['risk_score']}/100"
    )

    print(
        f"Prioridade: "
        f"{resposta['prioridade']}"
    )

    print(
        f"Nivel de resposta: "
        f"{resposta['nivel_resposta']}"
    )

    print(
        f"Acao principal: "
        f"{resposta['acao_principal']}"
    )

    print(
        f"SLA: "
        f"{resposta['sla_minutos']} minutos"
    )

    print("\nRecomendacoes:")

    for numero, recomendacao in enumerate(
        resposta["recomendacoes"],
        start=1
    ):

        print(
            f"{numero}. {recomendacao}"
        )


# ============================================================
# 6. RESUMO POR PRIORIDADE
# ============================================================

print("\n========================================")
print("RESUMO POR PRIORIDADE")
print("========================================")


for prioridade in [
    "P1",
    "P2",
    "P3",
    "P4"
]:

    quantidade = sum(

        1

        for resposta in respostas

        if resposta["prioridade"]
        == prioridade

    )


    print(
        f"{prioridade}: {quantidade}"
    )


# ============================================================
# 7. RESUMO POR NIVEL DE RESPOSTA
# ============================================================

print("\n========================================")
print("RESUMO POR NIVEL DE RESPOSTA")
print("========================================")


niveis_resposta = [

    "EMERGENCIAL",
    "PRIORITARIO",
    "ANALISE",
    "MONITORAMENTO"

]


for nivel in niveis_resposta:

    quantidade = sum(

        1

        for resposta in respostas

        if resposta["nivel_resposta"]
        == nivel

    )


    print(
        f"{nivel}: {quantidade}"
    )


# ============================================================
# 8. INCIDENTES COM MENOR SLA
# ============================================================

print("\n========================================")
print("INCIDENTES MAIS URGENTES")
print("========================================")


respostas_ordenadas = sorted(

    respostas,

    key=lambda resposta:
        resposta["sla_minutos"]

)


for resposta in respostas_ordenadas:

    print(
        f"{resposta['id_incidente']} | "
        f"{resposta['prioridade']} | "
        f"SLA={resposta['sla_minutos']} min | "
        f"{resposta['acao_principal']}"
    )


# ============================================================
# 9. SALVANDO RESPOSTAS
# ============================================================

with open(
    ARQUIVO_RESPOSTAS,
    "w",
    encoding="utf-8"
) as arquivo:

    json.dump(
        respostas,
        arquivo,
        indent=4,
        ensure_ascii=False
    )


print("\n========================================")
print("ARQUIVO GERADO")
print("========================================")


print(
    f"Respostas SOC: "
    f"{ARQUIVO_RESPOSTAS}"
)


# ============================================================
# 10. MOSTRANDO JSON DO PRIMEIRO PLAYBOOK
# ============================================================

if respostas:

    print("\n========================================")
    print("EXEMPLO DE RESPOSTA SOC")
    print("========================================")


    print(
        json.dumps(
            respostas[0],
            indent=4,
            ensure_ascii=False
        )
    )


# ============================================================
# 11. PIPELINE
# ============================================================

print("\n========================================")
print("PIPELINE ATUAL")
print("========================================")


print(
    "EVENTO -> ML -> ALERTA -> CORRELACAO -> "
    "INCIDENTE -> RISK SCORE -> PRIORIDADE -> "
    "PLAYBOOK SOC"
)


# ============================================================
# FINAL
# ============================================================

print("\n========================================")
print("AULA 15 CONCLUIDA")
print("PLAYBOOK SOC EXECUTADO")
print("========================================")