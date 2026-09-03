import json
import os
from datetime import datetime


# ============================================================
# AULA 18 - GESTAO DE CASOS SOC
# CASE MANAGEMENT
# ============================================================

print("\n========================================")
print("AULA 18 - GESTAO DE CASOS SOC")
print("========================================")


# ============================================================
# 1. CAMINHOS
# ============================================================

PASTA_ALERTAS = "alertas"

ARQUIVO_DECISOES = os.path.join(
    PASTA_ALERTAS,
    "decisoes_aula_17.json"
)

ARQUIVO_CASOS = os.path.join(
    PASTA_ALERTAS,
    "casos_aula_18.json"
)


# ============================================================
# 2. CARREGANDO DECISOES DA AULA 17
# ============================================================

print("\n========================================")
print("CARREGANDO DECISOES SOC")
print("========================================")


if not os.path.exists(ARQUIVO_DECISOES):

    print(
        "ERRO: arquivo da Aula 17 nao encontrado."
    )

    print(
        f"Arquivo esperado: {ARQUIVO_DECISOES}"
    )

    raise SystemExit


with open(
    ARQUIVO_DECISOES,
    "r",
    encoding="utf-8"
) as arquivo:

    decisoes = json.load(
        arquivo
    )


print(
    f"Decisoes carregadas: {len(decisoes)}"
)


# ============================================================
# 3. DEFINIR RESPONSAVEL
# ============================================================

def definir_responsavel(
    prioridade
):

    if prioridade == "P1":

        return "INCIDENT_RESPONSE"

    elif prioridade == "P2":

        return "SOC_L2"

    elif prioridade == "P3":

        return "SOC_L1"

    else:

        return "MONITORAMENTO_SOC"


# ============================================================
# 4. DEFINIR FILA
# ============================================================

def definir_fila(
    prioridade
):

    if prioridade == "P1":

        return "IR_CRITICO"

    elif prioridade == "P2":

        return "SOC_PRIORITARIO"

    elif prioridade == "P3":

        return "SOC_ANALISE"

    else:

        return "SOC_MONITORAMENTO"


# ============================================================
# 5. STATUS INICIAL
# ============================================================

def definir_status_inicial(
    prioridade
):

    if prioridade in [
        "P1",
        "P2"
    ]:

        return "ABERTO"

    elif prioridade == "P3":

        return "EM_ANALISE"

    else:

        return "MONITORAMENTO"


# ============================================================
# 6. CRIANDO CASOS SOC
# ============================================================

print("\n========================================")
print("CRIANDO CASOS SOC")
print("========================================")


casos = []


for indice, decisao in enumerate(
    decisoes,
    start=1
):

    prioridade = decisao.get(
        "prioridade_final",
        "P4"
    )

    responsavel = definir_responsavel(
        prioridade
    )

    fila = definir_fila(
        prioridade
    )

    status = definir_status_inicial(
        prioridade
    )

    agora = datetime.now().isoformat()

    id_caso = (
        f"CASE-{indice:03d}"
    )


    # ========================================================
    # HISTORICO INICIAL
    # ========================================================

    historico = [

        {
            "timestamp": agora,
            "acao": "CASO_CRIADO",
            "responsavel": "MOTOR_SOC",
            "descricao":
                "Caso criado automaticamente "
                "a partir da decisao final SOC"
        },

        {
            "timestamp": agora,
            "acao": "ATRIBUICAO_AUTOMATICA",
            "responsavel": responsavel,
            "descricao":
                f"Caso atribuido para {responsavel}"
        }

    ]


    # ========================================================
    # EVIDENCIAS
    # ========================================================

    evidencias = {

        "ip_origem":
            decisao.get(
                "ip_origem"
            ),

        "risk_score":
            decisao.get(
                "risk_score"
            ),

        "context_score":
            decisao.get(
                "context_score"
            ),

        "score_reputacao":
            decisao.get(
                "score_reputacao"
            ),

        "probabilidade_media":
            decisao.get(
                "probabilidade_media"
            ),

        "alertas_criticos":
            decisao.get(
                "alertas_criticos"
            ),

        "quantidade_alertas":
            decisao.get(
                "quantidade_alertas"
            ),

        "quantidade_destinos":
            decisao.get(
                "quantidade_destinos"
            ),

        "recorrencia":
            decisao.get(
                "recorrencia"
            )

    }


    # ========================================================
    # CASO
    # ========================================================

    caso = {

        "id_caso":
            id_caso,

        "id_incidente":
            decisao.get(
                "id_incidente"
            ),

        "timestamp_abertura":
            agora,

        "status":
            status,

        "prioridade":
            prioridade,

        "severidade":
            decisao.get(
                "severidade_final"
            ),

        "score_final":
            decisao.get(
                "score_final"
            ),

        "fila":
            fila,

        "responsavel":
            responsavel,

        "sla_minutos":
            decisao.get(
                "sla_final_minutos"
            ),

        "acao_recomendada":
            decisao.get(
                "acao_final"
            ),

        "decisao_soc":
            decisao.get(
                "decisao"
            ),

        "status_decisao":
            decisao.get(
                "status"
            ),

        "evidencias":
            evidencias,

        "historico":
            historico,

        "execucao_real":
            False,

        "modo":
            "CASE_MANAGEMENT_SIMULADO"

    }


    casos.append(
        caso
    )


# ============================================================
# 7. MOSTRANDO CASOS
# ============================================================

print("\n========================================")
print("CASOS SOC CRIADOS")
print("========================================")


if not casos:

    print(
        "Nenhum caso foi criado."
    )


for caso in casos:

    print("\n----------------------------------------")

    print(
        f"Caso: "
        f"{caso['id_caso']}"
    )

    print(
        f"Incidente: "
        f"{caso['id_incidente']}"
    )

    print(
        f"Status: "
        f"{caso['status']}"
    )

    print(
        f"Prioridade: "
        f"{caso['prioridade']}"
    )

    print(
        f"Severidade: "
        f"{caso['severidade']}"
    )

    print(
        f"Score FINAL: "
        f"{caso['score_final']}/100"
    )

    print(
        f"Fila: "
        f"{caso['fila']}"
    )

    print(
        f"Responsavel: "
        f"{caso['responsavel']}"
    )

    print(
        f"SLA: "
        f"{caso['sla_minutos']} minutos"
    )

    print(
        f"Acao recomendada: "
        f"{caso['acao_recomendada']}"
    )


# ============================================================
# 8. MOSTRANDO EVIDENCIAS
# ============================================================

print("\n========================================")
print("EVIDENCIAS DOS CASOS")
print("========================================")


for caso in casos:

    print("\n----------------------------------------")

    print(
        f"Caso: {caso['id_caso']}"
    )

    print(
        json.dumps(
            caso["evidencias"],
            indent=4,
            ensure_ascii=False
        )
    )


# ============================================================
# 9. HISTORICO DOS CASOS
# ============================================================

print("\n========================================")
print("HISTORICO DOS CASOS")
print("========================================")


for caso in casos:

    print("\n----------------------------------------")

    print(
        f"Caso: {caso['id_caso']}"
    )

    for entrada in caso[
        "historico"
    ]:

        print(
            f"{entrada['timestamp']} | "
            f"{entrada['acao']} | "
            f"{entrada['responsavel']} | "
            f"{entrada['descricao']}"
        )


# ============================================================
# 10. RESUMO POR STATUS
# ============================================================

print("\n========================================")
print("RESUMO POR STATUS")
print("========================================")


status_possiveis = [

    "ABERTO",
    "EM_ANALISE",
    "MONITORAMENTO",
    "ENCERRADO"

]


for status in status_possiveis:

    quantidade = sum(

        1

        for caso in casos

        if caso["status"]
        == status

    )

    print(
        f"{status}: {quantidade}"
    )


# ============================================================
# 11. RESUMO POR RESPONSAVEL
# ============================================================

print("\n========================================")
print("RESUMO POR RESPONSAVEL")
print("========================================")


responsaveis = [

    "INCIDENT_RESPONSE",
    "SOC_L2",
    "SOC_L1",
    "MONITORAMENTO_SOC"

]


for responsavel in responsaveis:

    quantidade = sum(

        1

        for caso in casos

        if caso["responsavel"]
        == responsavel

    )

    print(
        f"{responsavel}: {quantidade}"
    )


# ============================================================
# 12. CASO MAIS URGENTE
# ============================================================

if casos:

    casos_ordenados = sorted(

        casos,

        key=lambda caso:
            caso["score_final"],

        reverse=True
    )


    principal = casos_ordenados[0]


    print("\n========================================")
    print("CASO DE MAIOR PRIORIDADE")
    print("========================================")


    print(
        f"Caso: "
        f"{principal['id_caso']}"
    )

    print(
        f"Incidente: "
        f"{principal['id_incidente']}"
    )

    print(
        f"Score: "
        f"{principal['score_final']}/100"
    )

    print(
        f"Prioridade: "
        f"{principal['prioridade']}"
    )

    print(
        f"Responsavel: "
        f"{principal['responsavel']}"
    )

    print(
        f"SLA: "
        f"{principal['sla_minutos']} minutos"
    )


# ============================================================
# 13. SALVANDO CASOS
# ============================================================

with open(
    ARQUIVO_CASOS,
    "w",
    encoding="utf-8"
) as arquivo:

    json.dump(
        casos,
        arquivo,
        indent=4,
        ensure_ascii=False
    )


print("\n========================================")
print("ARQUIVO GERADO")
print("========================================")


print(
    f"Casos SOC: "
    f"{ARQUIVO_CASOS}"
)


# ============================================================
# 14. EXEMPLO JSON
# ============================================================

if casos:

    print("\n========================================")
    print("EXEMPLO DE CASO SOC")
    print("========================================")


    print(
        json.dumps(
            casos[0],
            indent=4,
            ensure_ascii=False
        )
    )


# ============================================================
# 15. PIPELINE
# ============================================================

print("\n========================================")
print("PIPELINE ATUAL")
print("========================================")


print(
    "EVENTO -> ML -> ALERTA -> CORRELACAO -> "
    "INCIDENTE -> RISK SCORE -> PRIORIDADE -> "
    "PLAYBOOK -> ENRIQUECIMENTO -> MOTOR DE REGRAS -> "
    "DECISAO FINAL -> CASE MANAGEMENT"
)


# ============================================================
# FINAL
# ============================================================

print("\n========================================")
print("AULA 18 CONCLUIDA")
print("GESTAO DE CASOS SOC EXECUTADA")
print("========================================")