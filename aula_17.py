import json
import os
from datetime import datetime


# ============================================================
# AULA 17 - MOTOR DE REGRAS SOC
# DECISAO FINAL BASEADA EM ML + CONTEXTO + RISCO
# ============================================================

print("\n========================================")
print("AULA 17 - MOTOR DE REGRAS SOC")
print("========================================")


# ============================================================
# 1. CAMINHOS
# ============================================================

PASTA_ALERTAS = "alertas"

ARQUIVO_INCIDENTES = os.path.join(
    PASTA_ALERTAS,
    "incidentes_enriquecidos_aula_16.json"
)

ARQUIVO_DECISOES = os.path.join(
    PASTA_ALERTAS,
    "decisoes_aula_17.json"
)


# ============================================================
# 2. CARREGANDO INCIDENTES ENRIQUECIDOS
# ============================================================

print("\n========================================")
print("CARREGANDO INCIDENTES ENRIQUECIDOS")
print("========================================")


if not os.path.exists(ARQUIVO_INCIDENTES):

    print(
        "ERRO: arquivo da Aula 16 nao encontrado."
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
# 3. FUNCAO DE PONTUACAO FINAL
# ============================================================

def calcular_score_final(
    incidente
):

    score = 0


    risk_score = incidente.get(
        "risk_score",
        0
    )


    context_score = incidente.get(
        "context_score",
        0
    )


    score_reputacao = incidente.get(
        "score_reputacao",
        0
    )


    probabilidade_media = incidente.get(
        "probabilidade_media",
        0
    )


    alertas_criticos = incidente.get(
        "alertas_criticos",
        0
    )


    quantidade_alertas = incidente.get(
        "quantidade_alertas",
        0
    )


    quantidade_destinos = incidente.get(
        "quantidade_destinos",
        0
    )


    ocorrencias = incidente.get(
        "ocorrencias_anteriores",
        0
    )


    # ========================================================
    # RISK SCORE
    # Peso maximo: 25
    # ========================================================

    score += (
        risk_score * 0.25
    )


    # ========================================================
    # CONTEXT SCORE
    # Peso maximo: 25
    # ========================================================

    score += (
        context_score * 0.25
    )


    # ========================================================
    # REPUTACAO
    # Peso maximo: 15
    # ========================================================

    score += (
        score_reputacao * 0.15
    )


    # ========================================================
    # PROBABILIDADE MEDIA DO ML
    # Peso maximo: 15
    # ========================================================

    score += (
        probabilidade_media * 0.15
    )


    # ========================================================
    # ALERTAS CRITICOS
    # Peso maximo: 10
    # ========================================================

    if alertas_criticos >= 3:
        score += 10

    elif alertas_criticos >= 2:
        score += 8

    elif alertas_criticos >= 1:
        score += 5


    # ========================================================
    # QUANTIDADE DE ALERTAS
    # Peso maximo: 5
    # ========================================================

    if quantidade_alertas >= 5:
        score += 5

    elif quantidade_alertas >= 3:
        score += 4

    elif quantidade_alertas >= 2:
        score += 2


    # ========================================================
    # QUANTIDADE DE DESTINOS
    # Peso maximo: 3
    # ========================================================

    if quantidade_destinos >= 5:
        score += 3

    elif quantidade_destinos >= 3:
        score += 2

    elif quantidade_destinos >= 2:
        score += 1


    # ========================================================
    # RECORRENCIA
    # Peso maximo: 2
    # ========================================================

    if ocorrencias >= 10:
        score += 2

    elif ocorrencias >= 5:
        score += 1.5

    elif ocorrencias >= 2:
        score += 1


    # ========================================================
    # LIMITANDO EM 100
    # ========================================================

    if score > 100:

        score = 100


    return round(
        score,
        2
    )


# ============================================================
# 4. CLASSIFICACAO DA DECISAO FINAL
# ============================================================

def classificar_decisao(
    score_final
):

    if score_final >= 80:

        return {
            "decisao": "INCIDENTE_CRITICO",
            "prioridade_final": "P1",
            "severidade_final": "CRITICO",
            "status": "ESCALAR_IMEDIATAMENTE"
        }


    elif score_final >= 65:

        return {
            "decisao": "INCIDENTE_ALTO_RISCO",
            "prioridade_final": "P2",
            "severidade_final": "ALTO",
            "status": "INVESTIGACAO_PRIORITARIA"
        }


    elif score_final >= 45:

        return {
            "decisao": "INCIDENTE_SUSPEITO",
            "prioridade_final": "P3",
            "severidade_final": "MEDIO",
            "status": "ANALISE_SOC"
        }


    else:

        return {
            "decisao": "INCIDENTE_BAIXO_RISCO",
            "prioridade_final": "P4",
            "severidade_final": "BAIXO",
            "status": "MONITORAMENTO"
        }


# ============================================================
# 5. ACAO FINAL RECOMENDADA
# ============================================================

def definir_acao_final(
    prioridade
):

    if prioridade == "P1":

        return (
            "ESCALAR PARA INCIDENT RESPONSE, "
            "VALIDAR ISOLAMENTO DO ATIVO, "
            "COLETAR EVIDENCIAS E AVALIAR BLOQUEIO"
        )


    elif prioridade == "P2":

        return (
            "ABRIR INVESTIGACAO PRIORITARIA, "
            "CORRELACIONAR LOGS, VALIDAR IOCS "
            "E ACOMPANHAR O ATIVO"
        )


    elif prioridade == "P3":

        return (
            "CRIAR CASO PARA ANALISE DO SOC "
            "E MANTER MONITORAMENTO REFORCADO"
        )


    else:

        return (
            "REGISTRAR E MANTER MONITORAMENTO"
        )


# ============================================================
# 6. SLA FINAL
# ============================================================

def definir_sla(
    prioridade
):

    if prioridade == "P1":

        return 15


    elif prioridade == "P2":

        return 30


    elif prioridade == "P3":

        return 120


    else:

        return 480


# ============================================================
# 7. EXECUTANDO MOTOR DE REGRAS
# ============================================================

print("\n========================================")
print("EXECUTANDO MOTOR DE REGRAS")
print("========================================")


decisoes = []


for incidente in incidentes:

    score_final = calcular_score_final(
        incidente
    )


    classificacao = classificar_decisao(
        score_final
    )


    prioridade_final = classificacao[
        "prioridade_final"
    ]


    acao_final = definir_acao_final(
        prioridade_final
    )


    sla_final = definir_sla(
        prioridade_final
    )


    decisao = {

        "timestamp_decisao":
            datetime.now().isoformat(),

        "id_incidente":
            incidente.get(
                "id_incidente"
            ),

        "ip_origem":
            incidente.get(
                "ip_origem"
            ),

        "risk_score":
            incidente.get(
                "risk_score"
            ),

        "context_score":
            incidente.get(
                "context_score"
            ),

        "score_reputacao":
            incidente.get(
                "score_reputacao"
            ),

        "probabilidade_media":
            incidente.get(
                "probabilidade_media"
            ),

        "alertas_criticos":
            incidente.get(
                "alertas_criticos"
            ),

        "quantidade_alertas":
            incidente.get(
                "quantidade_alertas"
            ),

        "quantidade_destinos":
            incidente.get(
                "quantidade_destinos"
            ),

        "recorrencia":
            incidente.get(
                "recorrencia"
            ),

        "score_final":
            score_final,

        "decisao":
            classificacao[
                "decisao"
            ],

        "prioridade_final":
            prioridade_final,

        "severidade_final":
            classificacao[
                "severidade_final"
            ],

        "status":
            classificacao[
                "status"
            ],

        "acao_final":
            acao_final,

        "sla_final_minutos":
            sla_final,

        "execucao_real":
            False,

        "modo":
            "MOTOR_REGRAS_SOC_SIMULADO"

    }


    decisoes.append(
        decisao
    )


# ============================================================
# 8. ORDENANDO POR SCORE FINAL
# ============================================================

decisoes = sorted(
    decisoes,
    key=lambda item:
        item["score_final"],
    reverse=True
)


# ============================================================
# 9. MOSTRANDO DECISOES
# ============================================================

print("\n========================================")
print("DECISOES FINAIS SOC")
print("========================================")


if not decisoes:

    print(
        "Nenhuma decisao foi gerada."
    )


for decisao in decisoes:

    print("\n----------------------------------------")

    print(
        f"Incidente: "
        f"{decisao['id_incidente']}"
    )

    print(
        f"IP origem: "
        f"{decisao['ip_origem']}"
    )

    print(
        f"Risk Score: "
        f"{decisao['risk_score']}/100"
    )

    print(
        f"Context Score: "
        f"{decisao['context_score']}/100"
    )

    print(
        f"Score reputacao: "
        f"{decisao['score_reputacao']}/100"
    )

    print(
        f"Probabilidade media: "
        f"{decisao['probabilidade_media']:.2f}%"
    )

    print(
        f"Score FINAL: "
        f"{decisao['score_final']}/100"
    )

    print(
        f"Decisao: "
        f"{decisao['decisao']}"
    )

    print(
        f"Prioridade FINAL: "
        f"{decisao['prioridade_final']}"
    )

    print(
        f"Severidade FINAL: "
        f"{decisao['severidade_final']}"
    )

    print(
        f"Status: "
        f"{decisao['status']}"
    )

    print(
        f"SLA FINAL: "
        f"{decisao['sla_final_minutos']} minutos"
    )

    print(
        f"Acao FINAL: "
        f"{decisao['acao_final']}"
    )


# ============================================================
# 10. RESUMO POR PRIORIDADE
# ============================================================

print("\n========================================")
print("RESUMO POR PRIORIDADE FINAL")
print("========================================")


for prioridade in [
    "P1",
    "P2",
    "P3",
    "P4"
]:

    quantidade = sum(

        1

        for decisao in decisoes

        if decisao[
            "prioridade_final"
        ] == prioridade

    )


    print(
        f"{prioridade}: {quantidade}"
    )


# ============================================================
# 11. RESUMO POR SEVERIDADE
# ============================================================

print("\n========================================")
print("RESUMO POR SEVERIDADE FINAL")
print("========================================")


for severidade in [

    "BAIXO",
    "MEDIO",
    "ALTO",
    "CRITICO"

]:

    quantidade = sum(

        1

        for decisao in decisoes

        if decisao[
            "severidade_final"
        ] == severidade

    )


    print(
        f"{severidade}: {quantidade}"
    )


# ============================================================
# 12. DECISAO MAIS URGENTE
# ============================================================

if decisoes:

    principal = decisoes[0]


    print("\n========================================")
    print("DECISAO DE MAIOR PRIORIDADE")
    print("========================================")


    print(
        f"Incidente: "
        f"{principal['id_incidente']}"
    )

    print(
        f"Score FINAL: "
        f"{principal['score_final']}/100"
    )

    print(
        f"Prioridade: "
        f"{principal['prioridade_final']}"
    )

    print(
        f"Severidade: "
        f"{principal['severidade_final']}"
    )

    print(
        f"Status: "
        f"{principal['status']}"
    )


# ============================================================
# 13. SALVANDO DECISOES
# ============================================================

with open(
    ARQUIVO_DECISOES,
    "w",
    encoding="utf-8"
) as arquivo:

    json.dump(
        decisoes,
        arquivo,
        indent=4,
        ensure_ascii=False
    )


print("\n========================================")
print("ARQUIVO GERADO")
print("========================================")


print(
    f"Decisoes SOC: "
    f"{ARQUIVO_DECISOES}"
)


# ============================================================
# 14. JSON DE EXEMPLO
# ============================================================

if decisoes:

    print("\n========================================")
    print("EXEMPLO DE DECISAO FINAL")
    print("========================================")


    print(
        json.dumps(
            decisoes[0],
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
    "PLAYBOOK -> ENRIQUECIMENTO -> MOTOR DE REGRAS "
    "-> DECISAO FINAL SOC"
)


# ============================================================
# FINAL
# ============================================================

print("\n========================================")
print("AULA 17 CONCLUIDA")
print("MOTOR DE REGRAS SOC EXECUTADO")
print("========================================")