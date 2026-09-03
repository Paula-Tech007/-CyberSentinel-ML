import json
import os
from datetime import datetime


# ============================================================
# AULA 16 - ENRIQUECIMENTO DE INCIDENTES SOC
# CONTEXTO + REPUTACAO + HISTORICO
# ============================================================

print("\n========================================")
print("AULA 16 - ENRIQUECIMENTO DE INCIDENTES")
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

ARQUIVO_ENRIQUECIDOS = os.path.join(
    PASTA_ALERTAS,
    "incidentes_enriquecidos_aula_16.json"
)


# ============================================================
# 2. CARREGANDO INCIDENTES
# ============================================================

print("\n========================================")
print("CARREGANDO INCIDENTES")
print("========================================")

if not os.path.exists(ARQUIVO_INCIDENTES):

    print(
        "ERRO: arquivo de incidentes da Aula 14 "
        "nao encontrado."
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
# 3. CARREGANDO RESPOSTAS DA AULA 15
# ============================================================

print("\n========================================")
print("CARREGANDO PLAYBOOKS")
print("========================================")

respostas = []

if os.path.exists(ARQUIVO_RESPOSTAS):

    with open(
        ARQUIVO_RESPOSTAS,
        "r",
        encoding="utf-8"
    ) as arquivo:

        respostas = json.load(
            arquivo
        )

    print(
        f"Respostas carregadas: {len(respostas)}"
    )

else:

    print(
        "Arquivo de respostas da Aula 15 "
        "nao encontrado."
    )

    print(
        "O enriquecimento continuara sem playbook."
    )


# ============================================================
# 4. INDEXANDO RESPOSTAS POR INCIDENTE
# ============================================================

respostas_por_incidente = {}

for resposta in respostas:

    id_incidente = resposta.get(
        "id_incidente"
    )

    if id_incidente:

        respostas_por_incidente[
            id_incidente
        ] = resposta


# ============================================================
# 5. BASE LOCAL DE REPUTACAO
# ============================================================
#
# Simulacao de uma fonte de Threat Intelligence.
#
# Mais adiante isso poderia vir de:
# AbuseIPDB
# VirusTotal
# MISP
# SIEM
# Threat Intel interna
#
# ============================================================

reputacao_ips = {

    "192.168.1.50": {
        "reputacao": "SUSPEITO",
        "score_reputacao": 80,
        "ocorrencias_anteriores": 7,
        "fonte": "THREAT_INTEL_LOCAL"
    },

    "172.16.0.25": {
        "reputacao": "DESCONHECIDO",
        "score_reputacao": 30,
        "ocorrencias_anteriores": 1,
        "fonte": "THREAT_INTEL_LOCAL"
    },

    "10.10.10.77": {
        "reputacao": "BAIXO_RISCO",
        "score_reputacao": 10,
        "ocorrencias_anteriores": 0,
        "fonte": "THREAT_INTEL_LOCAL"
    }

}


# ============================================================
# 6. FUNCAO DE REPUTACAO
# ============================================================

def obter_reputacao(ip):

    return reputacao_ips.get(
        ip,
        {
            "reputacao": "SEM_DADOS",
            "score_reputacao": 0,
            "ocorrencias_anteriores": 0,
            "fonte": "SEM_FONTE"
        }
    )


# ============================================================
# 7. CLASSIFICACAO DE RECORRENCIA
# ============================================================

def classificar_recorrencia(
    ocorrencias
):

    if ocorrencias >= 10:
        return "MUITO_ALTA"

    elif ocorrencias >= 5:
        return "ALTA"

    elif ocorrencias >= 2:
        return "MEDIA"

    elif ocorrencias == 1:
        return "BAIXA"

    else:
        return "SEM_HISTORICO"


# ============================================================
# 8. SCORE DE CONTEXTO
# ============================================================

def calcular_context_score(
    incidente,
    reputacao
):

    score = 0

    quantidade_alertas = incidente.get(
        "quantidade_alertas",
        0
    )

    quantidade_destinos = incidente.get(
        "quantidade_destinos",
        0
    )

    alertas_criticos = incidente.get(
        "alertas_criticos",
        0
    )

    probabilidade_media = incidente.get(
        "probabilidade_media",
        0
    )

    score_reputacao = reputacao.get(
        "score_reputacao",
        0
    )

    ocorrencias = reputacao.get(
        "ocorrencias_anteriores",
        0
    )


    # Quantidade de alertas
    if quantidade_alertas >= 5:
        score += 20

    elif quantidade_alertas >= 3:
        score += 15

    elif quantidade_alertas >= 2:
        score += 10


    # Quantidade de destinos
    if quantidade_destinos >= 5:
        score += 20

    elif quantidade_destinos >= 3:
        score += 15

    elif quantidade_destinos >= 2:
        score += 10


    # Alertas criticos
    if alertas_criticos >= 3:
        score += 20

    elif alertas_criticos >= 1:
        score += 15


    # Probabilidade media do ML
    if probabilidade_media >= 90:
        score += 20

    elif probabilidade_media >= 70:
        score += 15

    elif probabilidade_media >= 50:
        score += 10


    # Reputacao do IP
    if score_reputacao >= 80:
        score += 15

    elif score_reputacao >= 50:
        score += 10

    elif score_reputacao >= 20:
        score += 5


    # Recorrencia
    if ocorrencias >= 10:
        score += 15

    elif ocorrencias >= 5:
        score += 10

    elif ocorrencias >= 2:
        score += 5


    if score > 100:
        score = 100


    return score


# ============================================================
# 9. CLASSIFICACAO DO CONTEXTO
# ============================================================

def classificar_contexto(
    score
):

    if score >= 80:
        return "CRITICO"

    elif score >= 60:
        return "ALTO"

    elif score >= 40:
        return "MEDIO"

    else:
        return "BAIXO"


# ============================================================
# 10. ENRIQUECENDO INCIDENTES
# ============================================================

print("\n========================================")
print("ENRIQUECENDO INCIDENTES")
print("========================================")


incidentes_enriquecidos = []


for incidente in incidentes:

    id_incidente = incidente.get(
        "id_incidente"
    )

    ip_origem = incidente.get(
        "ip_origem",
        "DESCONHECIDO"
    )


    reputacao = obter_reputacao(
        ip_origem
    )


    ocorrencias = reputacao.get(
        "ocorrencias_anteriores",
        0
    )


    recorrencia = classificar_recorrencia(
        ocorrencias
    )


    context_score = calcular_context_score(
        incidente,
        reputacao
    )


    contexto = classificar_contexto(
        context_score
    )


    resposta_playbook = (
        respostas_por_incidente.get(
            id_incidente
        )
    )


    incidente_enriquecido = incidente.copy()


    incidente_enriquecido[
        "timestamp_enriquecimento"
    ] = datetime.now().isoformat()


    incidente_enriquecido[
        "reputacao_ip"
    ] = reputacao[
        "reputacao"
    ]


    incidente_enriquecido[
        "score_reputacao"
    ] = reputacao[
        "score_reputacao"
    ]


    incidente_enriquecido[
        "ocorrencias_anteriores"
    ] = ocorrencias


    incidente_enriquecido[
        "recorrencia"
    ] = recorrencia


    incidente_enriquecido[
        "fonte_reputacao"
    ] = reputacao[
        "fonte"
    ]


    incidente_enriquecido[
        "context_score"
    ] = context_score


    incidente_enriquecido[
        "nivel_contexto"
    ] = contexto


    if resposta_playbook:

        incidente_enriquecido[
            "acao_playbook"
        ] = resposta_playbook.get(
            "acao_principal"
        )

        incidente_enriquecido[
            "sla_playbook"
        ] = resposta_playbook.get(
            "sla_minutos"
        )

        incidente_enriquecido[
            "nivel_resposta"
        ] = resposta_playbook.get(
            "nivel_resposta"
        )


    incidentes_enriquecidos.append(
        incidente_enriquecido
    )


# ============================================================
# 11. MOSTRANDO RESULTADOS
# ============================================================

print("\n========================================")
print("INCIDENTES ENRIQUECIDOS")
print("========================================")


for incidente in incidentes_enriquecidos:

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
        f"Risk Score anterior: "
        f"{incidente.get('risk_score', 0)}/100"
    )

    print(
        f"Prioridade anterior: "
        f"{incidente.get('prioridade', 'N/A')}"
    )

    print(
        f"Reputacao do IP: "
        f"{incidente['reputacao_ip']}"
    )

    print(
        f"Score de reputacao: "
        f"{incidente['score_reputacao']}/100"
    )

    print(
        f"Ocorrencias anteriores: "
        f"{incidente['ocorrencias_anteriores']}"
    )

    print(
        f"Recorrencia: "
        f"{incidente['recorrencia']}"
    )

    print(
        f"Context Score: "
        f"{incidente['context_score']}/100"
    )

    print(
        f"Nivel de contexto: "
        f"{incidente['nivel_contexto']}"
    )


    if "acao_playbook" in incidente:

        print(
            f"Playbook: "
            f"{incidente['acao_playbook']}"
        )

        print(
            f"SLA: "
            f"{incidente['sla_playbook']} minutos"
        )


# ============================================================
# 12. RESUMO DE REPUTACAO
# ============================================================

print("\n========================================")
print("RESUMO DE REPUTACAO")
print("========================================")


reputacoes_possiveis = [

    "SUSPEITO",
    "DESCONHECIDO",
    "BAIXO_RISCO",
    "SEM_DADOS"

]


for reputacao in reputacoes_possiveis:

    quantidade = sum(

        1

        for incidente
        in incidentes_enriquecidos

        if incidente["reputacao_ip"]
        == reputacao

    )


    print(
        f"{reputacao}: {quantidade}"
    )


# ============================================================
# 13. RESUMO POR CONTEXTO
# ============================================================

print("\n========================================")
print("RESUMO POR NIVEL DE CONTEXTO")
print("========================================")


for nivel in [

    "BAIXO",
    "MEDIO",
    "ALTO",
    "CRITICO"

]:

    quantidade = sum(

        1

        for incidente
        in incidentes_enriquecidos

        if incidente["nivel_contexto"]
        == nivel

    )


    print(
        f"{nivel}: {quantidade}"
    )


# ============================================================
# 14. INCIDENTE MAIS RELEVANTE
# ============================================================

if incidentes_enriquecidos:

    incidente_principal = max(
        incidentes_enriquecidos,
        key=lambda item:
            item["context_score"]
    )


    print("\n========================================")
    print("INCIDENTE DE MAIOR CONTEXTO")
    print("========================================")


    print(
        f"Incidente: "
        f"{incidente_principal['id_incidente']}"
    )

    print(
        f"IP origem: "
        f"{incidente_principal['ip_origem']}"
    )

    print(
        f"Context Score: "
        f"{incidente_principal['context_score']}/100"
    )

    print(
        f"Nivel: "
        f"{incidente_principal['nivel_contexto']}"
    )

    print(
        f"Reputacao: "
        f"{incidente_principal['reputacao_ip']}"
    )


# ============================================================
# 15. SALVANDO INCIDENTES ENRIQUECIDOS
# ============================================================

with open(
    ARQUIVO_ENRIQUECIDOS,
    "w",
    encoding="utf-8"
) as arquivo:

    json.dump(
        incidentes_enriquecidos,
        arquivo,
        indent=4,
        ensure_ascii=False
    )


print("\n========================================")
print("ARQUIVO GERADO")
print("========================================")


print(
    f"Incidentes enriquecidos: "
    f"{ARQUIVO_ENRIQUECIDOS}"
)


# ============================================================
# 16. EXEMPLO JSON
# ============================================================

if incidentes_enriquecidos:

    print("\n========================================")
    print("EXEMPLO DE INCIDENTE ENRIQUECIDO")
    print("========================================")


    print(
        json.dumps(
            incidentes_enriquecidos[0],
            indent=4,
            ensure_ascii=False
        )
    )


# ============================================================
# 17. PIPELINE
# ============================================================

print("\n========================================")
print("PIPELINE ATUAL")
print("========================================")


print(
    "EVENTO -> ML -> ALERTA -> CORRELACAO -> "
    "INCIDENTE -> RISK SCORE -> PRIORIDADE -> "
    "PLAYBOOK -> ENRIQUECIMENTO"
)


# ============================================================
# FINAL
# ============================================================

print("\n========================================")
print("AULA 16 CONCLUIDA")
print("ENRIQUECIMENTO DE INCIDENTES EXECUTADO")
print("========================================")