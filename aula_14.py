import json
import os
from datetime import datetime


# ============================================================
# AULA 14 - PRIORIZACAO DE INCIDENTES SOC
# RISK SCORE + SEVERIDADE + ACAO RECOMENDADA
# ============================================================

print("\n========================================")
print("AULA 14 - PRIORIZACAO DE INCIDENTES SOC")
print("========================================")


# ============================================================
# 1. CAMINHOS
# ============================================================

PASTA_ALERTAS = "alertas"

ARQUIVO_INCIDENTES = os.path.join(
    PASTA_ALERTAS,
    "incidentes_aula_13.json"
)

ARQUIVO_PRIORIZADOS = os.path.join(
    PASTA_ALERTAS,
    "incidentes_priorizados_aula_14.json"
)


# ============================================================
# 2. VERIFICANDO ARQUIVO DA AULA 13
# ============================================================

print("\n========================================")
print("CARREGANDO INCIDENTES")
print("========================================")


if not os.path.exists(ARQUIVO_INCIDENTES):

    print(
        "ERRO: arquivo de incidentes da Aula 13 "
        "nao foi encontrado."
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
# 3. FUNCAO DE SCORE
# ============================================================

def calcular_score(incidente):

    score = 0

    quantidade_alertas = incidente.get(
        "quantidade_alertas",
        0
    )

    quantidade_destinos = incidente.get(
        "quantidade_destinos",
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


    # ========================================================
    # ALERTAS RELACIONADOS
    # ========================================================

    if quantidade_alertas >= 5:

        score += 30

    elif quantidade_alertas >= 3:

        score += 20

    elif quantidade_alertas >= 2:

        score += 10


    # ========================================================
    # DESTINOS DIFERENTES
    # ========================================================

    if quantidade_destinos >= 5:

        score += 20

    elif quantidade_destinos >= 3:

        score += 15

    elif quantidade_destinos >= 2:

        score += 10


    # ========================================================
    # PROBABILIDADE MEDIA
    # ========================================================

    if probabilidade_media >= 90:

        score += 25

    elif probabilidade_media >= 70:

        score += 20

    elif probabilidade_media >= 50:

        score += 15

    elif probabilidade_media >= 30:

        score += 10


    # ========================================================
    # ALERTAS CRITICOS
    # ========================================================

    if alertas_criticos >= 3:

        score += 25

    elif alertas_criticos >= 2:

        score += 20

    elif alertas_criticos >= 1:

        score += 10


    # ========================================================
    # LIMITE
    # ========================================================

    if score > 100:

        score = 100


    return score


# ============================================================
# 4. FUNCAO DE PRIORIDADE
# ============================================================

def calcular_prioridade(score):

    if score >= 80:

        return "P1"

    elif score >= 60:

        return "P2"

    elif score >= 40:

        return "P3"

    else:

        return "P4"


# ============================================================
# 5. FUNCAO DE SEVERIDADE
# ============================================================

def calcular_severidade(score):

    if score >= 80:

        return "CRITICO"

    elif score >= 60:

        return "ALTO"

    elif score >= 40:

        return "MEDIO"

    else:

        return "BAIXO"


# ============================================================
# 6. ACAO RECOMENDADA
# ============================================================

def recomendar_acao(prioridade):

    if prioridade == "P1":

        return (
            "INVESTIGACAO IMEDIATA - "
            "validar origem, bloquear se confirmado "
            "e iniciar resposta a incidente"
        )

    elif prioridade == "P2":

        return (
            "INVESTIGACAO PRIORITARIA - "
            "correlacionar logs adicionais "
            "e validar atividade suspeita"
        )

    elif prioridade == "P3":

        return (
            "ANALISE DO SOC - "
            "revisar contexto, comportamento "
            "e historico do ativo"
        )

    else:

        return (
            "MONITORAMENTO - "
            "acompanhar novos eventos relacionados"
        )


# ============================================================
# 7. ENRIQUECENDO INCIDENTES
# ============================================================

print("\n========================================")
print("CALCULANDO RISK SCORE")
print("========================================")


incidentes_priorizados = []


for incidente in incidentes:

    score = calcular_score(
        incidente
    )

    prioridade = calcular_prioridade(
        score
    )

    severidade = calcular_severidade(
        score
    )

    acao = recomendar_acao(
        prioridade
    )


    incidente_enriquecido = incidente.copy()


    incidente_enriquecido[
        "timestamp_priorizacao"
    ] = datetime.now().isoformat()


    incidente_enriquecido[
        "risk_score"
    ] = score


    incidente_enriquecido[
        "prioridade"
    ] = prioridade


    incidente_enriquecido[
        "severidade_priorizada"
    ] = severidade


    incidente_enriquecido[
        "acao_recomendada"
    ] = acao


    incidentes_priorizados.append(
        incidente_enriquecido
    )


# ============================================================
# 8. ORDENANDO POR SCORE
# ============================================================

incidentes_priorizados = sorted(
    incidentes_priorizados,
    key=lambda incidente:
        incidente["risk_score"],
    reverse=True
)


# ============================================================
# 9. MOSTRANDO RESULTADOS
# ============================================================

print("\n========================================")
print("INCIDENTES PRIORIZADOS")
print("========================================")


if not incidentes_priorizados:

    print(
        "Nenhum incidente disponivel."
    )


for incidente in incidentes_priorizados:

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
        f"Risk Score: "
        f"{incidente['risk_score']}/100"
    )

    print(
        f"Prioridade: "
        f"{incidente['prioridade']}"
    )

    print(
        f"Severidade: "
        f"{incidente['severidade_priorizada']}"
    )

    print(
        f"Acao recomendada: "
        f"{incidente['acao_recomendada']}"
    )


# ============================================================
# 10. RESUMO POR PRIORIDADE
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

        for incidente
        in incidentes_priorizados

        if incidente["prioridade"]
        == prioridade

    )


    print(
        f"{prioridade}: {quantidade}"
    )


# ============================================================
# 11. INCIDENTE MAIS CRITICO
# ============================================================

if incidentes_priorizados:

    principal = (
        incidentes_priorizados[0]
    )


    print("\n========================================")
    print("INCIDENTE DE MAIOR PRIORIDADE")
    print("========================================")


    print(
        f"Incidente: "
        f"{principal['id_incidente']}"
    )

    print(
        f"Risk Score: "
        f"{principal['risk_score']}/100"
    )

    print(
        f"Prioridade: "
        f"{principal['prioridade']}"
    )

    print(
        f"Severidade: "
        f"{principal['severidade_priorizada']}"
    )


# ============================================================
# 12. SALVANDO RESULTADO
# ============================================================

with open(
    ARQUIVO_PRIORIZADOS,
    "w",
    encoding="utf-8"
) as arquivo:

    json.dump(
        incidentes_priorizados,
        arquivo,
        indent=4,
        ensure_ascii=False
    )


print("\n========================================")
print("ARQUIVO GERADO")
print("========================================")


print(
    f"Incidentes priorizados: "
    f"{ARQUIVO_PRIORIZADOS}"
)


# ============================================================
# 13. JSON DE EXEMPLO
# ============================================================

if incidentes_priorizados:

    print("\n========================================")
    print("EXEMPLO DE INCIDENTE PRIORIZADO")
    print("========================================")


    print(
        json.dumps(
            incidentes_priorizados[0],
            indent=4,
            ensure_ascii=False
        )
    )


# ============================================================
# 14. PIPELINE
# ============================================================

print("\n========================================")
print("PIPELINE ATUAL")
print("========================================")


print(
    "EVENTO -> ML -> ALERTA -> CORRELACAO "
    "-> INCIDENTE -> RISK SCORE -> PRIORIDADE"
)


# ============================================================
# FINAL
# ============================================================

print("\n========================================")
print("AULA 14 CONCLUIDA")
print("PRIORIZACAO DE INCIDENTES EXECUTADA")
print("========================================")