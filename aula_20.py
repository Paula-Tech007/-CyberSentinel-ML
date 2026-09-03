import os
import json
import joblib
from datetime import datetime


# ============================================================
# AULA 20 - VALIDACAO FINAL DO PROJETO
# MACHINE LEARNING CYBER DETECTOR
# ============================================================

print("\n========================================")
print("AULA 20 - VALIDACAO FINAL DO PROJETO")
print("MACHINE LEARNING CYBER DETECTOR")
print("========================================")


# ============================================================
# 1. CONFIGURACAO
# ============================================================

PASTA_MODELOS = "modelos"
PASTA_ALERTAS = "alertas"
PASTA_EVENTOS = "eventos"

ARQUIVO_MODELO = os.path.join(
    PASTA_MODELOS,
    "unsw_decision_tree.joblib"
)

ARQUIVO_CONFIG = os.path.join(
    PASTA_MODELOS,
    "configuracao_modelo.joblib"
)

ARQUIVO_PIPELINE = os.path.join(
    PASTA_ALERTAS,
    "relatorio_pipeline_aula_19.json"
)

ARQUIVO_CASOS = os.path.join(
    PASTA_ALERTAS,
    "casos_aula_18.json"
)

ARQUIVO_RELATORIO_FINAL = os.path.join(
    PASTA_ALERTAS,
    "relatorio_final_aula_20.json"
)


# ============================================================
# 2. CONTROLE DAS VALIDACOES
# ============================================================

validacoes = []

def registrar_validacao(
    componente,
    status,
    detalhe
):

    validacoes.append({
        "componente": componente,
        "status": status,
        "detalhe": detalhe
    })

    simbolo = "[OK]" if status == "OK" else "[ERRO]"

    print(
        f"{simbolo} {componente}: {detalhe}"
    )


# ============================================================
# 3. VALIDANDO DIRETORIOS
# ============================================================

print("\n========================================")
print("VALIDANDO DIRETORIOS")
print("========================================")


diretorios = [
    PASTA_MODELOS,
    PASTA_ALERTAS,
    PASTA_EVENTOS
]


for diretorio in diretorios:

    if os.path.isdir(diretorio):

        registrar_validacao(
            diretorio,
            "OK",
            "Diretorio encontrado"
        )

    else:

        registrar_validacao(
            diretorio,
            "ERRO",
            "Diretorio nao encontrado"
        )


# ============================================================
# 4. VALIDANDO MODELO
# ============================================================

print("\n========================================")
print("VALIDANDO MODELO DE MACHINE LEARNING")
print("========================================")


modelo = None
configuracao = None


if os.path.exists(ARQUIVO_MODELO):

    try:

        modelo = joblib.load(
            ARQUIVO_MODELO
        )

        registrar_validacao(
            "Modelo ML",
            "OK",
            (
                f"{ARQUIVO_MODELO} | "
                f"{modelo.__class__.__name__}"
            )
        )

    except Exception as erro:

        registrar_validacao(
            "Modelo ML",
            "ERRO",
            str(erro)
        )

else:

    registrar_validacao(
        "Modelo ML",
        "ERRO",
        "Arquivo do modelo nao encontrado"
    )


# ============================================================
# 5. VALIDANDO CONFIGURACAO
# ============================================================

if os.path.exists(ARQUIVO_CONFIG):

    try:

        configuracao = joblib.load(
            ARQUIVO_CONFIG
        )

        registrar_validacao(
            "Configuracao ML",
            "OK",
            ARQUIVO_CONFIG
        )

    except Exception as erro:

        registrar_validacao(
            "Configuracao ML",
            "ERRO",
            str(erro)
        )

else:

    registrar_validacao(
        "Configuracao ML",
        "ERRO",
        "Arquivo de configuracao nao encontrado"
    )


# ============================================================
# 6. INFORMACOES DO MODELO
# ============================================================

print("\n========================================")
print("CONFIGURACAO DO MODELO")
print("========================================")


if modelo is not None:

    print(
        f"Algoritmo: "
        f"{modelo.__class__.__name__}"
    )

    if hasattr(
        modelo,
        "max_depth"
    ):

        print(
            f"max_depth: "
            f"{modelo.max_depth}"
        )


if configuracao is not None:

    threshold = configuracao.get(
        "threshold",
        "NAO_INFORMADO"
    )

    features = configuracao.get(
        "features",
        []
    )

    print(
        f"Threshold: {threshold}"
    )

    print(
        f"Quantidade de features: "
        f"{len(features)}"
    )

    if features:

        print("\nFeatures:")

        for indice, feature in enumerate(
            features,
            start=1
        ):

            print(
                f"{indice:02d} - {feature}"
            )


# ============================================================
# 7. VALIDANDO AULAS
# ============================================================

print("\n========================================")
print("VALIDANDO SCRIPTS DO PROJETO")
print("========================================")


scripts = [


    "aula_03.py",
    "aula_04.py",
    "aula_05.py",
    "aula_06.py",
    "aula_07.py",
    "aula_08.py",
    "aula_09.py",
    "aula_10.py",
    "aula_11.py",
    "aula_12.py",
    "aula_13.py",
    "aula_14.py",
    "aula_15.py",
    "aula_16.py",
    "aula_17.py",
    "aula_18.py",
    "aula_19.py",
    "aula_20.py"

]


scripts_encontrados = 0


for script in scripts:

    if os.path.exists(script):

        scripts_encontrados += 1

        registrar_validacao(
            script,
            "OK",
            "Encontrado"
        )

    else:

        registrar_validacao(
            script,
            "ERRO",
            "Nao encontrado"
        )


# ============================================================
# 8. VALIDANDO ARTEFATOS SOC
# ============================================================

print("\n========================================")
print("VALIDANDO ARTEFATOS SOC")
print("========================================")


artefatos = [

    "alertas/incidentes_aula_13.json",

    "alertas/incidentes_priorizados_aula_14.json",

    "alertas/respostas_aula_15.json",

    "alertas/incidentes_enriquecidos_aula_16.json",

    "alertas/decisoes_aula_17.json",

    "alertas/casos_aula_18.json",

    "alertas/relatorio_pipeline_aula_19.json"

]


artefatos_encontrados = 0


for artefato in artefatos:

    if os.path.exists(artefato):

        artefatos_encontrados += 1

        registrar_validacao(
            artefato,
            "OK",
            "Artefato encontrado"
        )

    else:

        registrar_validacao(
            artefato,
            "ERRO",
            "Artefato nao encontrado"
        )


# ============================================================
# 9. CARREGANDO RELATORIO DA AULA 19
# ============================================================

print("\n========================================")
print("VALIDANDO PIPELINE INTEGRADO")
print("========================================")


relatorio_pipeline = {}


if os.path.exists(
    ARQUIVO_PIPELINE
):

    try:

        with open(
            ARQUIVO_PIPELINE,
            "r",
            encoding="utf-8"
        ) as arquivo:

            relatorio_pipeline = json.load(
                arquivo
            )


        pipeline_sucesso = relatorio_pipeline.get(
            "pipeline_sucesso",
            False
        )


        if pipeline_sucesso:

            registrar_validacao(
                "Pipeline integrado",
                "OK",
                "Pipeline concluido com sucesso"
            )

        else:

            registrar_validacao(
                "Pipeline integrado",
                "ERRO",
                "Pipeline nao foi concluido com sucesso"
            )


        print(
            f"Etapas previstas: "
            f"{relatorio_pipeline.get('etapas_previstas')}"
        )

        print(
            f"Etapas executadas: "
            f"{relatorio_pipeline.get('etapas_executadas')}"
        )

        print(
            f"Etapas com sucesso: "
            f"{relatorio_pipeline.get('etapas_sucesso')}"
        )

        print(
            f"Etapas com erro: "
            f"{relatorio_pipeline.get('etapas_erro')}"
        )


    except Exception as erro:

        registrar_validacao(
            "Pipeline integrado",
            "ERRO",
            str(erro)
        )

else:

    registrar_validacao(
        "Pipeline integrado",
        "ERRO",
        "Relatorio da Aula 19 nao encontrado"
    )


# ============================================================
# 10. CARREGANDO CASOS SOC
# ============================================================

print("\n========================================")
print("VALIDANDO CASE MANAGEMENT")
print("========================================")


casos = []


if os.path.exists(
    ARQUIVO_CASOS
):

    try:

        with open(
            ARQUIVO_CASOS,
            "r",
            encoding="utf-8"
        ) as arquivo:

            casos = json.load(
                arquivo
            )


        registrar_validacao(
            "Case Management",
            "OK",
            f"{len(casos)} caso(s) encontrado(s)"
        )


    except Exception as erro:

        registrar_validacao(
            "Case Management",
            "ERRO",
            str(erro)
        )

else:

    registrar_validacao(
        "Case Management",
        "ERRO",
        "Arquivo de casos nao encontrado"
    )


# ============================================================
# 11. RESUMO DOS CASOS
# ============================================================

print("\n========================================")
print("RESUMO DOS CASOS SOC")
print("========================================")


print(
    f"Quantidade de casos: "
    f"{len(casos)}"
)


for caso in casos:

    print("\n----------------------------------------")

    print(
        f"Caso: "
        f"{caso.get('id_caso')}"
    )

    print(
        f"Incidente: "
        f"{caso.get('id_incidente')}"
    )

    print(
        f"Status: "
        f"{caso.get('status')}"
    )

    print(
        f"Prioridade: "
        f"{caso.get('prioridade')}"
    )

    print(
        f"Severidade: "
        f"{caso.get('severidade')}"
    )

    print(
        f"Score: "
        f"{caso.get('score_final')}/100"
    )

    print(
        f"Responsavel: "
        f"{caso.get('responsavel')}"
    )

    print(
        f"SLA: "
        f"{caso.get('sla_minutos')} minutos"
    )


# ============================================================
# 12. CALCULANDO SAUDE DO PROJETO
# ============================================================

print("\n========================================")
print("SAUDE DO PROJETO")
print("========================================")


total_validacoes = len(
    validacoes
)

validacoes_ok = sum(

    1

    for validacao in validacoes

    if validacao["status"] == "OK"
)


validacoes_erro = (
    total_validacoes
    - validacoes_ok
)


if total_validacoes > 0:

    percentual_saude = (
        validacoes_ok
        / total_validacoes
    ) * 100

else:

    percentual_saude = 0


print(
    f"Validacoes realizadas: "
    f"{total_validacoes}"
)

print(
    f"Validacoes OK: "
    f"{validacoes_ok}"
)

print(
    f"Validacoes com erro: "
    f"{validacoes_erro}"
)

print(
    f"Saude do projeto: "
    f"{percentual_saude:.2f}%"
)


# ============================================================
# 13. STATUS FINAL
# ============================================================

if validacoes_erro == 0:

    status_final = (
        "PROJETO VALIDADO"
    )

elif percentual_saude >= 90:

    status_final = (
        "PROJETO FUNCIONAL COM AJUSTES"
    )

else:

    status_final = (
        "PROJETO REQUER CORRECOES"
    )


print(
    f"Status final: "
    f"{status_final}"
)


# ============================================================
# 14. METRICAS DO MODELO FINAL
# ============================================================

metricas_modelo = {

    "dataset":
        "UNSW-NB15",

    "algoritmo":
        "DecisionTreeClassifier",

    "max_depth":
        5,

    "threshold":
        0.099,

    "features":
        9,

    "acuracia_percentual":
        92.42,

    "recall_percentual":
        99.55,

    "precision_percentual":
        90.30,

    "f1_score_percentual":
        94.70,

    "falsos_negativos":
        540,

    "falsos_positivos":
        12755

}


print("\n========================================")
print("MODELO FINAL")
print("========================================")


print(
    f"Dataset: "
    f"{metricas_modelo['dataset']}"
)

print(
    f"Algoritmo: "
    f"{metricas_modelo['algoritmo']}"
)

print(
    f"max_depth: "
    f"{metricas_modelo['max_depth']}"
)

print(
    f"Threshold: "
    f"{metricas_modelo['threshold']}"
)

print(
    f"Acuracia: "
    f"{metricas_modelo['acuracia_percentual']:.2f}%"
)

print(
    f"Recall: "
    f"{metricas_modelo['recall_percentual']:.2f}%"
)

print(
    f"Precision: "
    f"{metricas_modelo['precision_percentual']:.2f}%"
)

print(
    f"F1-Score: "
    f"{metricas_modelo['f1_score_percentual']:.2f}%"
)

print(
    f"Falsos Negativos: "
    f"{metricas_modelo['falsos_negativos']}"
)

print(
    f"Falsos Positivos: "
    f"{metricas_modelo['falsos_positivos']}"
)


# ============================================================
# 15. CAPACIDADES IMPLEMENTADAS
# ============================================================

capacidades = [

    "Treinamento de modelo de Machine Learning",

    "Deteccao binaria de trafego NORMAL ou ATAQUE",

    "Ajuste de threshold orientado a seguranca",

    "Deteccao por categoria de ataque",

    "Persistencia do modelo treinado",

    "Detector de eventos",

    "Deteccao em lote",

    "Pipeline de alertas SOC",

    "Processamento de eventos externos JSON",

    "API REST com FastAPI",

    "Cliente consumidor da API",

    "Monitoramento continuo",

    "Monitoramento de logs JSONL",

    "Processamento de novos eventos",

    "Correlacao de alertas",

    "Geracao de incidentes",

    "Calculo de Risk Score",

    "Priorizacao de incidentes",

    "Playbooks de resposta",

    "Enriquecimento de contexto",

    "Motor de regras SOC",

    "Decisao automatizada",

    "Case Management",

    "Orquestracao do pipeline"

]


print("\n========================================")
print("CAPACIDADES IMPLEMENTADAS")
print("========================================")


for indice, capacidade in enumerate(
    capacidades,
    start=1
):

    print(
        f"{indice:02d} - {capacidade}"
    )


# ============================================================
# 16. ARQUITETURA FINAL
# ============================================================

arquitetura = (
    "EVENTO -> API ML -> MODELO -> DETECCAO -> "
    "ALERTA -> CORRELACAO -> INCIDENTE -> "
    "RISK SCORE -> PRIORIZACAO -> PLAYBOOK -> "
    "ENRIQUECIMENTO -> MOTOR DE REGRAS -> "
    "DECISAO -> CASE MANAGEMENT"
)


print("\n========================================")
print("ARQUITETURA FINAL")
print("========================================")

print(
    arquitetura
)


# ============================================================
# 17. RELATORIO FINAL
# ============================================================

relatorio_final = {

    "projeto":
        "ML Cyber Detector",

    "versao":
        "1.0",

    "timestamp_validacao":
        datetime.now().isoformat(),

    "status_final":
        status_final,

    "saude_percentual":
        round(
            percentual_saude,
            2
        ),

    "validacoes_total":
        total_validacoes,

    "validacoes_ok":
        validacoes_ok,

    "validacoes_erro":
        validacoes_erro,

    "scripts_encontrados":
        scripts_encontrados,

    "scripts_esperados":
        len(scripts),

    "artefatos_encontrados":
        artefatos_encontrados,

    "artefatos_esperados":
        len(artefatos),

    "metricas_modelo":
        metricas_modelo,

    "pipeline_integrado":
        relatorio_pipeline,

    "quantidade_casos":
        len(casos),

    "casos":
        casos,

    "capacidades":
        capacidades,

    "arquitetura":
        arquitetura,

    "validacoes":
        validacoes

}


# ============================================================
# 18. SALVAR RELATORIO
# ============================================================

os.makedirs(
    PASTA_ALERTAS,
    exist_ok=True
)


with open(
    ARQUIVO_RELATORIO_FINAL,
    "w",
    encoding="utf-8"
) as arquivo:

    json.dump(
        relatorio_final,
        arquivo,
        indent=4,
        ensure_ascii=False
    )


print("\n========================================")
print("RELATORIO FINAL GERADO")
print("========================================")

print(
    f"Arquivo: "
    f"{ARQUIVO_RELATORIO_FINAL}"
)


# ============================================================
# 19. RESUMO FINAL
# ============================================================

print("\n========================================")
print("RESUMO FINAL DO LABORATORIO")
print("========================================")


print(
    "Projeto: ML Cyber Detector"
)

print(
    "Versao: 1.0"
)

print(
    f"Scripts: "
    f"{scripts_encontrados}/{len(scripts)}"
)

print(
    f"Artefatos SOC: "
    f"{artefatos_encontrados}/{len(artefatos)}"
)

print(
    f"Casos SOC: "
    f"{len(casos)}"
)

print(
    f"Saude: "
    f"{percentual_saude:.2f}%"
)

print(
    f"Status: "
    f"{status_final}"
)


# ============================================================
# FINAL
# ============================================================

print("\n========================================")
print("AULA 20 CONCLUIDA")
print("ML CYBER DETECTOR V1.0")
print("========================================")