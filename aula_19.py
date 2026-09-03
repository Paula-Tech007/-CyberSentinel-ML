import subprocess
import sys
import os
import json
from datetime import datetime


# ============================================================
# AULA 19 - PIPELINE INTEGRADO SOC
# ORQUESTRACAO AUTOMATICA
# ============================================================

print("\n========================================")
print("AULA 19 - PIPELINE INTEGRADO SOC")
print("ORQUESTRACAO AUTOMATICA")
print("========================================")


# ============================================================
# 1. CONFIGURACAO DO PIPELINE
# ============================================================

ETAPAS = [
    {
        "ordem": 1,
        "arquivo": "aula_13.py",
        "nome": "CORRELACAO DE EVENTOS",
        "saida": "alertas/incidentes_aula_13.json"
    },
    {
        "ordem": 2,
        "arquivo": "aula_14.py",
        "nome": "PRIORIZACAO DE INCIDENTES",
        "saida": "alertas/incidentes_priorizados_aula_14.json"
    },
    {
        "ordem": 3,
        "arquivo": "aula_15.py",
        "nome": "PLAYBOOK DE RESPOSTA SOC",
        "saida": "alertas/respostas_aula_15.json"
    },
    {
        "ordem": 4,
        "arquivo": "aula_16.py",
        "nome": "ENRIQUECIMENTO DE INCIDENTES",
        "saida": "alertas/incidentes_enriquecidos_aula_16.json"
    },
    {
        "ordem": 5,
        "arquivo": "aula_17.py",
        "nome": "MOTOR DE REGRAS SOC",
        "saida": "alertas/decisoes_aula_17.json"
    },
    {
        "ordem": 6,
        "arquivo": "aula_18.py",
        "nome": "GESTAO DE CASOS SOC",
        "saida": "alertas/casos_aula_18.json"
    }
]


ARQUIVO_RELATORIO = "alertas/relatorio_pipeline_aula_19.json"


# ============================================================
# 2. VERIFICAR ARQUIVOS
# ============================================================

print("\n========================================")
print("VERIFICANDO COMPONENTES")
print("========================================")


arquivos_ok = True


for etapa in ETAPAS:

    arquivo = etapa["arquivo"]

    if os.path.exists(arquivo):

        print(f"[OK] {arquivo}")

    else:

        print(f"[ERRO] {arquivo} nao encontrado")
        arquivos_ok = False


if not arquivos_ok:

    print("\nPipeline cancelado.")
    print("Existem componentes ausentes.")

    raise SystemExit(1)


print("\nTodos os componentes foram encontrados.")


# ============================================================
# 3. VERIFICAR API
# ============================================================

print("\n========================================")
print("IMPORTANTE")
print("========================================")

print("A API ML precisa estar ONLINE.")
print("O aula_13.py utiliza:")
print("http://127.0.0.1:8000/detectar")


# ============================================================
# 4. EXECUTAR PIPELINE
# ============================================================

print("\n========================================")
print("INICIANDO PIPELINE SOC")
print("========================================")


inicio_pipeline = datetime.now()

resultados_pipeline = []

pipeline_sucesso = True


for etapa in ETAPAS:

    print("\n========================================")
    print(
        f"ETAPA {etapa['ordem']}/{len(ETAPAS)}"
    )
    print(etapa["nome"])
    print("========================================")

    print(
        f"Executando: {etapa['arquivo']}"
    )

    inicio_etapa = datetime.now()

    try:

        processo = subprocess.run(
            [
                sys.executable,
                etapa["arquivo"]
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace"
        )

        fim_etapa = datetime.now()

        duracao = (
            fim_etapa - inicio_etapa
        ).total_seconds()


        # ====================================================
        # SUCESSO
        # ====================================================

        if processo.returncode == 0:

            print(
                f"[OK] {etapa['nome']}"
            )

            print(
                f"Tempo: {duracao:.2f} segundos"
            )

            arquivo_saida_existe = os.path.exists(
                etapa["saida"]
            )

            if arquivo_saida_existe:

                print(
                    f"[OK] Saida: {etapa['saida']}"
                )

            else:

                print(
                    f"[AVISO] Saida esperada nao encontrada: "
                    f"{etapa['saida']}"
                )


            resultado = {

                "ordem":
                    etapa["ordem"],

                "arquivo":
                    etapa["arquivo"],

                "nome":
                    etapa["nome"],

                "status":
                    "SUCESSO",

                "returncode":
                    processo.returncode,

                "duracao_segundos":
                    round(duracao, 2),

                "arquivo_saida":
                    etapa["saida"],

                "arquivo_saida_existe":
                    arquivo_saida_existe

            }


            resultados_pipeline.append(
                resultado
            )


        # ====================================================
        # ERRO
        # ====================================================

        else:

            print(
                f"[ERRO] Falha em {etapa['nome']}"
            )

            print(
                f"Codigo de retorno: "
                f"{processo.returncode}"
            )

            if processo.stdout:

                print("\nSAIDA:")
                print(processo.stdout)

            if processo.stderr:

                print("\nERRO:")
                print(processo.stderr)


            resultado = {

                "ordem":
                    etapa["ordem"],

                "arquivo":
                    etapa["arquivo"],

                "nome":
                    etapa["nome"],

                "status":
                    "ERRO",

                "returncode":
                    processo.returncode,

                "duracao_segundos":
                    round(duracao, 2),

                "erro":
                    processo.stderr

            }


            resultados_pipeline.append(
                resultado
            )

            pipeline_sucesso = False

            print("\nPipeline interrompido.")

            break


    except Exception as erro:

        fim_etapa = datetime.now()

        duracao = (
            fim_etapa - inicio_etapa
        ).total_seconds()


        print(
            f"[ERRO] Excecao durante a execucao:"
        )

        print(erro)


        resultados_pipeline.append({

            "ordem":
                etapa["ordem"],

            "arquivo":
                etapa["arquivo"],

            "nome":
                etapa["nome"],

            "status":
                "EXCECAO",

            "duracao_segundos":
                round(duracao, 2),

            "erro":
                str(erro)

        })


        pipeline_sucesso = False

        break


# ============================================================
# 5. TEMPO TOTAL
# ============================================================

fim_pipeline = datetime.now()

duracao_total = (
    fim_pipeline - inicio_pipeline
).total_seconds()


# ============================================================
# 6. CARREGAR RESULTADO FINAL
# ============================================================

casos_finais = []


if os.path.exists(
    "alertas/casos_aula_18.json"
):

    try:

        with open(
            "alertas/casos_aula_18.json",
            "r",
            encoding="utf-8"
        ) as arquivo:

            casos_finais = json.load(
                arquivo
            )

    except Exception as erro:

        print(
            "\nNao foi possivel carregar "
            "os casos finais."
        )

        print(erro)


# ============================================================
# 7. RESUMO DO PIPELINE
# ============================================================

print("\n========================================")
print("RESUMO DO PIPELINE")
print("========================================")


print(
    f"Etapas previstas: {len(ETAPAS)}"
)

print(
    f"Etapas executadas: "
    f"{len(resultados_pipeline)}"
)


sucessos = sum(

    1

    for resultado
    in resultados_pipeline

    if resultado["status"]
    == "SUCESSO"
)


erros = sum(

    1

    for resultado
    in resultados_pipeline

    if resultado["status"]
    != "SUCESSO"
)


print(
    f"Etapas com sucesso: {sucessos}"
)

print(
    f"Etapas com erro: {erros}"
)

print(
    f"Tempo total: "
    f"{duracao_total:.2f} segundos"
)


if pipeline_sucesso:

    print(
        "Status final: PIPELINE CONCLUIDO"
    )

else:

    print(
        "Status final: PIPELINE COM ERRO"
    )


# ============================================================
# 8. STATUS DAS ETAPAS
# ============================================================

print("\n========================================")
print("STATUS DAS ETAPAS")
print("========================================")


for resultado in resultados_pipeline:

    print(
        f"ETAPA {resultado['ordem']} | "
        f"{resultado['nome']} | "
        f"{resultado['status']} | "
        f"{resultado['duracao_segundos']}s"
    )


# ============================================================
# 9. CASOS FINAIS
# ============================================================

print("\n========================================")
print("CASOS SOC RESULTANTES")
print("========================================")


print(
    f"Quantidade de casos: "
    f"{len(casos_finais)}"
)


for caso in casos_finais:

    print("\n----------------------------------------")

    print(
        f"Caso: {caso.get('id_caso')}"
    )

    print(
        f"Incidente: {caso.get('id_incidente')}"
    )

    print(
        f"Status: {caso.get('status')}"
    )

    print(
        f"Prioridade: {caso.get('prioridade')}"
    )

    print(
        f"Severidade: {caso.get('severidade')}"
    )

    print(
        f"Score: {caso.get('score_final')}/100"
    )

    print(
        f"Responsavel: {caso.get('responsavel')}"
    )

    print(
        f"SLA: {caso.get('sla_minutos')} minutos"
    )


# ============================================================
# 10. RELATORIO FINAL
# ============================================================

relatorio = {

    "aula":
        19,

    "tipo":
        "PIPELINE_INTEGRADO_SOC",

    "timestamp_inicio":
        inicio_pipeline.isoformat(),

    "timestamp_fim":
        fim_pipeline.isoformat(),

    "duracao_total_segundos":
        round(duracao_total, 2),

    "pipeline_sucesso":
        pipeline_sucesso,

    "etapas_previstas":
        len(ETAPAS),

    "etapas_executadas":
        len(resultados_pipeline),

    "etapas_sucesso":
        sucessos,

    "etapas_erro":
        erros,

    "resultados":
        resultados_pipeline,

    "quantidade_casos":
        len(casos_finais),

    "casos_finais":
        casos_finais

}


# ============================================================
# 11. SALVAR RELATORIO
# ============================================================

os.makedirs(
    "alertas",
    exist_ok=True
)


with open(
    ARQUIVO_RELATORIO,
    "w",
    encoding="utf-8"
) as arquivo:

    json.dump(
        relatorio,
        arquivo,
        indent=4,
        ensure_ascii=False
    )


print("\n========================================")
print("RELATORIO GERADO")
print("========================================")

print(
    f"Arquivo: {ARQUIVO_RELATORIO}"
)


# ============================================================
# 12. ARQUITETURA FINAL
# ============================================================

print("\n========================================")
print("ARQUITETURA EXECUTADA")
print("========================================")

print(
    "EVENTOS"
    " -> API ML"
    " -> DETECCAO"
    " -> ALERTAS"
    " -> CORRELACAO"
    " -> INCIDENTE"
    " -> RISK SCORE"
    " -> PRIORIZACAO"
    " -> PLAYBOOK"
    " -> ENRIQUECIMENTO"
    " -> MOTOR DE REGRAS"
    " -> DECISAO"
    " -> CASE MANAGEMENT"
)


# ============================================================
# FINAL
# ============================================================

print("\n========================================")

if pipeline_sucesso:

    print("AULA 19 CONCLUIDA")
    print("PIPELINE SOC EXECUTADO COM SUCESSO")

else:

    print("AULA 19 FINALIZADA")
    print("PIPELINE SOC APRESENTOU ERRO")

print("========================================")