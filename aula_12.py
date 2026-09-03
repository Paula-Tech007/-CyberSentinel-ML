import json
import os
import time
from datetime import datetime

import requests


# ==========================================================
# AULA 12 - MONITOR CONTINUO DE NOVOS LOGS
# MACHINE LEARNING PARA SOC
# ==========================================================

print("\n========================================")
print("AULA 12 - MONITOR CONTINUO DE NOVOS LOGS")
print("MACHINE LEARNING PARA SOC")
print("========================================")


# ==========================================================
# 1. CONFIGURACAO
# ==========================================================

API_URL = "http://127.0.0.1:8000"

ENDPOINT_HEALTH = f"{API_URL}/health"
ENDPOINT_DETECCAO = f"{API_URL}/detectar"

ARQUIVO_EVENTOS = "eventos/eventos_rede.jsonl"

PASTA_ALERTAS = "alertas"

ARQUIVO_RESULTADOS = os.path.join(
    PASTA_ALERTAS,
    "resultados_aula_12.jsonl"
)

ARQUIVO_ALERTAS = os.path.join(
    PASTA_ALERTAS,
    "alertas_aula_12.jsonl"
)

INTERVALO_LEITURA = 1


print("\n========================================")
print("CONFIGURACAO")
print("========================================")

print(f"API: {API_URL}")
print(f"Endpoint: {ENDPOINT_DETECCAO}")
print(f"Arquivo monitorado: {ARQUIVO_EVENTOS}")
print(f"Intervalo de leitura: {INTERVALO_LEITURA} segundo")


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
# 3. GARANTINDO QUE O ARQUIVO EXISTA
# ==========================================================

if not os.path.exists(ARQUIVO_EVENTOS):

    with open(
        ARQUIVO_EVENTOS,
        "w",
        encoding="utf-8"
    ):
        pass

    print("\nArquivo de eventos criado:")
    print(ARQUIVO_EVENTOS)


# ==========================================================
# 4. VERIFICANDO API
# ==========================================================

print("\n========================================")
print("VERIFICANDO API")
print("========================================")

try:

    resposta = requests.get(
        ENDPOINT_HEALTH,
        timeout=5
    )

    if resposta.status_code == 200:

        print("API esta ONLINE!")
        print(f"Status HTTP: {resposta.status_code}")

    else:

        print("API respondeu com problema.")
        print(f"Status HTTP: {resposta.status_code}")

        raise SystemExit


except requests.exceptions.RequestException as erro:

    print("Nao foi possivel conectar com a API.")

    print(f"Erro: {erro}")

    print("\nExecute a API em outro terminal:")

    print(
        "uvicorn aula_08:app --reload"
    )

    raise SystemExit


# ==========================================================
# 5. FUNCAO PARA SALVAR JSONL
# ==========================================================

def salvar_jsonl(caminho, dados):

    with open(
        caminho,
        "a",
        encoding="utf-8"
    ) as arquivo:

        arquivo.write(
            json.dumps(
                dados,
                ensure_ascii=False
            )
            + "\n"
        )


# ==========================================================
# 6. FEATURES DO MODELO
# ==========================================================

FEATURES = [

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


# ==========================================================
# 7. CONTADORES
# ==========================================================

total_processados = 0
total_ataques = 0
total_normais = 0
total_erros = 0


# ==========================================================
# 8. PROCESSAR EVENTO
# ==========================================================

def processar_evento(evento_original):

    global total_processados
    global total_ataques
    global total_normais
    global total_erros


    id_evento = evento_original.get(
        "id_evento",
        f"EVT-{datetime.now().strftime('%Y%m%d%H%M%S%f')}"
    )


    print("\n========================================")
    print("NOVO EVENTO DETECTADO")
    print("========================================")

    print(f"ID: {id_evento}")

    print(
        "Horario:",
        datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )
    )


    # ======================================================
    # 9. VALIDANDO FEATURES
    # ======================================================

    faltantes = []

    for feature in FEATURES:

        if feature not in evento_original:

            faltantes.append(feature)


    if faltantes:

        print("\nEVENTO INVALIDO.")

        print("Features ausentes:")

        for feature in faltantes:

            print(f"- {feature}")

        total_erros += 1

        return


    # ======================================================
    # 10. PREPARANDO EVENTO PARA API
    # ======================================================

    evento_modelo = {}

    for feature in FEATURES:

        evento_modelo[feature] = (
            evento_original[feature]
        )


    print("\nEVENTO PREPARADO:")

    print(
        json.dumps(
            evento_modelo,
            indent=4,
            ensure_ascii=False
        )
    )


    # ======================================================
    # 11. ENVIANDO EVENTO PARA API
    # ======================================================

    print("\nEnviando evento para o modelo...")


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

            print(
                "Erro retornado pela API."
            )

            print(
                resposta.text
            )

            total_erros += 1

            return


        # ==================================================
        # 12. RECEBENDO RESULTADO
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
            "threshold"
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
        # 13. MOSTRANDO RESULTADO
        # ==================================================

        print("\n========================================")
        print("RESULTADO DA ANALISE")
        print("========================================")


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
        # 14. REGISTRO COMPLETO
        # ==================================================

        registro = {

            "timestamp":
                datetime.now().isoformat(),

            "id_evento":
                id_evento,

            "classificacao":
                classificacao,

            "probabilidade_ataque":
                probabilidade,

            "probabilidade_percentual":
                probabilidade_percentual,

            "threshold":
                threshold,

            "nivel_risco":
                nivel_risco,

            "modelo":
                modelo,

            "evento":
                evento_modelo

        }


        salvar_jsonl(
            ARQUIVO_RESULTADOS,
            registro
        )


        # ==================================================
        # 15. ATAQUE
        # ==================================================

        if classificacao == "ATAQUE":

            total_ataques += 1


            alerta = {

                "timestamp_alerta":
                    datetime.now().isoformat(),

                "id_evento":
                    id_evento,

                "tipo_alerta":
                    "ML_NETWORK_ATTACK",

                "origem":
                    "MONITOR_CONTINUO_JSONL",

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


            salvar_jsonl(
                ARQUIVO_ALERTAS,
                alerta
            )


            print("\n>>> ALERTA SOC GERADO <<<")


            if nivel_risco == "CRITICO":

                print(
                    ">>> ALERTA CRITICO <<<"
                )


        # ==================================================
        # 16. NORMAL
        # ==================================================

        else:

            total_normais += 1

            print(
                "\nEvento considerado NORMAL."
            )


    except requests.exceptions.RequestException as erro:

        total_erros += 1

        print(
            "\nERRO DE COMUNICACAO COM A API"
        )

        print(
            f"Detalhes: {erro}"
        )


# ==========================================================
# 17. DESCOBRINDO QUANTAS LINHAS JA EXISTEM
# ==========================================================

with open(
    ARQUIVO_EVENTOS,
    "r",
    encoding="utf-8"
) as arquivo:

    linhas_iniciais = arquivo.readlines()


ultima_linha_processada = len(
    linhas_iniciais
)


print("\n========================================")
print("ESTADO INICIAL")
print("========================================")

print(
    f"Linhas existentes no arquivo: "
    f"{ultima_linha_processada}"
)

print(
    "Essas linhas serao ignoradas."
)

print(
    "Somente novos eventos serao processados."
)


# ==========================================================
# 18. MONITOR CONTINUO
# ==========================================================

print("\n========================================")
print("MONITOR CONTINUO INICIADO")
print("========================================")

print(
    "Aguardando novos eventos..."
)

print(
    "Para encerrar pressione CTRL + C."
)


try:

    while True:


        # ==================================================
        # ABRE O ARQUIVO
        # LE
        # FECHA
        # ==================================================

        try:

            with open(
                ARQUIVO_EVENTOS,
                "r",
                encoding="utf-8"
            ) as arquivo:

                linhas = arquivo.readlines()


        except PermissionError:

            time.sleep(
                INTERVALO_LEITURA
            )

            continue


        # ==================================================
        # VERIFICANDO NOVAS LINHAS
        # ==================================================

        quantidade_atual = len(
            linhas
        )


        if quantidade_atual > ultima_linha_processada:


            novas_linhas = linhas[
                ultima_linha_processada:
            ]


            print("\n========================================")
            print("NOVAS LINHAS ENCONTRADAS")
            print("========================================")

            print(
                f"Quantidade: {len(novas_linhas)}"
            )


            for linha in novas_linhas:


                linha = linha.strip()


                if not linha:

                    continue


                # ==========================================
                # CONVERTENDO JSON
                # ==========================================

                try:

                    evento = json.loads(
                        linha
                    )


                except json.JSONDecodeError as erro:

                    total_erros += 1

                    print(
                        "\nJSON INVALIDO RECEBIDO."
                    )

                    print(
                        f"Erro: {erro}"
                    )

                    continue


                # ==========================================
                # PROCESSANDO
                # ==========================================

                processar_evento(
                    evento
                )


            ultima_linha_processada = (
                quantidade_atual
            )


        # ==================================================
        # ARQUIVO DIMINUIU OU FOI LIMPO
        # ==================================================

        elif quantidade_atual < ultima_linha_processada:

            print("\n========================================")
            print("ARQUIVO FOI REDUZIDO OU LIMPO")
            print("========================================")

            ultima_linha_processada = (
                quantidade_atual
            )


        time.sleep(
            INTERVALO_LEITURA
        )


# ==========================================================
# 19. CTRL + C
# ==========================================================

except KeyboardInterrupt:


    print("\n\n========================================")
    print("MONITORAMENTO ENCERRADO")
    print("========================================")


    print("\nRESUMO DA EXECUCAO:")


    print(
        f"Eventos processados: "
        f"{total_processados}"
    )


    print(
        f"Ataques detectados: "
        f"{total_ataques}"
    )


    print(
        f"Eventos normais: "
        f"{total_normais}"
    )


    print(
        f"Erros: "
        f"{total_erros}"
    )


    print("\nARQUIVOS GERADOS:")

    print(
        f"Resultados: {ARQUIVO_RESULTADOS}"
    )

    print(
        f"Alertas: {ARQUIVO_ALERTAS}"
    )


# ==========================================================
# FINAL
# ==========================================================

print("\n========================================")
print("AULA 12 CONCLUIDA")
print("MONITOR CONTINUO FINALIZADO")
print("========================================")