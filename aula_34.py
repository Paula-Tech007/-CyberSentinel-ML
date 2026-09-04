# ============================================================
# CyberSentinel-ML
# AULA 34 - RISK SCORE V2
# ML + Threat Intelligence + IOC + Priorizacao SOC
# ============================================================

import json
import os
import sys
import time
from datetime import datetime, timezone
from ipaddress import ip_address
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import requests
from dotenv import load_dotenv


# ============================================================
# CONFIGURACAO GERAL
# ============================================================

PROJETO = "CyberSentinel-ML"
AULA = 34

BASE_DIR = Path(__file__).resolve().parent

ENV_FILE = BASE_DIR / ".env"

DIR_MODELOS = BASE_DIR / "modelos"
DIR_ALERTAS = BASE_DIR / "alertas"
DIR_RISK = BASE_DIR / "risk_scores"

MODELO_BINARIO_PATH = (
    DIR_MODELOS / "unsw_decision_tree.joblib"
)

CONFIG_BINARIA_PATH = (
    DIR_MODELOS / "configuracao_modelo.joblib"
)

MODELO_MULTICLASSE_PATH = (
    DIR_MODELOS / "unsw_attack_multiclass_otimizado.joblib"
)

CONFIG_MULTICLASSE_PATH = (
    DIR_MODELOS /
    "configuracao_multiclasse_otimizada_aula_22.joblib"
)

ARQUIVO_RISK = (
    DIR_RISK /
    "risk_scores_aula_34.json"
)

ARQUIVO_ALERTAS = (
    DIR_ALERTAS /
    "alertas_risk_score_aula_34.json"
)

ARQUIVO_RELATORIO = (
    DIR_ALERTAS /
    "relatorio_aula_34.json"
)

ABUSEIPDB_URL = (
    "https://api.abuseipdb.com/api/v2/check"
)

MAX_AGE_DAYS = 90
TIMEOUT_API = 10


# ============================================================
# PESOS DO RISK SCORE V2
# ============================================================

PESO_PROBABILIDADE_ML = 0.30
PESO_CONFIANCA_CATEGORIA = 0.15
PESO_CATEGORIA = 0.20
PESO_ABUSE_SCORE = 0.25
PESO_REPORTS = 0.10


# ============================================================
# PESO DE RISCO POR CATEGORIA
# ============================================================

RISCO_CATEGORIA = {
    "Analysis": 35,
    "Backdoor": 90,
    "DoS": 70,
    "Exploits": 95,
    "Fuzzers": 55,
    "Generic": 75,
    "Reconnaissance": 50,
    "Shellcode": 95,
    "Worms": 100
}


# ============================================================
# AMBIENTE
# ============================================================

load_dotenv(dotenv_path=ENV_FILE)

ABUSEIPDB_API_KEY = os.getenv(
    "ABUSEIPDB_API_KEY"
)


# ============================================================
# ESTADO
# ============================================================

modelo_binario = None
config_binaria = None

modelo_multiclasse = None
config_multiclasse = None

FEATURES = []
THRESHOLD = 0.5

risk_scores = []
alertas = []

estatisticas = {
    "eventos_recebidos": 0,
    "eventos_validos": 0,
    "eventos_invalidos": 0,
    "normais": 0,
    "ataques": 0,
    "consultas_ti": 0,
    "consultas_sucesso": 0,
    "consultas_erro": 0,
    "risk_scores_gerados": 0,
    "baixo": 0,
    "medio": 0,
    "alto": 0,
    "critico": 0,
    "alertas": 0
}


# ============================================================
# INTERFACE
# ============================================================

def titulo(texto):
    print("=" * 72)
    print(texto)
    print("=" * 72)


def subtitulo(texto):
    print()
    print("-" * 72)
    print(texto)
    print("-" * 72)


def agora_utc():
    return datetime.now(
        timezone.utc
    ).isoformat()


# ============================================================
# DIRETORIOS
# ============================================================

def preparar_diretorios():

    titulo(
        "ETAPA 1 - PREPARANDO DIRETORIOS"
    )

    for diretorio in [
        DIR_MODELOS,
        DIR_ALERTAS,
        DIR_RISK
    ]:

        diretorio.mkdir(
            parents=True,
            exist_ok=True
        )

        print(
            f"[OK] Diretorio "
            f"{diretorio.name} pronto"
        )


# ============================================================
# CONFIGURACAO
# ============================================================

def validar_configuracao():

    titulo(
        "ETAPA 2 - VALIDANDO CONFIGURACAO"
    )

    if not ENV_FILE.exists():

        print(
            "[ERRO] Arquivo .env nao encontrado"
        )

        return False

    print(
        "[OK] Arquivo .env encontrado"
    )

    if not ABUSEIPDB_API_KEY:

        print(
            "[ERRO] ABUSEIPDB_API_KEY "
            "nao encontrada"
        )

        return False

    print(
        "[OK] ABUSEIPDB_API_KEY carregada"
    )

    print(
        "[OK] API Key protegida"
    )

    soma_pesos = (
        PESO_PROBABILIDADE_ML
        + PESO_CONFIANCA_CATEGORIA
        + PESO_CATEGORIA
        + PESO_ABUSE_SCORE
        + PESO_REPORTS
    )

    if abs(soma_pesos - 1.0) > 0.0001:

        print(
            "[ERRO] Pesos do Risk Score "
            "nao totalizam 1.0"
        )

        return False

    print(
        "[OK] Pesos Risk Score V2: 100%"
    )

    return True


# ============================================================
# ARTEFATOS ML
# ============================================================

def validar_artefatos():

    titulo(
        "ETAPA 3 - VALIDANDO ARTEFATOS ML"
    )

    artefatos = [
        (
            "Modelo binario",
            MODELO_BINARIO_PATH
        ),
        (
            "Configuracao binaria",
            CONFIG_BINARIA_PATH
        ),
        (
            "Modelo multiclasse",
            MODELO_MULTICLASSE_PATH
        ),
        (
            "Configuracao multiclasse",
            CONFIG_MULTICLASSE_PATH
        )
    ]

    sucesso = True

    for nome, caminho in artefatos:

        if caminho.exists():

            print(
                f"[OK] {nome}: "
                f"{caminho.relative_to(BASE_DIR)}"
            )

        else:

            print(
                f"[ERRO] {nome} nao encontrado"
            )

            sucesso = False

    return sucesso


# ============================================================
# CARREGAMENTO ML
# ============================================================

def carregar_modelos():

    global modelo_binario
    global config_binaria
    global modelo_multiclasse
    global config_multiclasse
    global FEATURES
    global THRESHOLD

    titulo(
        "ETAPA 4 - CARREGANDO MODELOS"
    )

    try:

        modelo_binario = joblib.load(
            MODELO_BINARIO_PATH
        )

        config_binaria = joblib.load(
            CONFIG_BINARIA_PATH
        )

        modelo_multiclasse = joblib.load(
            MODELO_MULTICLASSE_PATH
        )

        config_multiclasse = joblib.load(
            CONFIG_MULTICLASSE_PATH
        )

    except Exception as erro:

        print(
            f"[ERRO] Falha ao carregar "
            f"modelos: {erro}"
        )

        return False

    if isinstance(
        config_binaria,
        dict
    ):

        FEATURES = (
            config_binaria.get("features")
            or config_binaria.get(
                "feature_names"
            )
            or []
        )

        THRESHOLD = float(
            config_binaria.get(
                "threshold",
                0.5
            )
        )

    if not FEATURES:

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

    print(
        "[OK] Modelo binario carregado"
    )

    print(
        "[OK] Modelo multiclasse carregado"
    )

    print(
        "[OK] Configuracoes carregadas"
    )

    print()

    print(
        f"Modelo binario: "
        f"{modelo_binario.__class__.__name__}"
    )

    print(
        f"Modelo multiclasse: "
        f"{modelo_multiclasse.__class__.__name__}"
    )

    print(
        f"Threshold: {THRESHOLD:.4f}"
    )

    print(
        f"Features: {len(FEATURES)}"
    )

    return True


# ============================================================
# VALIDACAO EVENTO
# ============================================================

def validar_evento(evento):

    if not isinstance(evento, dict):

        return False, "Evento invalido"

    for feature in FEATURES:

        if feature not in evento:

            return (
                False,
                f"Feature obrigatoria ausente: "
                f"{feature}"
            )

        try:

            valor = float(
                evento[feature]
            )

            if not np.isfinite(valor):

                return (
                    False,
                    f"Valor invalido: {feature}"
                )

        except (TypeError, ValueError):

            return (
                False,
                f"Feature nao numerica: "
                f"{feature}"
            )

    return True, "Evento valido"


def preparar_dataframe(evento):

    dados = {
        feature: [
            float(evento[feature])
        ]
        for feature in FEATURES
    }

    return pd.DataFrame(
        dados,
        columns=FEATURES
    )


# ============================================================
# PREDICAO BINARIA
# ============================================================

def predicao_binaria(df):

    probabilidades = (
        modelo_binario.predict_proba(df)[0]
    )

    classes = list(
        modelo_binario.classes_
    )

    if 1 in classes:
        indice = classes.index(1)

    elif "1" in classes:
        indice = classes.index("1")

    else:
        indice = 1

    probabilidade = float(
        probabilidades[indice]
    )

    classificacao = (
        "ATAQUE"
        if probabilidade >= THRESHOLD
        else "NORMAL"
    )

    return (
        classificacao,
        probabilidade
    )


# ============================================================
# PREDICAO MULTICLASSE
# ============================================================

def predicao_multiclasse(df):

    probabilidades = (
        modelo_multiclasse.predict_proba(df)[0]
    )

    indice = int(
        np.argmax(probabilidades)
    )

    classes = list(
        modelo_multiclasse.classes_
    )

    categoria = str(
        classes[indice]
    )

    confianca = float(
        probabilidades[indice]
    )

    return categoria, confianca


# ============================================================
# IP
# ============================================================

def analisar_ip(ip):

    try:

        endereco = ip_address(
            str(ip)
        )

    except ValueError:

        return {
            "valido": False,
            "publico": False,
            "tipo": "INVALIDO"
        }

    if endereco.is_private:

        return {
            "valido": True,
            "publico": False,
            "tipo": "PRIVADO"
        }

    if (
        endereco.is_loopback
        or endereco.is_multicast
        or endereco.is_unspecified
        or endereco.is_reserved
    ):

        return {
            "valido": True,
            "publico": False,
            "tipo": "ESPECIAL"
        }

    return {
        "valido": True,
        "publico": True,
        "tipo": "PUBLICO"
    }


# ============================================================
# THREAT INTELLIGENCE
# ============================================================

def consultar_abuseipdb(ip):

    estatisticas[
        "consultas_ti"
    ] += 1

    headers = {
        "Accept": "application/json",
        "Key": ABUSEIPDB_API_KEY
    }

    params = {
        "ipAddress": ip,
        "maxAgeInDays": MAX_AGE_DAYS
    }

    inicio = time.perf_counter()

    try:

        resposta = requests.get(
            ABUSEIPDB_URL,
            headers=headers,
            params=params,
            timeout=TIMEOUT_API
        )

        tempo_ms = (
            time.perf_counter()
            - inicio
        ) * 1000

        if resposta.status_code != 200:

            estatisticas[
                "consultas_erro"
            ] += 1

            return {
                "status": "ERRO",
                "http_status":
                    resposta.status_code,
                "tempo_ms":
                    round(tempo_ms, 4)
            }

        dados = resposta.json().get(
            "data",
            {}
        )

        estatisticas[
            "consultas_sucesso"
        ] += 1

        return {
            "status": "SUCESSO",
            "abuse_score": int(
                dados.get(
                    "abuseConfidenceScore",
                    0
                )
                or 0
            ),
            "reports": int(
                dados.get(
                    "totalReports",
                    0
                )
                or 0
            ),
            "pais":
                dados.get("countryCode"),
            "isp":
                dados.get("isp"),
            "dominio":
                dados.get("domain"),
            "tempo_ms":
                round(tempo_ms, 4)
        }

    except requests.exceptions.RequestException as erro:

        estatisticas[
            "consultas_erro"
        ] += 1

        return {
            "status": "ERRO",
            "erro": str(erro),
            "abuse_score": 0,
            "reports": 0
        }


# ============================================================
# NORMALIZACAO DE REPORTS
# ============================================================

def normalizar_reports(reports):

    """
    Converte quantidade de reports em score 0-100.

    0 reports       = 0
    1-4 reports     = 20
    5-19 reports    = 40
    20-49 reports   = 60
    50-99 reports   = 80
    100+ reports    = 100
    """

    if reports <= 0:
        return 0

    if reports < 5:
        return 20

    if reports < 20:
        return 40

    if reports < 50:
        return 60

    if reports < 100:
        return 80

    return 100


# ============================================================
# NIVEL DO RISK SCORE
# ============================================================

def classificar_risco(score):

    if score >= 80:
        return "CRITICO"

    if score >= 60:
        return "ALTO"

    if score >= 35:
        return "MEDIO"

    return "BAIXO"


# ============================================================
# RISK SCORE V2
# ============================================================

def calcular_risk_score(
    probabilidade,
    confianca,
    categoria,
    ti
):

    score_ml = (
        probabilidade * 100
    )

    score_confianca = (
        confianca * 100
    )

    score_categoria = (
        RISCO_CATEGORIA.get(
            categoria,
            50
        )
    )

    # Quando nao existe consulta externa,
    # nao tratamos a ausencia de TI como
    # evidencia de que o IP e seguro.
    if (
        ti
        and ti.get("status") == "SUCESSO"
    ):

        score_abuse = float(
            ti.get(
                "abuse_score",
                0
            )
        )

        score_reports = (
            normalizar_reports(
                int(
                    ti.get(
                        "reports",
                        0
                    )
                )
            )
        )

        componentes = {
            "probabilidade_ml": {
                "valor": round(
                    score_ml,
                    2
                ),
                "peso": 30
            },
            "confianca_categoria": {
                "valor": round(
                    score_confianca,
                    2
                ),
                "peso": 15
            },
            "risco_categoria": {
                "valor": score_categoria,
                "peso": 20
            },
            "abuse_score": {
                "valor": score_abuse,
                "peso": 25
            },
            "reports": {
                "valor": score_reports,
                "peso": 10
            }
        }

        score_final = (
            score_ml
            * PESO_PROBABILIDADE_ML
            +
            score_confianca
            * PESO_CONFIANCA_CATEGORIA
            +
            score_categoria
            * PESO_CATEGORIA
            +
            score_abuse
            * PESO_ABUSE_SCORE
            +
            score_reports
            * PESO_REPORTS
        )

        modo = "ML_TI"

    else:

        # Sem TI disponivel, redistribuimos os
        # pesos somente entre sinais conhecidos.

        soma_pesos_ml = (
            PESO_PROBABILIDADE_ML
            + PESO_CONFIANCA_CATEGORIA
            + PESO_CATEGORIA
        )

        peso_ml = (
            PESO_PROBABILIDADE_ML
            / soma_pesos_ml
        )

        peso_confianca = (
            PESO_CONFIANCA_CATEGORIA
            / soma_pesos_ml
        )

        peso_categoria = (
            PESO_CATEGORIA
            / soma_pesos_ml
        )

        score_final = (
            score_ml * peso_ml
            +
            score_confianca
            * peso_confianca
            +
            score_categoria
            * peso_categoria
        )

        componentes = {
            "probabilidade_ml": {
                "valor": round(
                    score_ml,
                    2
                ),
                "peso_efetivo":
                    round(
                        peso_ml * 100,
                        2
                    )
            },
            "confianca_categoria": {
                "valor": round(
                    score_confianca,
                    2
                ),
                "peso_efetivo":
                    round(
                        peso_confianca * 100,
                        2
                    )
            },
            "risco_categoria": {
                "valor":
                    score_categoria,
                "peso_efetivo":
                    round(
                        peso_categoria * 100,
                        2
                    )
            },
            "threat_intelligence": {
                "status":
                    "NAO_DISPONIVEL"
            }
        }

        modo = "SOMENTE_ML"

    score_final = max(
        0,
        min(
            100,
            score_final
        )
    )

    score_final = round(
        score_final,
        2
    )

    nivel = classificar_risco(
        score_final
    )

    return {
        "risk_score": score_final,
        "nivel_risco": nivel,
        "modo_calculo": modo,
        "componentes": componentes
    }


# ============================================================
# CONTADORES DE RISCO
# ============================================================

def registrar_nivel(nivel):

    mapa = {
        "BAIXO": "baixo",
        "MEDIO": "medio",
        "ALTO": "alto",
        "CRITICO": "critico"
    }

    chave = mapa.get(nivel)

    if chave:
        estatisticas[chave] += 1


# ============================================================
# PROCESSAMENTO
# ============================================================

def processar_evento(evento):

    estatisticas[
        "eventos_recebidos"
    ] += 1

    valido, erro = validar_evento(
        evento
    )

    if not valido:

        estatisticas[
            "eventos_invalidos"
        ] += 1

        return {
            "status": "REJEITADO",
            "id_evento":
                evento.get(
                    "id_evento",
                    "SEM-ID"
                ),
            "erro": erro
        }

    estatisticas[
        "eventos_validos"
    ] += 1

    df = preparar_dataframe(
        evento
    )

    classificacao, probabilidade = (
        predicao_binaria(df)
    )

    if classificacao == "NORMAL":

        estatisticas[
            "normais"
        ] += 1

        return {
            "status": "PROCESSADO",
            "id_evento":
                evento.get("id_evento"),
            "classificacao": "NORMAL",
            "probabilidade_ataque":
                round(
                    probabilidade,
                    6
                ),
            "alerta_soc": False
        }

    estatisticas[
        "ataques"
    ] += 1

    categoria, confianca = (
        predicao_multiclasse(df)
    )

    ip = evento.get(
        "ip_origem"
    )

    info_ip = analisar_ip(
        ip
    )

    ti = None

    if (
        info_ip["valido"]
        and info_ip["publico"]
    ):

        ti = consultar_abuseipdb(
            ip
        )

    else:

        ti = {
            "status":
                "NAO_CONSULTADO",
            "motivo":
                info_ip["tipo"],
            "abuse_score": 0,
            "reports": 0
        }

    risco = calcular_risk_score(
        probabilidade,
        confianca,
        categoria,
        ti
    )

    registrar_nivel(
        risco["nivel_risco"]
    )

    estatisticas[
        "risk_scores_gerados"
    ] += 1

    risk_id = (
        "RISK-"
        + datetime.now(
            timezone.utc
        ).strftime(
            "%Y%m%d%H%M%S%f"
        )
    )

    registro_risco = {
        "risk_id": risk_id,
        "id_evento":
            evento.get("id_evento"),
        "ip_origem": ip,
        "classificacao":
            classificacao,
        "probabilidade_ataque":
            round(
                probabilidade,
                6
            ),
        "categoria":
            categoria,
        "confianca_categoria":
            round(
                confianca,
                6
            ),
        "threat_intelligence":
            ti,
        "risk_score":
            risco["risk_score"],
        "nivel_risco":
            risco["nivel_risco"],
        "modo_calculo":
            risco["modo_calculo"],
        "componentes":
            risco["componentes"],
        "timestamp":
            agora_utc()
    }

    risk_scores.append(
        registro_risco
    )

    alerta_id = (
        "RISK-ALT-"
        + datetime.now(
            timezone.utc
        ).strftime(
            "%Y%m%d%H%M%S%f"
        )
    )

    alerta = {
        "projeto": PROJETO,
        "aula": AULA,
        "alerta_id": alerta_id,
        "id_evento":
            evento.get("id_evento"),
        "ip_origem": ip,
        "classificacao":
            classificacao,
        "categoria_ataque":
            categoria,
        "risk_score":
            risco["risk_score"],
        "nivel_risco":
            risco["nivel_risco"],
        "prioridade_soc":
            risco["nivel_risco"],
        "risk_id":
            risk_id,
        "alerta_soc": True,
        "timestamp":
            agora_utc()
    }

    alertas.append(
        alerta
    )

    estatisticas[
        "alertas"
    ] += 1

    return {
        **registro_risco,
        "alerta_id":
            alerta_id,
        "alerta_soc":
            True,
        "status":
            "PROCESSADO"
    }


# ============================================================
# EVENTOS DE TESTE
# ============================================================

def preparar_eventos():

    titulo(
        "ETAPA 5 - PREPARANDO EVENTOS"
    )

    eventos = [
        {
            "id_evento":
                "RISK-34-001",
            "origem":
                "LABORATORIO",
            "ip_origem":
                "8.8.8.8",
            "spkts": 10,
            "dpkts": 8,
            "sbytes": 1200,
            "dbytes": 900,
            "rate": 25.0,
            "sttl": 64,
            "dttl": 64,
            "sload": 5000.0,
            "dload": 4000.0
        },
        {
            "id_evento":
                "RISK-34-002",
            "origem":
                "LABORATORIO",
            "ip_origem":
                "1.1.1.1",
            "spkts": 2,
            "dpkts": 0,
            "sbytes": 800,
            "dbytes": 0,
            "rate": 5000.0,
            "sttl": 254,
            "dttl": 0,
            "sload": 950000.0,
            "dload": 0.0
        },
        {
            "id_evento":
                "RISK-34-003",
            "origem":
                "LABORATORIO",
            "ip_origem":
                "192.168.1.50",
            "spkts": 6,
            "dpkts": 2,
            "sbytes": 3500,
            "dbytes": 250,
            "rate": 1500.0,
            "sttl": 254,
            "dttl": 64,
            "sload": 350000.0,
            "dload": 25000.0
        }
    ]

    print(
        f"[OK] {len(eventos)} "
        f"eventos preparados"
    )

    for evento in eventos:

        print(
            f"- {evento['id_evento']} "
            f"| IP: {evento['ip_origem']}"
        )

    return eventos


# ============================================================
# EXECUCAO DO PIPELINE
# ============================================================

def executar_pipeline(eventos):

    titulo(
        "ETAPA 6 - EXECUTANDO RISK SCORE V2"
    )

    resultados = []

    for indice, evento in enumerate(
        eventos,
        start=1
    ):

        subtitulo(
            f"EVENTO {indice}/{len(eventos)}"
        )

        print(
            f"ID: {evento['id_evento']}"
        )

        print(
            f"IP: {evento['ip_origem']}"
        )

        resultado = processar_evento(
            evento
        )

        resultados.append(
            resultado
        )

        if (
            resultado["status"]
            == "REJEITADO"
        ):

            print(
                f"[ERRO] {resultado['erro']}"
            )

            continue

        print(
            f"Classificacao: "
            f"{resultado['classificacao']}"
        )

        if (
            resultado["classificacao"]
            == "NORMAL"
        ):

            print(
                "[OK] Evento normal"
            )

            continue

        print(
            f"Probabilidade ataque: "
            f"{resultado['probabilidade_ataque'] * 100:.2f}%"
        )

        print(
            f"Categoria: "
            f"{resultado['categoria']}"
        )

        print(
            f"Confianca categoria: "
            f"{resultado['confianca_categoria'] * 100:.2f}%"
        )

        ti = resultado[
            "threat_intelligence"
        ]

        print()

        print(
            "Threat Intelligence:"
        )

        print(
            f"Status: "
            f"{ti['status']}"
        )

        if ti[
            "status"
        ] == "SUCESSO":

            print(
                f"Abuse Score: "
                f"{ti['abuse_score']}%"
            )

            print(
                f"Reports: "
                f"{ti['reports']}"
            )

            print(
                f"Pais: "
                f"{ti['pais']}"
            )

            print(
                f"ISP: "
                f"{ti['isp']}"
            )

        else:

            print(
                f"Motivo: "
                f"{ti.get('motivo', 'ERRO')}"
            )

        print()

        print(
            "RISK SCORE V2:"
        )

        print(
            f"Score: "
            f"{resultado['risk_score']}/100"
        )

        print(
            f"Nivel: "
            f"{resultado['nivel_risco']}"
        )

        print(
            f"Modo: "
            f"{resultado['modo_calculo']}"
        )

        print(
            f"[OK] Alerta SOC: "
            f"{resultado['alerta_id']}"
        )

    return resultados


# ============================================================
# PERSISTENCIA
# ============================================================

def salvar_json(
    caminho,
    dados
):

    with open(
        caminho,
        "w",
        encoding="utf-8"
    ) as arquivo:

        json.dump(
            dados,
            arquivo,
            indent=4,
            ensure_ascii=False
        )


def persistir(resultados):

    titulo(
        "ETAPA 7 - PERSISTINDO RESULTADOS"
    )

    salvar_json(
        ARQUIVO_RISK,
        {
            "projeto": PROJETO,
            "aula": AULA,
            "versao_risk_score": "2.0",
            "timestamp":
                agora_utc(),
            "risk_scores":
                risk_scores
        }
    )

    print(
        "[OK] Risk Scores salvos"
    )

    print(
        f"Arquivo: "
        f"{ARQUIVO_RISK.relative_to(BASE_DIR)}"
    )

    salvar_json(
        ARQUIVO_ALERTAS,
        {
            "projeto": PROJETO,
            "aula": AULA,
            "timestamp":
                agora_utc(),
            "alertas":
                alertas
        }
    )

    print(
        "[OK] Alertas SOC salvos"
    )

    print(
        f"Arquivo: "
        f"{ARQUIVO_ALERTAS.relative_to(BASE_DIR)}"
    )

    salvar_json(
        ARQUIVO_RELATORIO,
        {
            "projeto": PROJETO,
            "aula": AULA,
            "timestamp":
                agora_utc(),
            "estatisticas":
                estatisticas,
            "resultados":
                resultados
        }
    )

    print(
        "[OK] Relatorio salvo"
    )

    print(
        f"Arquivo: "
        f"{ARQUIVO_RELATORIO.relative_to(BASE_DIR)}"
    )


# ============================================================
# VALIDACAO
# ============================================================

def validar_final():

    titulo(
        "ETAPA 8 - VALIDACAO FINAL"
    )

    validacoes = [
        (
            "Arquivo .env encontrado",
            ENV_FILE.exists()
        ),
        (
            "API Key carregada",
            bool(ABUSEIPDB_API_KEY)
        ),
        (
            "Modelo binario carregado",
            modelo_binario is not None
        ),
        (
            "Modelo multiclasse carregado",
            modelo_multiclasse is not None
        ),
        (
            "9 features configuradas",
            len(FEATURES) == 9
        ),
        (
            "Eventos processados",
            estatisticas[
                "eventos_recebidos"
            ] > 0
        ),
        (
            "Risk Scores gerados",
            estatisticas[
                "risk_scores_gerados"
            ] > 0
        ),
        (
            "Threat Intelligence executada",
            estatisticas[
                "consultas_ti"
            ] > 0
        ),
        (
            "Alertas SOC gerados",
            estatisticas[
                "alertas"
            ] > 0
        ),
        (
            "Arquivo Risk Score criado",
            ARQUIVO_RISK.exists()
        ),
        (
            "Arquivo de alertas criado",
            ARQUIVO_ALERTAS.exists()
        ),
        (
            "Relatorio criado",
            ARQUIVO_RELATORIO.exists()
        )
    ]

    ok = 0

    for nome, status in validacoes:

        if status:

            print(
                f"[OK] {nome}"
            )

            ok += 1

        else:

            print(
                f"[ERRO] {nome}"
            )

    total = len(
        validacoes
    )

    saude = (
        ok / total
    ) * 100

    print()

    print(
        f"Validacoes: {ok}/{total}"
    )

    print(
        f"Saude: {saude:.2f}%"
    )

    return (
        ok == total,
        ok,
        total,
        saude
    )


# ============================================================
# RESUMO
# ============================================================

def resumo(
    sucesso,
    ok,
    total,
    saude
):

    titulo(
        "RESUMO FINAL DA AULA 34"
    )

    print(
        f"Eventos recebidos: "
        f"{estatisticas['eventos_recebidos']}"
    )

    print(
        f"Eventos ATAQUE: "
        f"{estatisticas['ataques']}"
    )

    print(
        f"Risk Scores gerados: "
        f"{estatisticas['risk_scores_gerados']}"
    )

    print(
        f"Consultas Threat Intelligence: "
        f"{estatisticas['consultas_ti']}"
    )

    print(
        f"Consultas sucesso: "
        f"{estatisticas['consultas_sucesso']}"
    )

    print()

    print(
        "Distribuicao de risco:"
    )

    print(
        f"BAIXO: "
        f"{estatisticas['baixo']}"
    )

    print(
        f"MEDIO: "
        f"{estatisticas['medio']}"
    )

    print(
        f"ALTO: "
        f"{estatisticas['alto']}"
    )

    print(
        f"CRITICO: "
        f"{estatisticas['critico']}"
    )

    print()

    print(
        f"Alertas SOC: "
        f"{estatisticas['alertas']}"
    )

    print(
        f"Validacoes: {ok}/{total}"
    )

    print(
        f"Saude: {saude:.2f}%"
    )

    if sucesso:

        print(
            "Status: AULA 34 CONCLUIDA"
        )

    else:

        print(
            "Status: AULA 34 REQUER ATENCAO"
        )


# ============================================================
# ARQUITETURA
# ============================================================

def arquitetura():

    titulo(
        "ARQUITETURA DA AULA 34"
    )

    print(
        """
EVENTO
  |
  v
DETECTOR ML BINARIO
  |
  +------ NORMAL --------------------> FINALIZA
  |
  v
ATAQUE
  |
  v
CLASSIFICADOR MULTICLASSE
  |
  +-----------------------------+
  |                             |
  v                             v
PROBABILIDADE               CATEGORIA
CONFIANCA                   RISCO BASE
  |                             |
  +-------------+---------------+
                |
                v
          IP DE ORIGEM
                |
       +--------+--------+
       |                 |
       v                 v
     PUBLICO           PRIVADO
       |                 |
       v                 |
   AbuseIPDB             |
       |                 |
       v                 |
 ABUSE SCORE             |
 REPORTS                 |
       |                 |
       +--------+--------+
                |
                v
          RISK SCORE V2
                |
        SCORE DE 0 A 100
                |
                v
     +-----------------------+
     | BAIXO                 |
     | MEDIO                 |
     | ALTO                  |
     | CRITICO               |
     +-----------------------+
                |
                v
       PRIORIZACAO SOC
                |
                v
          ALERTA SOC
"""
    )


# ============================================================
# MAIN
# ============================================================

def main():

    titulo(
        "AULA 34 - RISK SCORE V2"
    )

    print(PROJETO)

    print(
        "ML + Threat Intelligence "
        "+ Priorizacao SOC"
    )

    print()

    print(
        "Objetivo:"
    )

    print(
        "Calcular um score de risco "
        "de 0 a 100 combinando ML, "
        "categoria do ataque e "
        "Threat Intelligence."
    )

    preparar_diretorios()

    if not validar_configuracao():
        sys.exit(1)

    if not validar_artefatos():
        sys.exit(1)

    if not carregar_modelos():
        sys.exit(1)

    eventos = preparar_eventos()

    resultados = executar_pipeline(
        eventos
    )

    persistir(
        resultados
    )

    (
        sucesso,
        ok,
        total,
        saude
    ) = validar_final()

    resumo(
        sucesso,
        ok,
        total,
        saude
    )

    arquitetura()

    titulo(
        "CYBERSENTINEL-ML"
    )

    print(
        "AULA 34 - RISK SCORE V2"
    )

    if sucesso:

        print(
            "AULA 34 CONCLUIDA"
        )

    else:

        print(
            "AULA 34 REQUER ATENCAO"
        )


# ============================================================
# EXECUCAO
# ============================================================

if __name__ == "__main__":
    main()