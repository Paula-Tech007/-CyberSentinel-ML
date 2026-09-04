# ============================================================
# CyberSentinel-ML
# AULA 33 - IOC ENRICHMENT
# ML + Threat Intelligence + IOC Context
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
AULA = 33

BASE_DIR = Path(__file__).resolve().parent

ENV_FILE = BASE_DIR / ".env"

DIRETORIO_MODELOS = BASE_DIR / "modelos"
DIRETORIO_ALERTAS = BASE_DIR / "alertas"
DIRETORIO_THREAT_INTEL = BASE_DIR / "threat_intel"
DIRETORIO_IOCS = BASE_DIR / "iocs"

MODELO_BINARIO_PATH = (
    DIRETORIO_MODELOS / "unsw_decision_tree.joblib"
)

CONFIG_BINARIA_PATH = (
    DIRETORIO_MODELOS / "configuracao_modelo.joblib"
)

MODELO_MULTICLASSE_PATH = (
    DIRETORIO_MODELOS /
    "unsw_attack_multiclass_otimizado.joblib"
)

CONFIG_MULTICLASSE_PATH = (
    DIRETORIO_MODELOS /
    "configuracao_multiclasse_otimizada_aula_22.joblib"
)

ARQUIVO_IOCS = (
    DIRETORIO_IOCS /
    "iocs_enriquecidos_aula_33.json"
)

ARQUIVO_ALERTAS = (
    DIRETORIO_ALERTAS /
    "alertas_ioc_aula_33.json"
)

ARQUIVO_RELATORIO = (
    DIRETORIO_ALERTAS /
    "relatorio_aula_33.json"
)

ABUSEIPDB_URL = (
    "https://api.abuseipdb.com/api/v2/check"
)

MAX_AGE_DAYS = 90
TIMEOUT_API = 10


# ============================================================
# CARREGANDO .ENV
# ============================================================

load_dotenv(dotenv_path=ENV_FILE)

ABUSEIPDB_API_KEY = os.getenv(
    "ABUSEIPDB_API_KEY"
)


# ============================================================
# VARIAVEIS GLOBAIS
# ============================================================

modelo_binario = None
config_binaria = None

modelo_multiclasse = None
config_multiclasse = None

FEATURES = []
THRESHOLD = 0.5

iocs_enriquecidos = []
alertas_gerados = []

estatisticas = {
    "eventos_recebidos": 0,
    "eventos_validos": 0,
    "eventos_invalidos": 0,
    "normais": 0,
    "ataques": 0,
    "iocs_extraidos": 0,
    "iocs_publicos": 0,
    "iocs_privados": 0,
    "iocs_enriquecidos": 0,
    "consultas_abuseipdb": 0,
    "consultas_sucesso": 0,
    "consultas_erro": 0,
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

    diretorios = [
        DIRETORIO_MODELOS,
        DIRETORIO_ALERTAS,
        DIRETORIO_THREAT_INTEL,
        DIRETORIO_IOCS
    ]

    for diretorio in diretorios:

        diretorio.mkdir(
            parents=True,
            exist_ok=True
        )

        print(
            f"[OK] Diretorio "
            f"{diretorio.name} pronto"
        )


# ============================================================
# .ENV
# ============================================================

def validar_env():

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
# CARREGANDO ML
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
            f"artefatos: {erro}"
        )

        return False

    print(
        "[OK] Modelo binario carregado"
    )

    print(
        "[OK] Configuracao binaria carregada"
    )

    print(
        "[OK] Modelo multiclasse carregado"
    )

    print(
        "[OK] Configuracao multiclasse carregada"
    )

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
        f"Threshold: "
        f"{THRESHOLD:.4f}"
    )

    print(
        f"Features: "
        f"{len(FEATURES)}"
    )

    return True


# ============================================================
# EVENTO
# ============================================================

def validar_evento(evento):

    if not isinstance(
        evento,
        dict
    ):

        return (
            False,
            "Evento invalido"
        )

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

            if not np.isfinite(
                valor
            ):

                return (
                    False,
                    f"Valor invalido: {feature}"
                )

        except (
            TypeError,
            ValueError
        ):

            return (
                False,
                f"Feature nao numerica: "
                f"{feature}"
            )

    return (
        True,
        "Evento valido"
    )


def preparar_dataframe(evento):

    dados = {}

    for feature in FEATURES:

        dados[feature] = [
            float(
                evento[feature]
            )
        ]

    return pd.DataFrame(
        dados,
        columns=FEATURES
    )


# ============================================================
# MODELO BINARIO
# ============================================================

def predicao_binaria(df):

    probabilidades = (
        modelo_binario.predict_proba(
            df
        )[0]
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
# MODELO MULTICLASSE
# ============================================================

def predicao_multiclasse(df):

    probabilidades = (
        modelo_multiclasse.predict_proba(
            df
        )[0]
    )

    indice = int(
        np.argmax(
            probabilidades
        )
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

    return (
        categoria,
        confianca
    )


# ============================================================
# IOC
# ============================================================

def classificar_ip(ip):

    try:

        endereco = ip_address(
            str(ip)
        )

    except ValueError:

        return {
            "valido": False,
            "tipo": "INVALIDO",
            "publico": False
        }

    if endereco.is_private:

        return {
            "valido": True,
            "tipo": "IP_PRIVADO",
            "publico": False
        }

    if (
        endereco.is_loopback
        or endereco.is_multicast
        or endereco.is_unspecified
        or endereco.is_reserved
    ):

        return {
            "valido": True,
            "tipo": "IP_ESPECIAL",
            "publico": False
        }

    return {
        "valido": True,
        "tipo": "IP_PUBLICO",
        "publico": True
    }


def extrair_ioc(evento):

    ip = evento.get(
        "ip_origem"
    )

    if not ip:

        return None

    classificacao = classificar_ip(
        ip
    )

    estatisticas[
        "iocs_extraidos"
    ] += 1

    if classificacao[
        "publico"
    ]:

        estatisticas[
            "iocs_publicos"
        ] += 1

    elif classificacao[
        "tipo"
    ] == "IP_PRIVADO":

        estatisticas[
            "iocs_privados"
        ] += 1

    return {
        "ioc_id": (
            f"IOC-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f')}"
        ),
        "tipo_ioc": "IP",
        "valor": str(ip),
        "classificacao":
            classificacao[
                "tipo"
            ],
        "publico":
            classificacao[
                "publico"
            ],
        "valido":
            classificacao[
                "valido"
            ],
        "extraido_em":
            agora_utc()
    }


# ============================================================
# ABUSEIPDB
# ============================================================

def consultar_abuseipdb(ip):

    estatisticas[
        "consultas_abuseipdb"
    ] += 1

    headers = {
        "Accept": "application/json",
        "Key": ABUSEIPDB_API_KEY
    }

    params = {
        "ipAddress": ip,
        "maxAgeInDays":
            MAX_AGE_DAYS
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
                    round(
                        tempo_ms,
                        4
                    )
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
            "http_status": 200,
            "tempo_ms":
                round(
                    tempo_ms,
                    4
                ),
            "dados": dados
        }

    except requests.exceptions.RequestException as erro:

        estatisticas[
            "consultas_erro"
        ] += 1

        return {
            "status": "ERRO",
            "erro": str(erro)
        }


# ============================================================
# REPUTACAO IOC
# ============================================================

def calcular_reputacao(score):

    if score >= 80:
        return "MALICIOSO"

    if score >= 50:
        return "ALTO_RISCO"

    if score >= 20:
        return "SUSPEITO"

    if score > 0:
        return "BAIXO_RISCO"

    return "SEM_EVIDENCIA"


# ============================================================
# ENRIQUECIMENTO IOC
# ============================================================

def enriquecer_ioc(ioc):

    if not ioc:

        return None

    ioc_enriquecido = {
        **ioc,
        "fonte_enriquecimento":
            None,
        "status_enriquecimento":
            "NAO_CONSULTADO",
        "reputacao":
            "NAO_AVALIADO",
        "threat_intelligence":
            None
    }

    if not ioc[
        "valido"
    ]:

        ioc_enriquecido[
            "status_enriquecimento"
        ] = "IOC_INVALIDO"

        return ioc_enriquecido

    if not ioc[
        "publico"
    ]:

        ioc_enriquecido[
            "status_enriquecimento"
        ] = "IOC_INTERNO"

        ioc_enriquecido[
            "reputacao"
        ] = "NAO_APLICAVEL"

        iocs_enriquecidos.append(
            ioc_enriquecido
        )

        return ioc_enriquecido

    consulta = consultar_abuseipdb(
        ioc["valor"]
    )

    if consulta[
        "status"
    ] != "SUCESSO":

        ioc_enriquecido[
            "fonte_enriquecimento"
        ] = "AbuseIPDB"

        ioc_enriquecido[
            "status_enriquecimento"
        ] = "ERRO"

        ioc_enriquecido[
            "erro"
        ] = consulta.get(
            "erro",
            "Erro na consulta"
        )

        iocs_enriquecidos.append(
            ioc_enriquecido
        )

        return ioc_enriquecido

    dados = consulta[
        "dados"
    ]

    score = int(
        dados.get(
            "abuseConfidenceScore",
            0
        )
        or 0
    )

    reputacao = calcular_reputacao(
        score
    )

    ioc_enriquecido[
        "fonte_enriquecimento"
    ] = "AbuseIPDB"

    ioc_enriquecido[
        "status_enriquecimento"
    ] = "SUCESSO"

    ioc_enriquecido[
        "reputacao"
    ] = reputacao

    ioc_enriquecido[
        "threat_intelligence"
    ] = {
        "abuse_confidence_score":
            score,

        "total_reports":
            dados.get(
                "totalReports",
                0
            ),

        "last_reported_at":
            dados.get(
                "lastReportedAt"
            ),

        "country_code":
            dados.get(
                "countryCode"
            ),

        "country_name":
            dados.get(
                "countryName"
            ),

        "isp":
            dados.get(
                "isp"
            ),

        "domain":
            dados.get(
                "domain"
            ),

        "usage_type":
            dados.get(
                "usageType"
            ),

        "is_whitelisted":
            dados.get(
                "isWhitelisted"
            ),

        "tempo_consulta_ms":
            consulta.get(
                "tempo_ms"
            )
    }

    estatisticas[
        "iocs_enriquecidos"
    ] += 1

    iocs_enriquecidos.append(
        ioc_enriquecido
    )

    return ioc_enriquecido


# ============================================================
# SEVERIDADE
# ============================================================

def calcular_severidade(
    probabilidade,
    confianca
):

    score = (
        probabilidade * 0.60
        +
        confianca * 0.40
    )

    if score >= 0.75:
        return "CRITICO"

    if score >= 0.40:
        return "ALTO"

    if score >= 0.20:
        return "MEDIO"

    return "BAIXO"


def ajustar_severidade_ioc(
    severidade,
    ioc
):

    if not ioc:

        return severidade

    reputacao = ioc.get(
        "reputacao"
    )

    if reputacao == "MALICIOSO":

        return "CRITICO"

    if reputacao == "ALTO_RISCO":

        if severidade in [
            "BAIXO",
            "MEDIO"
        ]:

            return "ALTO"

    if reputacao == "SUSPEITO":

        if severidade == "BAIXO":

            return "MEDIO"

    return severidade


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
        predicao_binaria(
            df
        )
    )

    if classificacao == "NORMAL":

        estatisticas[
            "normais"
        ] += 1

        return {
            "status": "PROCESSADO",
            "id_evento":
                evento.get(
                    "id_evento"
                ),
            "classificacao":
                "NORMAL",
            "probabilidade_ataque":
                round(
                    probabilidade,
                    6
                ),
            "alerta_soc":
                False,
            "ioc":
                None
        }

    estatisticas[
        "ataques"
    ] += 1

    categoria, confianca = (
        predicao_multiclasse(
            df
        )
    )

    severidade_ml = (
        calcular_severidade(
            probabilidade,
            confianca
        )
    )

    ioc = extrair_ioc(
        evento
    )

    ioc_enriquecido = (
        enriquecer_ioc(
            ioc
        )
    )

    severidade_final = (
        ajustar_severidade_ioc(
            severidade_ml,
            ioc_enriquecido
        )
    )

    alerta_id = (
        f"IOC-ALT-"
        f"{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f')}"
    )

    alerta = {
        "projeto": PROJETO,
        "aula": AULA,
        "status": "PROCESSADO",
        "alerta_soc": True,
        "alerta_id": alerta_id,

        "id_evento":
            evento.get(
                "id_evento"
            ),

        "origem":
            evento.get(
                "origem",
                "DESCONHECIDA"
            ),

        "classificacao":
            classificacao,

        "probabilidade_ataque":
            round(
                probabilidade,
                6
            ),

        "probabilidade_ataque_percentual":
            round(
                probabilidade * 100,
                2
            ),

        "categoria_ataque":
            categoria,

        "confianca_categoria":
            round(
                confianca,
                6
            ),

        "confianca_categoria_percentual":
            round(
                confianca * 100,
                2
            ),

        "severidade_ml":
            severidade_ml,

        "severidade_final":
            severidade_final,

        "ioc":
            ioc_enriquecido,

        "timestamp":
            agora_utc()
    }

    alertas_gerados.append(
        alerta
    )

    estatisticas[
        "alertas"
    ] += 1

    return alerta


# ============================================================
# EVENTOS DE LABORATORIO
# ============================================================

def preparar_eventos():

    titulo(
        "ETAPA 5 - PREPARANDO EVENTOS"
    )

    eventos = [
        {
            "id_evento":
                "IOC-33-001",
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
                "IOC-33-002",
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
                "IOC-33-003",
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
            f"| IOC: "
            f"{evento['ip_origem']}"
        )

    return eventos


# ============================================================
# PIPELINE
# ============================================================

def executar_pipeline(eventos):

    titulo(
        "ETAPA 6 - EXECUTANDO IOC ENRICHMENT"
    )

    resultados = []

    for indice, evento in enumerate(
        eventos,
        start=1
    ):

        subtitulo(
            f"EVENTO "
            f"{indice}/{len(eventos)}"
        )

        print(
            f"ID: "
            f"{evento['id_evento']}"
        )

        resultado = processar_evento(
            evento
        )

        resultados.append(
            resultado
        )

        if (
            resultado[
                "status"
            ] == "REJEITADO"
        ):

            print(
                f"[ERRO] "
                f"{resultado['erro']}"
            )

            continue

        print(
            f"Classificacao: "
            f"{resultado['classificacao']}"
        )

        if (
            resultado[
                "classificacao"
            ] == "NORMAL"
        ):

            print(
                "[OK] Evento normal"
            )

            continue

        print(
            f"Probabilidade ataque: "
            f"{resultado['probabilidade_ataque_percentual']:.2f}%"
        )

        print(
            f"Categoria: "
            f"{resultado['categoria_ataque']}"
        )

        print(
            f"Confianca categoria: "
            f"{resultado['confianca_categoria_percentual']:.2f}%"
        )

        ioc = resultado[
            "ioc"
        ]

        print()

        print(
            "IOC:"
        )

        print(
            f"ID: "
            f"{ioc['ioc_id']}"
        )

        print(
            f"Tipo: "
            f"{ioc['tipo_ioc']}"
        )

        print(
            f"Valor: "
            f"{ioc['valor']}"
        )

        print(
            f"Classificacao IOC: "
            f"{ioc['classificacao']}"
        )

        print(
            f"Status enriquecimento: "
            f"{ioc['status_enriquecimento']}"
        )

        print(
            f"Reputacao: "
            f"{ioc['reputacao']}"
        )

        if (
            ioc[
                "status_enriquecimento"
            ] == "SUCESSO"
        ):

            ti = ioc[
                "threat_intelligence"
            ]

            print(
                f"Abuse Score: "
                f"{ti['abuse_confidence_score']}%"
            )

            print(
                f"Reports: "
                f"{ti['total_reports']}"
            )

            print(
                f"Pais: "
                f"{ti['country_code']}"
            )

            print(
                f"ISP: "
                f"{ti['isp']}"
            )

            print(
                f"Dominio: "
                f"{ti['domain']}"
            )

        print()

        print(
            f"Severidade ML: "
            f"{resultado['severidade_ml']}"
        )

        print(
            f"Severidade final: "
            f"{resultado['severidade_final']}"
        )

        print(
            f"[OK] Alerta SOC: "
            f"{resultado['alerta_id']}"
        )

    return resultados


# ============================================================
# JSON
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


# ============================================================
# PERSISTENCIA
# ============================================================

def persistir(resultados):

    titulo(
        "ETAPA 7 - PERSISTINDO IOCS"
    )

    salvar_json(
        ARQUIVO_IOCS,
        {
            "projeto": PROJETO,
            "aula": AULA,
            "timestamp":
                agora_utc(),
            "iocs":
                iocs_enriquecidos
        }
    )

    print(
        "[OK] IOCs enriquecidos salvos"
    )

    print(
        f"Arquivo: "
        f"{ARQUIVO_IOCS.relative_to(BASE_DIR)}"
    )

    salvar_json(
        ARQUIVO_ALERTAS,
        {
            "projeto": PROJETO,
            "aula": AULA,
            "timestamp":
                agora_utc(),
            "alertas":
                alertas_gerados
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
# VALIDACAO FINAL
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
            bool(
                ABUSEIPDB_API_KEY
            )
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
            "IOCs extraidos",
            estatisticas[
                "iocs_extraidos"
            ] > 0
        ),
        (
            "IOC publico enriquecido",
            estatisticas[
                "iocs_enriquecidos"
            ] > 0
        ),
        (
            "Alertas SOC gerados",
            estatisticas[
                "alertas"
            ] > 0
        ),
        (
            "Arquivo IOC criado",
            ARQUIVO_IOCS.exists()
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
        f"Validacoes: "
        f"{ok}/{total}"
    )

    print(
        f"Saude: "
        f"{saude:.2f}%"
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
        "RESUMO FINAL DA AULA 33"
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
        f"IOCs extraidos: "
        f"{estatisticas['iocs_extraidos']}"
    )

    print(
        f"IOCs publicos: "
        f"{estatisticas['iocs_publicos']}"
    )

    print(
        f"IOCs privados: "
        f"{estatisticas['iocs_privados']}"
    )

    print(
        f"IOCs enriquecidos: "
        f"{estatisticas['iocs_enriquecidos']}"
    )

    print(
        f"Consultas AbuseIPDB: "
        f"{estatisticas['consultas_abuseipdb']}"
    )

    print(
        f"Consultas sucesso: "
        f"{estatisticas['consultas_sucesso']}"
    )

    print(
        f"Alertas SOC: "
        f"{estatisticas['alertas']}"
    )

    print()

    print(
        f"Validacoes: "
        f"{ok}/{total}"
    )

    print(
        f"Saude: "
        f"{saude:.2f}%"
    )

    if sucesso:

        print(
            "Status: AULA 33 CONCLUIDA"
        )

    else:

        print(
            "Status: AULA 33 REQUER ATENCAO"
        )


# ============================================================
# ARQUITETURA
# ============================================================

def arquitetura():

    titulo(
        "ARQUITETURA DA AULA 33"
    )

    print(
        """
EVENTO
  |
  v
DETECTOR ML
  |
  +---- NORMAL -----------------> FINALIZA
  |
  v
ATAQUE
  |
  v
CLASSIFICADOR MULTICLASSE
  |
  v
EXTRACAO DE IOC
  |
  v
IP ORIGEM
  |
  +---- PRIVADO ----------------> IOC INTERNO
  |
  v
PUBLICO
  |
  v
AbuseIPDB
  |
  v
IOC ENRICHMENT
  |
  +---- REPUTACAO
  +---- ABUSE SCORE
  +---- REPORTS
  +---- PAIS
  +---- ISP
  +---- DOMINIO
  |
  v
CORRELACAO ML + IOC
  |
  v
SEVERIDADE FINAL
  |
  v
ALERTA SOC ENRIQUECIDO
"""
    )


# ============================================================
# MAIN
# ============================================================

def main():

    titulo(
        "AULA 33 - IOC ENRICHMENT"
    )

    print(
        PROJETO
    )

    print(
        "IOC Enrichment + AbuseIPDB"
    )

    print()

    print(
        "Objetivo:"
    )

    print(
        "Extrair, estruturar e enriquecer "
        "IOCs detectados pelo pipeline ML."
    )

    preparar_diretorios()

    if not validar_env():

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
        "AULA 33 - IOC ENRICHMENT"
    )

    if sucesso:

        print(
            "AULA 33 CONCLUIDA"
        )

    else:

        print(
            "AULA 33 REQUER ATENCAO"
        )


# ============================================================
# EXECUCAO
# ============================================================

if __name__ == "__main__":
    main()