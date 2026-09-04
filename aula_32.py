# ============================================================
# CyberSentinel-ML
# AULA 32 - ENRIQUECIMENTO AUTOMATICO DE ALERTAS SOC
# ML + AbuseIPDB Threat Intelligence
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
AULA = 32

BASE_DIR = Path(__file__).resolve().parent

ENV_FILE = BASE_DIR / ".env"

DIRETORIO_MODELOS = BASE_DIR / "modelos"
DIRETORIO_ALERTAS = BASE_DIR / "alertas"
DIRETORIO_THREAT_INTEL = BASE_DIR / "threat_intel"

MODELO_BINARIO_PATH = (
    DIRETORIO_MODELOS
    / "unsw_decision_tree.joblib"
)

CONFIG_BINARIA_PATH = (
    DIRETORIO_MODELOS
    / "configuracao_modelo.joblib"
)

MODELO_MULTICLASSE_PATH = (
    DIRETORIO_MODELOS
    / "unsw_attack_multiclass_otimizado.joblib"
)

CONFIG_MULTICLASSE_PATH = (
    DIRETORIO_MODELOS
    / "configuracao_multiclasse_otimizada_aula_22.joblib"
)

ARQUIVO_ALERTAS = (
    DIRETORIO_ALERTAS
    / "alertas_enriquecidos_aula_32.json"
)

ARQUIVO_RELATORIO = (
    DIRETORIO_ALERTAS
    / "relatorio_aula_32.json"
)

ARQUIVO_THREAT_INTEL = (
    DIRETORIO_THREAT_INTEL
    / "consultas_aula_32.json"
)

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

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

CATEGORIAS = []

alertas_gerados = []

consultas_threat_intel = []

estatisticas = {
    "eventos_recebidos": 0,
    "eventos_validos": 0,
    "eventos_invalidos": 0,
    "normais": 0,
    "ataques": 0,
    "alertas": 0,
    "consultas_abuseipdb": 0,
    "consultas_sucesso": 0,
    "consultas_erro": 0
}


# ============================================================
# FUNCOES DE INTERFACE
# ============================================================

def titulo(texto):
    print("=" * 72)
    print(texto)
    print("=" * 72)


def subtitulo(texto):
    print("\n" + "-" * 72)
    print(texto)
    print("-" * 72)


def agora_utc():
    return datetime.now(
        timezone.utc
    ).isoformat()


# ============================================================
# PREPARACAO DOS DIRETORIOS
# ============================================================

def preparar_diretorios():

    titulo(
        "ETAPA 1 - PREPARANDO DIRETORIOS"
    )

    diretorios = [
        DIRETORIO_MODELOS,
        DIRETORIO_ALERTAS,
        DIRETORIO_THREAT_INTEL
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
# VALIDACAO DO .ENV
# ============================================================

def validar_env():

    titulo(
        "ETAPA 2 - VALIDANDO THREAT INTELLIGENCE"
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
        "[OK] Valor da chave protegido"
    )

    return True


# ============================================================
# VALIDACAO DOS ARTEFATOS ML
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
                f"[ERRO] {nome} nao encontrado:"
            )

            print(caminho)

            sucesso = False

    return sucesso


# ============================================================
# CARREGAMENTO DOS MODELOS
# ============================================================

def carregar_modelos():

    global modelo_binario
    global config_binaria
    global modelo_multiclasse
    global config_multiclasse
    global FEATURES
    global THRESHOLD
    global CATEGORIAS

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

    except Exception as erro:

        print(
            f"[ERRO] Falha ao carregar modelos: "
            f"{erro}"
        )

        return False

    # --------------------------------------------------------
    # FEATURES
    # --------------------------------------------------------

    if isinstance(config_binaria, dict):

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

    # --------------------------------------------------------
    # CATEGORIAS
    # --------------------------------------------------------

    if isinstance(
        config_multiclasse,
        dict
    ):

        CATEGORIAS = (
            config_multiclasse.get(
                "categorias"
            )
            or config_multiclasse.get(
                "classes"
            )
            or []
        )

    if not CATEGORIAS:

        if hasattr(
            modelo_multiclasse,
            "classes_"
        ):

            CATEGORIAS = list(
                modelo_multiclasse.classes_
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
        f"Threshold binario: "
        f"{THRESHOLD:.4f}"
    )

    print(
        f"Quantidade de features: "
        f"{len(FEATURES)}"
    )

    return True


# ============================================================
# VALIDACAO DAS FEATURES
# ============================================================

def validar_features_modelos():

    titulo(
        "ETAPA 5 - VALIDANDO COMPATIBILIDADE"
    )

    if len(FEATURES) != 9:

        print(
            "[ERRO] Quantidade inesperada "
            "de features"
        )

        return False

    print(
        "[OK] 9 features configuradas"
    )

    print()

    for indice, feature in enumerate(
        FEATURES,
        start=1
    ):

        print(
            f"{indice:02d} - {feature}"
        )

    return True


# ============================================================
# VALIDACAO DO EVENTO
# ============================================================

def validar_evento(evento):

    if not isinstance(evento, dict):

        return (
            False,
            "Evento deve ser um objeto JSON"
        )

    for feature in FEATURES:

        if feature not in evento:

            return (
                False,
                f"Feature obrigatoria "
                f"ausente: {feature}"
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

        except (
            TypeError,
            ValueError
        ):

            return (
                False,
                f"Feature nao numerica: "
                f"{feature}"
            )

    return True, "Evento valido"


# ============================================================
# PREPARACAO DAS FEATURES
# ============================================================

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
# PREDICAO BINARIA
# ============================================================

def predicao_binaria(df):

    probabilidades = (
        modelo_binario.predict_proba(df)
    )

    classes = list(
        modelo_binario.classes_
    )

    if 1 in classes:

        indice_ataque = classes.index(1)

    elif "1" in classes:

        indice_ataque = classes.index("1")

    else:

        indice_ataque = 1

    probabilidade = float(
        probabilidades[
            0
        ][
            indice_ataque
        ]
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
        np.argmax(
            probabilidades
        )
    )

    confianca = float(
        probabilidades[indice]
    )

    classes_modelo = list(
        modelo_multiclasse.classes_
    )

    classe_prevista = (
        classes_modelo[indice]
    )

    categoria = str(
        classe_prevista
    )

    return (
        categoria,
        confianca
    )


# ============================================================
# SEVERIDADE DO ALERTA
# ============================================================

def calcular_severidade(
    probabilidade_ataque,
    confianca_categoria
):

    score = (
        probabilidade_ataque * 0.60
        +
        confianca_categoria * 0.40
    )

    if score >= 0.75:
        return "CRITICO"

    if score >= 0.40:
        return "ALTO"

    if score >= 0.20:
        return "MEDIO"

    return "BAIXO"


# ============================================================
# VALIDACAO DE IP PUBLICO
# ============================================================

def validar_ip_publico(ip):

    if not ip:

        return (
            False,
            "IP de origem nao informado"
        )

    try:

        endereco = ip_address(
            str(ip)
        )

    except ValueError:

        return (
            False,
            "Formato de IP invalido"
        )

    if endereco.is_private:

        return (
            False,
            "IP privado"
        )

    if endereco.is_loopback:

        return (
            False,
            "IP loopback"
        )

    if endereco.is_multicast:

        return (
            False,
            "IP multicast"
        )

    if endereco.is_unspecified:

        return (
            False,
            "IP nao especificado"
        )

    if endereco.is_reserved:

        return (
            False,
            "IP reservado"
        )

    return (
        True,
        "IP publico valido"
    )


# ============================================================
# CONSULTA ABUSEIPDB
# ============================================================

def consultar_abuseipdb(ip):

    estatisticas[
        "consultas_abuseipdb"
    ] += 1

    headers = {
        "Accept": "application/json",
        "Key": ABUSEIPDB_API_KEY
    }

    parametros = {
        "ipAddress": ip,
        "maxAgeInDays": MAX_AGE_DAYS
    }

    inicio = time.perf_counter()

    try:

        resposta = requests.get(
            ABUSEIPDB_URL,
            headers=headers,
            params=parametros,
            timeout=TIMEOUT_API
        )

        tempo_ms = (
            time.perf_counter()
            - inicio
        ) * 1000

        if resposta.status_code == 401:

            estatisticas[
                "consultas_erro"
            ] += 1

            return {
                "status": "ERRO",
                "fonte": "AbuseIPDB",
                "ip": ip,
                "erro": (
                    "API Key invalida "
                    "ou nao autorizada"
                ),
                "http_status": 401,
                "tempo_ms": round(
                    tempo_ms,
                    4
                )
            }

        if resposta.status_code == 429:

            estatisticas[
                "consultas_erro"
            ] += 1

            return {
                "status": "ERRO",
                "fonte": "AbuseIPDB",
                "ip": ip,
                "erro": (
                    "Limite de requisicoes "
                    "atingido"
                ),
                "http_status": 429,
                "tempo_ms": round(
                    tempo_ms,
                    4
                )
            }

        if resposta.status_code != 200:

            estatisticas[
                "consultas_erro"
            ] += 1

            return {
                "status": "ERRO",
                "fonte": "AbuseIPDB",
                "ip": ip,
                "erro": (
                    "Resposta inesperada "
                    "do AbuseIPDB"
                ),
                "http_status":
                    resposta.status_code,
                "tempo_ms": round(
                    tempo_ms,
                    4
                )
            }

        payload = resposta.json()

        dados = payload.get(
            "data",
            {}
        )

        estatisticas[
            "consultas_sucesso"
        ] += 1

        return {
            "status": "SUCESSO",
            "fonte": "AbuseIPDB",
            "ip": ip,
            "http_status": 200,
            "tempo_ms": round(
                tempo_ms,
                4
            ),
            "dados": dados
        }

    except requests.exceptions.Timeout:

        estatisticas[
            "consultas_erro"
        ] += 1

        return {
            "status": "ERRO",
            "fonte": "AbuseIPDB",
            "ip": ip,
            "erro": "Timeout",
            "tempo_ms": round(
                (
                    time.perf_counter()
                    - inicio
                ) * 1000,
                4
            )
        }

    except requests.exceptions.RequestException as erro:

        estatisticas[
            "consultas_erro"
        ] += 1

        return {
            "status": "ERRO",
            "fonte": "AbuseIPDB",
            "ip": ip,
            "erro": str(erro)
        }


# ============================================================
# NIVEL DE RISCO THREAT INTELLIGENCE
# ============================================================

def nivel_risco_abuse(score):

    if score >= 80:
        return "CRITICO"

    if score >= 50:
        return "ALTO"

    if score >= 20:
        return "MEDIO"

    if score > 0:
        return "BAIXO"

    return "SEM_RISCO"


# ============================================================
# NORMALIZACAO ABUSEIPDB
# ============================================================

def normalizar_abuseipdb(
    ip,
    consulta
):

    if consulta[
        "status"
    ] != "SUCESSO":

        return {
            "fonte": "AbuseIPDB",
            "status": "ERRO",
            "ip": ip,
            "erro": consulta.get(
                "erro"
            )
        }

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

    resultado = {
        "fonte": "AbuseIPDB",
        "status": "SUCESSO",
        "ip": ip,
        "abuse_confidence_score":
            score,
        "nivel_risco":
            nivel_risco_abuse(
                score
            ),
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

    consultas_threat_intel.append(
        {
            "timestamp": agora_utc(),
            **resultado
        }
    )

    return resultado


# ============================================================
# AJUSTE DA SEVERIDADE COM THREAT INTELLIGENCE
# ============================================================

def ajustar_severidade_com_threat_intel(
    severidade_ml,
    threat_intel
):

    if (
        not threat_intel
        or threat_intel.get(
            "status"
        ) != "SUCESSO"
    ):

        return severidade_ml

    score = threat_intel.get(
        "abuse_confidence_score",
        0
    )

    if score >= 80:
        return "CRITICO"

    if score >= 50:

        if severidade_ml in [
            "BAIXO",
            "MEDIO"
        ]:

            return "ALTO"

    if score >= 20:

        if severidade_ml == "BAIXO":
            return "MEDIO"

    return severidade_ml


# ============================================================
# GERACAO DE ID DO ALERTA
# ============================================================

def gerar_alerta_id():

    timestamp = datetime.now(
        timezone.utc
    ).strftime(
        "%Y%m%d%H%M%S%f"
    )

    return (
        f"TI-ALT-{timestamp}"
    )


# ============================================================
# PROCESSAMENTO DO EVENTO
# ============================================================

def processar_evento(evento):

    estatisticas[
        "eventos_recebidos"
    ] += 1

    valido, motivo = validar_evento(
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
            "erro": motivo,
            "timestamp": agora_utc()
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

    resultado_base = {
        "projeto": PROJETO,
        "aula": AULA,
        "id_evento":
            evento.get(
                "id_evento",
                "SEM-ID"
            ),
        "origem":
            evento.get(
                "origem",
                "DESCONHECIDA"
            ),
        "ip_origem":
            evento.get(
                "ip_origem"
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
        "threshold":
            THRESHOLD,
        "timestamp":
            agora_utc()
    }

    # --------------------------------------------------------
    # EVENTO NORMAL
    # --------------------------------------------------------

    if classificacao == "NORMAL":

        estatisticas[
            "normais"
        ] += 1

        resultado_base[
            "status"
        ] = "PROCESSADO"

        resultado_base[
            "alerta_soc"
        ] = False

        resultado_base[
            "threat_intelligence"
        ] = {
            "status": "NAO_CONSULTADO",
            "motivo": (
                "Evento classificado "
                "como NORMAL"
            )
        }

        return resultado_base

    # --------------------------------------------------------
    # EVENTO ATAQUE
    # --------------------------------------------------------

    estatisticas[
        "ataques"
    ] += 1

    categoria, confianca = (
        predicao_multiclasse(
            df
        )
    )

    severidade_ml = calcular_severidade(
        probabilidade,
        confianca
    )

    ip_origem = evento.get(
        "ip_origem"
    )

    ip_valido, motivo_ip = (
        validar_ip_publico(
            ip_origem
        )
    )

    threat_intel = None

    # --------------------------------------------------------
    # ENRIQUECIMENTO
    # --------------------------------------------------------

    if ip_valido:

        consulta = consultar_abuseipdb(
            ip_origem
        )

        threat_intel = (
            normalizar_abuseipdb(
                ip_origem,
                consulta
            )
        )

    else:

        threat_intel = {
            "fonte": "AbuseIPDB",
            "status": "NAO_CONSULTADO",
            "ip": ip_origem,
            "motivo": motivo_ip
        }

    severidade_final = (
        ajustar_severidade_com_threat_intel(
            severidade_ml,
            threat_intel
        )
    )

    alerta_id = gerar_alerta_id()

    alerta = {
        **resultado_base,

        "status":
            "PROCESSADO",

        "alerta_soc":
            True,

        "alerta_id":
            alerta_id,

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

        "threat_intelligence":
            threat_intel
    }

    alertas_gerados.append(
        alerta
    )

    estatisticas[
        "alertas"
    ] += 1

    return alerta


# ============================================================
# EVENTOS DO LABORATORIO
# ============================================================

def preparar_eventos():

    titulo(
        "ETAPA 6 - PREPARANDO EVENTOS"
    )

    eventos = [

        {
            "id_evento":
                "TI-32-001",

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
                "TI-32-002",

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
                "TI-32-003",

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
            f"- "
            f"{evento['id_evento']} "
            f"| IP: "
            f"{evento['ip_origem']}"
        )

    return eventos


# ============================================================
# EXECUCAO DO PIPELINE
# ============================================================

def executar_pipeline(eventos):

    titulo(
        "ETAPA 7 - EXECUTANDO PIPELINE ML + THREAT INTELLIGENCE"
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

        print(
            f"IP origem: "
            f"{evento.get('ip_origem')}"
        )

        resultado = processar_evento(
            evento
        )

        resultados.append(
            resultado
        )

        if resultado[
            "status"
        ] == "REJEITADO":

            print(
                f"[ERRO] "
                f"{resultado['erro']}"
            )

            continue

        print(
            f"Classificacao ML: "
            f"{resultado['classificacao']}"
        )

        print(
            f"Probabilidade ataque: "
            f"{resultado['probabilidade_ataque_percentual']:.2f}%"
        )

        if (
            resultado[
                "classificacao"
            ] == "NORMAL"
        ):

            print(
                "[OK] Evento NORMAL"
            )

            print(
                "Threat Intelligence "
                "nao consultada"
            )

            continue

        print(
            f"Categoria: "
            f"{resultado['categoria_ataque']}"
        )

        print(
            f"Confianca categoria: "
            f"{resultado['confianca_categoria_percentual']:.2f}%"
        )

        print(
            f"Severidade ML: "
            f"{resultado['severidade_ml']}"
        )

        threat = resultado[
            "threat_intelligence"
        ]

        print()

        print(
            "Threat Intelligence:"
        )

        print(
            f"Status: "
            f"{threat['status']}"
        )

        if (
            threat[
                "status"
            ] == "SUCESSO"
        ):

            print(
                f"Abuse Score: "
                f"{threat['abuse_confidence_score']}%"
            )

            print(
                f"Nivel risco IP: "
                f"{threat['nivel_risco']}"
            )

            print(
                f"Reports: "
                f"{threat['total_reports']}"
            )

            print(
                f"ISP: "
                f"{threat['isp']}"
            )

            print(
                f"Pais: "
                f"{threat['country_code']}"
            )

        else:

            print(
                f"Motivo: "
                f"{threat.get('motivo') or threat.get('erro')}"
            )

        print()

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
# SALVANDO JSON
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

def persistir_resultados(
    resultados
):

    titulo(
        "ETAPA 8 - PERSISTINDO RESULTADOS"
    )

    salvar_json(
        ARQUIVO_ALERTAS,
        {
            "projeto": PROJETO,
            "aula": AULA,
            "timestamp": agora_utc(),
            "alertas": alertas_gerados
        }
    )

    print(
        "[OK] Alertas enriquecidos salvos"
    )

    print(
        f"Arquivo: "
        f"{ARQUIVO_ALERTAS.relative_to(BASE_DIR)}"
    )

    salvar_json(
        ARQUIVO_THREAT_INTEL,
        {
            "projeto": PROJETO,
            "aula": AULA,
            "fonte": "AbuseIPDB",
            "timestamp": agora_utc(),
            "consultas":
                consultas_threat_intel
        }
    )

    print(
        "[OK] Threat Intelligence salva"
    )

    print(
        f"Arquivo: "
        f"{ARQUIVO_THREAT_INTEL.relative_to(BASE_DIR)}"
    )

    relatorio = {
        "projeto": PROJETO,
        "aula": AULA,
        "timestamp": agora_utc(),
        "estatisticas":
            estatisticas,
        "resultados":
            resultados
    }

    salvar_json(
        ARQUIVO_RELATORIO,
        relatorio
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

def validacao_final():

    titulo(
        "ETAPA 9 - VALIDACAO FINAL"
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
            "Alertas SOC gerados",
            estatisticas[
                "alertas"
            ] > 0
        ),

        (
            "Threat Intelligence executada",
            estatisticas[
                "consultas_abuseipdb"
            ] > 0
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

def exibir_resumo(
    sucesso,
    ok,
    total,
    saude
):

    titulo(
        "RESUMO FINAL DA AULA 32"
    )

    print(
        f"Eventos recebidos: "
        f"{estatisticas['eventos_recebidos']}"
    )

    print(
        f"Eventos validos: "
        f"{estatisticas['eventos_validos']}"
    )

    print(
        f"Eventos invalidos: "
        f"{estatisticas['eventos_invalidos']}"
    )

    print(
        f"Eventos NORMAL: "
        f"{estatisticas['normais']}"
    )

    print(
        f"Eventos ATAQUE: "
        f"{estatisticas['ataques']}"
    )

    print(
        f"Alertas SOC: "
        f"{estatisticas['alertas']}"
    )

    print(
        f"Consultas AbuseIPDB: "
        f"{estatisticas['consultas_abuseipdb']}"
    )

    print(
        f"Consultas com sucesso: "
        f"{estatisticas['consultas_sucesso']}"
    )

    print(
        f"Consultas com erro: "
        f"{estatisticas['consultas_erro']}"
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
            "Status: AULA 32 CONCLUIDA"
        )

    else:

        print(
            "Status: AULA 32 REQUER ATENCAO"
        )


# ============================================================
# ARQUITETURA
# ============================================================

def exibir_arquitetura():

    titulo(
        "ARQUITETURA DA AULA 32"
    )

    print(
        """
EVENTO DE REDE
      |
      v
VALIDACAO
      |
      v
DETECTOR ML BINARIO
      |
      +------ NORMAL --------------------+
      |                                  |
      |                                  v
      |                              FINALIZA
      |
      v
    ATAQUE
      |
      v
CLASSIFICADOR MULTICLASSE
      |
      v
CATEGORIA DO ATAQUE
      |
      v
IP DE ORIGEM
      |
      +------ IP PRIVADO ----------------+
      |                                  |
      |                                  v
      |                         SEM CONSULTA EXTERNA
      |
      v
   IP PUBLICO
      |
      v
   AbuseIPDB
      |
      v
THREAT INTELLIGENCE
      |
      v
ABUSE SCORE + REPORTS
      |
      v
CORRELACAO ML + TI
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
        "AULA 32 - ENRIQUECIMENTO AUTOMATICO DE ALERTAS SOC"
    )

    print(PROJETO)

    print(
        "Machine Learning + AbuseIPDB"
    )

    print()

    print(
        "Objetivo:"
    )

    print(
        "Integrar a deteccao ML do CyberSentinel "
        "com Threat Intelligence real."
    )

    print()

    print(
        "Eventos classificados como ATAQUE "
        "com IP publico serao enriquecidos "
        "automaticamente pelo AbuseIPDB."
    )

    print()

    # --------------------------------------------------------
    # PREPARACAO
    # --------------------------------------------------------

    preparar_diretorios()

    # --------------------------------------------------------
    # .ENV
    # --------------------------------------------------------

    if not validar_env():

        print()

        print(
            "Status: AULA 32 REQUER ATENCAO"
        )

        sys.exit(1)

    # --------------------------------------------------------
    # ARTEFATOS
    # --------------------------------------------------------

    if not validar_artefatos():

        print()

        print(
            "Status: AULA 32 REQUER ATENCAO"
        )

        sys.exit(1)

    # --------------------------------------------------------
    # MODELOS
    # --------------------------------------------------------

    if not carregar_modelos():

        print()

        print(
            "Status: AULA 32 REQUER ATENCAO"
        )

        sys.exit(1)

    # --------------------------------------------------------
    # FEATURES
    # --------------------------------------------------------

    if not validar_features_modelos():

        print()

        print(
            "Status: AULA 32 REQUER ATENCAO"
        )

        sys.exit(1)

    # --------------------------------------------------------
    # EVENTOS
    # --------------------------------------------------------

    eventos = preparar_eventos()

    # --------------------------------------------------------
    # PIPELINE
    # --------------------------------------------------------

    resultados = executar_pipeline(
        eventos
    )

    # --------------------------------------------------------
    # PERSISTENCIA
    # --------------------------------------------------------

    persistir_resultados(
        resultados
    )

    # --------------------------------------------------------
    # VALIDACAO
    # --------------------------------------------------------

    (
        sucesso,
        ok,
        total,
        saude
    ) = validacao_final()

    # --------------------------------------------------------
    # RESUMO
    # --------------------------------------------------------

    exibir_resumo(
        sucesso,
        ok,
        total,
        saude
    )

    # --------------------------------------------------------
    # ARQUITETURA
    # --------------------------------------------------------

    exibir_arquitetura()

    titulo(
        "CYBERSENTINEL-ML"
    )

    print(
        "AULA 32 - ML + THREAT INTELLIGENCE"
    )

    if sucesso:

        print(
            "AULA 32 CONCLUIDA"
        )

    else:

        print(
            "AULA 32 REQUER ATENCAO"
        )


# ============================================================
# EXECUCAO
# ============================================================

if __name__ == "__main__":
    main()