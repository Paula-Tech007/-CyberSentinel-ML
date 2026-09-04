# ============================================================
# CyberSentinel-ML
# AULA 35 - CORRELACAO HISTORICA DE IOC
#
# ML + Threat Intelligence + Risk Score V2
# + Historico SQLite + Risk Score Correlacionado
#
# ============================================================

import json
import os
import sqlite3
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
# CONFIGURACOES
# ============================================================

PROJETO = "CyberSentinel-ML"
AULA = 35
VERSAO = "Risk Correlation 1.0"

BASE_DIR = Path(__file__).resolve().parent

ENV_FILE = BASE_DIR / ".env"

DIR_MODELOS = BASE_DIR / "modelos"
DIR_DADOS = BASE_DIR / "dados"
DIR_ALERTAS = BASE_DIR / "alertas"
DIR_CORRELACAO = BASE_DIR / "correlacao"

BANCO_PATH = (
    DIR_DADOS /
    "cybersentinel.db"
)

MODELO_BINARIO_PATH = (
    DIR_MODELOS /
    "unsw_decision_tree.joblib"
)

CONFIG_BINARIA_PATH = (
    DIR_MODELOS /
    "configuracao_modelo.joblib"
)

MODELO_MULTICLASSE_PATH = (
    DIR_MODELOS /
    "unsw_attack_multiclass_otimizado.joblib"
)

CONFIG_MULTICLASSE_PATH = (
    DIR_MODELOS /
    "configuracao_multiclasse_otimizada_aula_22.joblib"
)

ARQUIVO_CORRELACAO = (
    DIR_CORRELACAO /
    "correlacao_ioc_aula_35.json"
)

ARQUIVO_ALERTAS = (
    DIR_ALERTAS /
    "alertas_correlacionados_aula_35.json"
)

ARQUIVO_RELATORIO = (
    DIR_ALERTAS /
    "relatorio_aula_35.json"
)


# ============================================================
# ABUSEIPDB
# ============================================================

ABUSEIPDB_URL = (
    "https://api.abuseipdb.com/api/v2/check"
)

MAX_AGE_DAYS = 90
TIMEOUT_API = 10


# ============================================================
# PESOS RISK SCORE V2
# ============================================================

PESO_PROBABILIDADE_ML = 0.30
PESO_CONFIANCA = 0.15
PESO_CATEGORIA = 0.20
PESO_ABUSE = 0.25
PESO_REPORTS = 0.10


# ============================================================
# RISCO BASE POR CATEGORIA
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
# CORRELACAO
# ============================================================

BONUS_POR_REINCIDENCIA = 5
MAX_BONUS_REINCIDENCIA = 15

BONUS_CATEGORIA_DIFERENTE = 3
MAX_BONUS_CATEGORIAS = 6

BONUS_HISTORICO_CRITICO = 5

MAX_BONUS_CORRELACAO = 20


# ============================================================
# .ENV
# ============================================================

load_dotenv(
    dotenv_path=ENV_FILE
)

ABUSEIPDB_API_KEY = os.getenv(
    "ABUSEIPDB_API_KEY"
)


# ============================================================
# MODELOS
# ============================================================

modelo_binario = None
config_binaria = None

modelo_multiclasse = None
config_multiclasse = None

FEATURES = []
THRESHOLD = 0.5


# ============================================================
# CACHE LOCAL DE THREAT INTELLIGENCE
# ============================================================

cache_ti = {}


# ============================================================
# RESULTADOS
# ============================================================

correlacoes = []
alertas = []

estatisticas = {
    "eventos_recebidos": 0,
    "eventos_validos": 0,
    "eventos_invalidos": 0,
    "normais": 0,
    "ataques": 0,
    "consultas_ti": 0,
    "consultas_ti_cache": 0,
    "consultas_sucesso": 0,
    "consultas_erro": 0,
    "risk_scores": 0,
    "iocs_novos": 0,
    "iocs_reincidentes": 0,
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
        DIR_DADOS,
        DIR_ALERTAS,
        DIR_CORRELACAO
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

    soma = (
        PESO_PROBABILIDADE_ML
        + PESO_CONFIANCA
        + PESO_CATEGORIA
        + PESO_ABUSE
        + PESO_REPORTS
    )

    if abs(
        soma - 1.0
    ) > 0.0001:

        print(
            "[ERRO] Pesos Risk Score "
            "invalidos"
        )

        return False

    print(
        "[OK] Pesos Risk Score V2: 100%"
    )

    return True


# ============================================================
# ARTEFATOS
# ============================================================

def validar_artefatos():

    titulo(
        "ETAPA 3 - VALIDANDO ARTEFATOS"
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
# CARREGAR MODELOS
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
            config_binaria.get(
                "features"
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
        f"Threshold: "
        f"{THRESHOLD:.4f}"
    )

    print(
        f"Features: "
        f"{len(FEATURES)}"
    )

    return True


# ============================================================
# SQLITE
# ============================================================

def conectar_banco():

    conexao = sqlite3.connect(
        BANCO_PATH,
        timeout=10
    )

    conexao.row_factory = (
        sqlite3.Row
    )

    return conexao


# ============================================================
# TABELA DE CORRELACAO
# ============================================================

def inicializar_banco():

    titulo(
        "ETAPA 5 - PREPARANDO CORRELACAO SQLITE"
    )

    conexao = conectar_banco()

    cursor = conexao.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS correlacao_ioc_eventos (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            id_evento TEXT NOT NULL,

            timestamp TEXT NOT NULL,

            ip_origem TEXT NOT NULL,

            categoria TEXT,

            probabilidade_ataque REAL,

            confianca_categoria REAL,

            abuse_score REAL,

            total_reports INTEGER,

            risk_score_base REAL,

            bonus_correlacao REAL,

            risk_score_correlacionado REAL,

            nivel_risco TEXT,

            alerta_id TEXT

        )
        """
    )

    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS
        idx_correlacao_ip

        ON correlacao_ioc_eventos(
            ip_origem
        )
        """
    )

    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS
        idx_correlacao_timestamp

        ON correlacao_ioc_eventos(
            timestamp
        )
        """
    )

    conexao.commit()

    conexao.close()

    print(
        "[OK] Banco SQLite pronto"
    )

    print(
        "[OK] Tabela correlacao_ioc_eventos pronta"
    )

    print(
        f"Banco: "
        f"{BANCO_PATH.relative_to(BASE_DIR)}"
    )


# ============================================================
# VALIDACAO EVENTO
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
                f"Feature ausente: "
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
                    f"Valor invalido: "
                    f"{feature}"
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

    return pd.DataFrame(
        {
            feature: [
                float(
                    evento[feature]
                )
            ]

            for feature in FEATURES
        },
        columns=FEATURES
    )


# ============================================================
# ML BINARIO
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

        raise ValueError(
            "Classe ATAQUE nao encontrada"
        )

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
# ML MULTICLASSE
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
        or endereco.is_reserved
        or endereco.is_unspecified
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

    if ip in cache_ti:

        estatisticas[
            "consultas_ti_cache"
        ] += 1

        return cache_ti[ip]

    estatisticas[
        "consultas_ti"
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

            resultado = {
                "status": "ERRO",
                "http_status":
                    resposta.status_code,
                "abuse_score": 0,
                "reports": 0,
                "tempo_ms":
                    round(
                        tempo_ms,
                        4
                    )
            }

            cache_ti[ip] = resultado

            return resultado

        dados = resposta.json().get(
            "data",
            {}
        )

        estatisticas[
            "consultas_sucesso"
        ] += 1

        resultado = {
            "status": "SUCESSO",

            "abuse_score":
                int(
                    dados.get(
                        "abuseConfidenceScore",
                        0
                    )
                    or 0
                ),

            "reports":
                int(
                    dados.get(
                        "totalReports",
                        0
                    )
                    or 0
                ),

            "pais":
                dados.get(
                    "countryCode"
                ),

            "isp":
                dados.get(
                    "isp"
                ),

            "dominio":
                dados.get(
                    "domain"
                ),

            "tempo_ms":
                round(
                    tempo_ms,
                    4
                )
        }

        cache_ti[ip] = resultado

        return resultado

    except requests.exceptions.RequestException as erro:

        estatisticas[
            "consultas_erro"
        ] += 1

        resultado = {
            "status": "ERRO",
            "erro": str(erro),
            "abuse_score": 0,
            "reports": 0
        }

        cache_ti[ip] = resultado

        return resultado


# ============================================================
# REPORTS
# ============================================================

def normalizar_reports(reports):

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
# NIVEL DE RISCO
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

    if (
        ti
        and ti.get(
            "status"
        ) == "SUCESSO"
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

        score = (
            score_ml
            * PESO_PROBABILIDADE_ML
            +
            score_confianca
            * PESO_CONFIANCA
            +
            score_categoria
            * PESO_CATEGORIA
            +
            score_abuse
            * PESO_ABUSE
            +
            score_reports
            * PESO_REPORTS
        )

        modo = "ML_TI"

    else:

        soma = (
            PESO_PROBABILIDADE_ML
            + PESO_CONFIANCA
            + PESO_CATEGORIA
        )

        score = (
            score_ml
            * (
                PESO_PROBABILIDADE_ML
                / soma
            )
            +
            score_confianca
            * (
                PESO_CONFIANCA
                / soma
            )
            +
            score_categoria
            * (
                PESO_CATEGORIA
                / soma
            )
        )

        modo = "SOMENTE_ML"

    score = round(
        max(
            0,
            min(
                100,
                score
            )
        ),
        2
    )

    return {
        "score": score,
        "nivel":
            classificar_risco(
                score
            ),
        "modo":
            modo
    }


# ============================================================
# HISTORICO DO IOC
# ============================================================

def consultar_historico_ioc(ip):

    conexao = conectar_banco()

    cursor = conexao.cursor()

    cursor.execute(
        """
        SELECT

            id_evento,
            timestamp,
            categoria,
            risk_score_base,
            risk_score_correlacionado,
            nivel_risco,
            alerta_id

        FROM correlacao_ioc_eventos

        WHERE ip_origem = ?

        ORDER BY id DESC
        """,

        (ip,)
    )

    registros = [
        dict(item)
        for item in cursor.fetchall()
    ]

    conexao.close()

    return registros


# ============================================================
# CORRELACAO
# ============================================================

def calcular_correlacao(
    ip,
    categoria,
    risk_score_base
):

    historico = consultar_historico_ioc(
        ip
    )

    ocorrencias_anteriores = len(
        historico
    )

    ocorrencias_total = (
        ocorrencias_anteriores + 1
    )

    categorias_historicas = {
        item["categoria"]

        for item in historico

        if item["categoria"]
    }

    categorias_total = set(
        categorias_historicas
    )

    categorias_total.add(
        categoria
    )


    # ========================================================
    # BONUS REINCIDENCIA
    # ========================================================

    bonus_reincidencia = min(
        ocorrencias_anteriores
        * BONUS_POR_REINCIDENCIA,

        MAX_BONUS_REINCIDENCIA
    )


    # ========================================================
    # BONUS DIVERSIDADE DE CATEGORIA
    # ========================================================

    categorias_extras = max(
        0,
        len(categorias_total) - 1
    )

    bonus_categorias = min(
        categorias_extras
        * BONUS_CATEGORIA_DIFERENTE,

        MAX_BONUS_CATEGORIAS
    )


    # ========================================================
    # HISTORICO CRITICO
    # ========================================================

    maior_score_historico = 0.0

    for item in historico:

        valor = (
            item.get(
                "risk_score_correlacionado"
            )
            or
            item.get(
                "risk_score_base"
            )
            or 0
        )

        maior_score_historico = max(
            maior_score_historico,
            float(valor)
        )


    bonus_historico_critico = 0

    if maior_score_historico >= 80:

        bonus_historico_critico = (
            BONUS_HISTORICO_CRITICO
        )


    # ========================================================
    # BONUS TOTAL
    # ========================================================

    bonus_total = (
        bonus_reincidencia
        + bonus_categorias
        + bonus_historico_critico
    )

    bonus_total = min(
        bonus_total,
        MAX_BONUS_CORRELACAO
    )


    # ========================================================
    # SCORE CORRELACIONADO
    # ========================================================

    score_correlacionado = min(
        100,
        risk_score_base
        + bonus_total
    )

    score_correlacionado = round(
        score_correlacionado,
        2
    )


    # ========================================================
    # STATUS
    # ========================================================

    if ocorrencias_anteriores > 0:

        status = "REINCIDENTE"

        estatisticas[
            "iocs_reincidentes"
        ] += 1

    else:

        status = "NOVO"

        estatisticas[
            "iocs_novos"
        ] += 1


    return {
        "status_correlacao":
            status,

        "ocorrencias_anteriores":
            ocorrencias_anteriores,

        "ocorrencias_total":
            ocorrencias_total,

        "categorias_historicas":
            sorted(
                categorias_historicas
            ),

        "categorias_total":
            sorted(
                categorias_total
            ),

        "maior_risk_score_historico":
            round(
                maior_score_historico,
                2
            ),

        "bonus_reincidencia":
            bonus_reincidencia,

        "bonus_categorias":
            bonus_categorias,

        "bonus_historico_critico":
            bonus_historico_critico,

        "bonus_total":
            bonus_total,

        "risk_score_base":
            risk_score_base,

        "risk_score_correlacionado":
            score_correlacionado,

        "nivel_risco_correlacionado":
            classificar_risco(
                score_correlacionado
            )
    }


# ============================================================
# PERSISTIR EVENTO CORRELACIONADO
# ============================================================

def persistir_correlacao(
    resultado
):

    conexao = conectar_banco()

    cursor = conexao.cursor()

    cursor.execute(
        """
        INSERT INTO correlacao_ioc_eventos (

            id_evento,
            timestamp,
            ip_origem,
            categoria,
            probabilidade_ataque,
            confianca_categoria,
            abuse_score,
            total_reports,
            risk_score_base,
            bonus_correlacao,
            risk_score_correlacionado,
            nivel_risco,
            alerta_id

        )

        VALUES (
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
        )
        """,

        (
            resultado[
                "id_evento"
            ],

            resultado[
                "timestamp"
            ],

            resultado[
                "ip_origem"
            ],

            resultado[
                "categoria_ataque"
            ],

            resultado[
                "probabilidade_ataque"
            ],

            resultado[
                "confianca_categoria"
            ],

            resultado[
                "threat_intelligence"
            ].get(
                "abuse_score",
                0
            ),

            resultado[
                "threat_intelligence"
            ].get(
                "reports",
                0
            ),

            resultado[
                "risk_score_base"
            ],

            resultado[
                "correlacao"
            ][
                "bonus_total"
            ],

            resultado[
                "risk_score_correlacionado"
            ],

            resultado[
                "nivel_risco"
            ],

            resultado[
                "alerta_id"
            ]
        )
    )

    conexao.commit()

    registro_id = cursor.lastrowid

    conexao.close()

    return registro_id


# ============================================================
# PROCESSAR EVENTO
# ============================================================

def processar_evento(evento):

    estatisticas[
        "eventos_recebidos"
    ] += 1

    valido, mensagem = validar_evento(
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
            "erro":
                mensagem
        }

    estatisticas[
        "eventos_validos"
    ] += 1

    df = preparar_dataframe(
        evento
    )

    (
        classificacao,
        probabilidade
    ) = predicao_binaria(
        df
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
                False
        }

    estatisticas[
        "ataques"
    ] += 1

    (
        categoria,
        confianca
    ) = predicao_multiclasse(
        df
    )

    ip = str(
        evento.get(
            "ip_origem",
            ""
        )
    )

    info_ip = analisar_ip(
        ip
    )

    if (
        info_ip[
            "valido"
        ]
        and
        info_ip[
            "publico"
        ]
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
            "abuse_score":
                0,
            "reports":
                0
        }

    risco_base = calcular_risk_score(
        probabilidade,
        confianca,
        categoria,
        ti
    )

    estatisticas[
        "risk_scores"
    ] += 1


    # ========================================================
    # CORRELACAO HISTORICA
    # ========================================================

    correlacao = calcular_correlacao(
        ip,
        categoria,
        risco_base[
            "score"
        ]
    )


    alerta_id = (
        "CORR-ALT-"
        + datetime.now(
            timezone.utc
        ).strftime(
            "%Y%m%d%H%M%S%f"
        )
    )


    resultado = {
        "projeto":
            PROJETO,

        "aula":
            AULA,

        "status":
            "PROCESSADO",

        "id_evento":
            evento.get(
                "id_evento"
            ),

        "origem":
            evento.get(
                "origem",
                "LABORATORIO"
            ),

        "timestamp":
            agora_utc(),

        "ip_origem":
            ip,

        "classificacao":
            "ATAQUE",

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

        "threat_intelligence":
            ti,

        "risk_score_base":
            risco_base[
                "score"
            ],

        "nivel_risco_base":
            risco_base[
                "nivel"
            ],

        "modo_risk_score":
            risco_base[
                "modo"
            ],

        "correlacao":
            correlacao,

        "risk_score_correlacionado":
            correlacao[
                "risk_score_correlacionado"
            ],

        "nivel_risco":
            correlacao[
                "nivel_risco_correlacionado"
            ],

        "prioridade_soc":
            correlacao[
                "nivel_risco_correlacionado"
            ],

        "alerta_soc":
            True,

        "alerta_id":
            alerta_id
    }


    registro_banco = persistir_correlacao(
        resultado
    )

    resultado[
        "registro_banco"
    ] = registro_banco


    correlacoes.append(
        resultado
    )

    alertas.append(
        {
            "alerta_id":
                alerta_id,

            "id_evento":
                resultado[
                    "id_evento"
                ],

            "ip_origem":
                ip,

            "categoria":
                categoria,

            "status_correlacao":
                correlacao[
                    "status_correlacao"
                ],

            "ocorrencias_total":
                correlacao[
                    "ocorrencias_total"
                ],

            "risk_score_base":
                risco_base[
                    "score"
                ],

            "bonus_correlacao":
                correlacao[
                    "bonus_total"
                ],

            "risk_score_final":
                correlacao[
                    "risk_score_correlacionado"
                ],

            "prioridade_soc":
                correlacao[
                    "nivel_risco_correlacionado"
                ],

            "timestamp":
                resultado[
                    "timestamp"
                ]
        }
    )

    estatisticas[
        "alertas"
    ] += 1

    return resultado


# ============================================================
# EVENTOS DE TESTE
# ============================================================

def preparar_eventos():

    titulo(
        "ETAPA 6 - PREPARANDO EVENTOS DE CORRELACAO"
    )

    eventos = [

        # Primeiro aparecimento do IOC
        {
            "id_evento":
                "CORR-35-001",

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

        # Mesmo IOC novamente
        {
            "id_evento":
                "CORR-35-002",

            "origem":
                "LABORATORIO",

            "ip_origem":
                "8.8.8.8",

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

        # Terceira ocorrencia do mesmo IOC
        {
            "id_evento":
                "CORR-35-003",

            "origem":
                "LABORATORIO",

            "ip_origem":
                "8.8.8.8",

            "spkts": 6,
            "dpkts": 2,
            "sbytes": 3500,
            "dbytes": 250,
            "rate": 1500.0,
            "sttl": 254,
            "dttl": 64,
            "sload": 350000.0,
            "dload": 25000.0
        },

        # IOC diferente
        {
            "id_evento":
                "CORR-35-004",

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
        }
    ]

    print(
        f"[OK] "
        f"{len(eventos)} eventos preparados"
    )

    for evento in eventos:

        print(
            f"- {evento['id_evento']} "
            f"| IOC: {evento['ip_origem']}"
        )

    return eventos


# ============================================================
# EXECUTAR
# ============================================================

def executar_pipeline(eventos):

    titulo(
        "ETAPA 7 - EXECUTANDO CORRELACAO HISTORICA"
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
            f"IOC: "
            f"{evento['ip_origem']}"
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
                "[OK] Evento NORMAL"
            )

            continue

        print(
            f"Categoria: "
            f"{resultado['categoria_ataque']}"
        )

        print(
            f"Probabilidade ataque: "
            f"{resultado['probabilidade_ataque_percentual']:.2f}%"
        )

        print(
            f"Confianca categoria: "
            f"{resultado['confianca_categoria_percentual']:.2f}%"
        )

        print()

        print(
            f"Risk Score base: "
            f"{resultado['risk_score_base']}/100"
        )

        correlacao = resultado[
            "correlacao"
        ]

        print()

        print(
            "CORRELACAO:"
        )

        print(
            f"Status: "
            f"{correlacao['status_correlacao']}"
        )

        print(
            f"Ocorrencias anteriores: "
            f"{correlacao['ocorrencias_anteriores']}"
        )

        print(
            f"Ocorrencias total: "
            f"{correlacao['ocorrencias_total']}"
        )

        print(
            f"Categorias historicas: "
            f"{correlacao['categorias_historicas']}"
        )

        print(
            f"Bonus reincidencia: "
            f"+{correlacao['bonus_reincidencia']}"
        )

        print(
            f"Bonus categorias: "
            f"+{correlacao['bonus_categorias']}"
        )

        print(
            f"Bonus historico critico: "
            f"+{correlacao['bonus_historico_critico']}"
        )

        print(
            f"Bonus total: "
            f"+{correlacao['bonus_total']}"
        )

        print()

        print(
            f"Risk Score correlacionado: "
            f"{resultado['risk_score_correlacionado']}/100"
        )

        print(
            f"Prioridade SOC: "
            f"{resultado['prioridade_soc']}"
        )

        print(
            f"[OK] Alerta: "
            f"{resultado['alerta_id']}"
        )

    return resultados


# ============================================================
# SALVAR JSON
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
        ARQUIVO_CORRELACAO,
        {
            "projeto":
                PROJETO,

            "aula":
                AULA,

            "versao":
                VERSAO,

            "timestamp":
                agora_utc(),

            "correlacoes":
                correlacoes
        }
    )

    print(
        "[OK] Correlacoes salvas"
    )

    print(
        f"Arquivo: "
        f"{ARQUIVO_CORRELACAO.relative_to(BASE_DIR)}"
    )


    salvar_json(
        ARQUIVO_ALERTAS,
        {
            "projeto":
                PROJETO,

            "aula":
                AULA,

            "timestamp":
                agora_utc(),

            "alertas":
                alertas
        }
    )

    print(
        "[OK] Alertas correlacionados salvos"
    )

    print(
        f"Arquivo: "
        f"{ARQUIVO_ALERTAS.relative_to(BASE_DIR)}"
    )


    salvar_json(
        ARQUIVO_RELATORIO,
        {
            "projeto":
                PROJETO,

            "aula":
                AULA,

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
# VALIDAR TABELA
# ============================================================

def tabela_correlacao_existe():

    conexao = conectar_banco()

    cursor = conexao.cursor()

    cursor.execute(
        """
        SELECT name

        FROM sqlite_master

        WHERE
            type = 'table'
            AND
            name = 'correlacao_ioc_eventos'
        """
    )

    resultado = (
        cursor.fetchone()
    )

    conexao.close()

    return (
        resultado is not None
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
            "SQLite disponivel",
            BANCO_PATH.exists()
        ),

        (
            "Tabela de correlacao criada",
            tabela_correlacao_existe()
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
                "risk_scores"
            ] > 0
        ),

        (
            "IOC reincidente detectado",
            estatisticas[
                "iocs_reincidentes"
            ] > 0
        ),

        (
            "Alertas gerados",
            estatisticas[
                "alertas"
            ] > 0
        ),

        (
            "Arquivo correlacao criado",
            ARQUIVO_CORRELACAO.exists()
        ),

        (
            "Relatorio criado",
            ARQUIVO_RELATORIO.exists()
        )
    ]

    ok = 0

    for nome, resultado in validacoes:

        if resultado:

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
        "RESUMO FINAL DA AULA 35"
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
        f"Risk Scores: "
        f"{estatisticas['risk_scores']}"
    )

    print(
        f"IOCs novos: "
        f"{estatisticas['iocs_novos']}"
    )

    print(
        f"IOCs reincidentes: "
        f"{estatisticas['iocs_reincidentes']}"
    )

    print(
        f"Consultas AbuseIPDB: "
        f"{estatisticas['consultas_ti']}"
    )

    print(
        f"Consultas atendidas pelo cache: "
        f"{estatisticas['consultas_ti_cache']}"
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
            "Status: AULA 35 CONCLUIDA"
        )

    else:

        print(
            "Status: AULA 35 REQUER ATENCAO"
        )


# ============================================================
# ARQUITETURA
# ============================================================

def arquitetura():

    titulo(
        "ARQUITETURA DA AULA 35"
    )

    print(
        """
EVENTO
   |
   v
ML BINARIO
   |
   +------ NORMAL --------------------> FINALIZA
   |
   v
ATAQUE
   |
   v
MULTICLASSE
   |
   v
IOC / IP
   |
   v
THREAT INTELLIGENCE
   |
   v
RISK SCORE V2
   |
   v
CONSULTA HISTORICA SQLITE
   |
   +---- IOC NOVO
   |
   +---- IOC REINCIDENTE
              |
              +---- OCORRENCIAS
              +---- CATEGORIAS
              +---- RISCO HISTORICO
              |
              v
        BONUS DE CORRELACAO
              |
              v
    RISK SCORE CORRELACIONADO
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
        "AULA 35 - CORRELACAO HISTORICA DE IOC"
    )

    print(
        PROJETO
    )

    print(
        "Risk Score V2 + Contexto Historico"
    )

    print()

    print(
        "Objetivo:"
    )

    print(
        "Correlacionar IOCs recorrentes "
        "e utilizar o historico para "
        "priorizacao SOC."
    )


    preparar_diretorios()


    if not validar_configuracao():

        sys.exit(1)


    if not validar_artefatos():

        sys.exit(1)


    if not carregar_modelos():

        sys.exit(1)


    inicializar_banco()


    eventos = preparar_eventos()


    resultados = executar_pipeline(
        eventos
    )


    persistir_resultados(
        resultados
    )


    (
        sucesso,
        ok,
        total,
        saude
    ) = validacao_final()


    exibir_resumo(
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
        "AULA 35 - CORRELACAO HISTORICA"
    )


    if sucesso:

        print(
            "AULA 35 CONCLUIDA"
        )

    else:

        print(
            "AULA 35 REQUER ATENCAO"
        )


# ============================================================
# EXECUCAO
# ============================================================

if __name__ == "__main__":

    main()