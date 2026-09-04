# ============================================================
# CyberSentinel-ML
# AULA 40 - INCIDENT EVIDENCE CORRELATION
# Versao corrigida V2
# Campaign Score + Timeline Variation + Deduplicacao Contextual
# ============================================================

import os
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4


# ============================================================
# CONFIGURACAO
# ============================================================

BASE_DIR = Path(__file__).resolve().parent

DADOS_DIR = BASE_DIR / "dados"
EVIDENCIAS_DIR = BASE_DIR / "evidencias"
ALERTAS_DIR = BASE_DIR / "alertas"

DB_PATH = DADOS_DIR / "cybersentinel.db"

ARQUIVO_EVIDENCIAS = EVIDENCIAS_DIR / "evidencias_aula_40.json"
ARQUIVO_RELATORIO = ALERTAS_DIR / "relatorio_aula_40.json"

TABELA_CORRELACAO = "correlacao_ioc_eventos"
TABELA_CAMPANHAS = "campanhas_ioc"
TABELA_TIMELINES = "incident_timelines"
TABELA_PLAYBOOKS = "incident_response_playbooks"
TABELA_MITRE = "mitre_attack_mapping"
TABELA_EVIDENCIAS = "incident_evidence"

LARGURA = 72


# ============================================================
# FUNCOES VISUAIS
# ============================================================

def linha():
    print("=" * LARGURA)


def separador():
    print("-" * LARGURA)


def titulo(texto):
    linha()
    print(texto)
    linha()


def ok(texto):
    print(f"[OK] {texto}")


def info(texto):
    print(f"[INFO] {texto}")


def alerta(texto):
    print(f"[ALERTA] {texto}")


def erro(texto):
    print(f"[ERRO] {texto}")


# ============================================================
# FUNCOES AUXILIARES
# ============================================================

def agora_iso():
    return datetime.now(timezone.utc).isoformat()


def gerar_id(prefixo):
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f")
    sufixo = uuid4().hex[:8].upper()
    return f"{prefixo}-{timestamp}-{sufixo}"


def salvar_json(caminho, dados):
    caminho.parent.mkdir(parents=True, exist_ok=True)

    with open(caminho, "w", encoding="utf-8") as arquivo:
        json.dump(
            dados,
            arquivo,
            ensure_ascii=False,
            indent=4,
            default=str
        )


def tabela_existe(conexao, tabela):
    cursor = conexao.cursor()

    cursor.execute(
        """
        SELECT name
        FROM sqlite_master
        WHERE type = 'table'
        AND name = ?
        """,
        (tabela,)
    )

    return cursor.fetchone() is not None


def obter_colunas(conexao, tabela):
    cursor = conexao.cursor()
    cursor.execute(f"PRAGMA table_info({tabela})")

    return [linha[1] for linha in cursor.fetchall()]


def valor_float(valor, padrao=0.0):
    try:
        if valor is None:
            return padrao

        return float(valor)

    except (TypeError, ValueError):
        return padrao


def valor_int(valor, padrao=0):
    try:
        if valor is None:
            return padrao

        return int(valor)

    except (TypeError, ValueError):
        try:
            return int(float(valor))
        except (TypeError, ValueError):
            return padrao


def texto(valor, padrao="NAO_DISPONIVEL"):
    if valor is None:
        return padrao

    valor = str(valor).strip()

    if not valor:
        return padrao

    return valor


def normalizar_booleano(valor):
    if valor is None:
        return False

    if isinstance(valor, bool):
        return valor

    if isinstance(valor, (int, float)):
        return valor != 0

    valor = str(valor).strip().upper()

    return valor in {
        "1",
        "TRUE",
        "SIM",
        "YES",
        "CAMPANHA_DETECTADA",
        "DETECTADA"
    }


def row_para_dict(row):
    if row is None:
        return None

    return dict(row)


def primeiro_valor(dados, nomes, padrao=None):
    if not dados:
        return padrao

    for nome in nomes:
        if nome in dados:
            valor = dados.get(nome)

            if valor is not None:
                return valor

    return padrao


def escolher_coluna(colunas, candidatos):
    for candidato in candidatos:
        if candidato in colunas:
            return candidato

    return None


def nivel_score(score):
    if score >= 80:
        return "CRITICO"

    if score >= 60:
        return "ALTO"

    if score >= 40:
        return "MEDIO"

    return "BAIXO"


# ============================================================
# PREPARACAO DA TABELA INCIDENT EVIDENCE
# ============================================================

def preparar_tabela_evidencias(conexao):
    cursor = conexao.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS incident_evidence (
            evidence_id TEXT PRIMARY KEY,
            timestamp TEXT,
            ip_origem TEXT,
            total_eventos INTEGER,
            categorias_distintas INTEGER,
            categorias TEXT,
            risk_score_maximo REAL,
            campanha_detectada INTEGER,
            score_campanha REAL,
            nivel_campanha TEXT,
            timeline_id TEXT,
            status_timeline TEXT,
            variacao_risco REAL,
            tendencia_timeline TEXT,
            playbook_id TEXT,
            prioridade_playbook TEXT,
            acao_recomendada TEXT,
            mitre_contexto TEXT,
            mitre_tatica TEXT,
            mitre_technique_id TEXT,
            mitre_confianca TEXT,
            evidence_score REAL,
            nivel_evidencia TEXT,
            confianca_evidencia TEXT,
            fontes_correlacionadas INTEGER,
            componentes TEXT
        )
        """
    )

    conexao.commit()


def migrar_tabela_evidencias(conexao):
    colunas_necessarias = {
        "evidence_id": "TEXT",
        "timestamp": "TEXT",
        "ip_origem": "TEXT",
        "total_eventos": "INTEGER",
        "categorias_distintas": "INTEGER",
        "categorias": "TEXT",
        "risk_score_maximo": "REAL",
        "campanha_detectada": "INTEGER",
        "score_campanha": "REAL",
        "nivel_campanha": "TEXT",
        "timeline_id": "TEXT",
        "status_timeline": "TEXT",
        "variacao_risco": "REAL",
        "tendencia_timeline": "TEXT",
        "playbook_id": "TEXT",
        "prioridade_playbook": "TEXT",
        "acao_recomendada": "TEXT",
        "mitre_contexto": "TEXT",
        "mitre_tatica": "TEXT",
        "mitre_technique_id": "TEXT",
        "mitre_confianca": "TEXT",
        "evidence_score": "REAL",
        "nivel_evidencia": "TEXT",
        "confianca_evidencia": "TEXT",
        "fontes_correlacionadas": "INTEGER",
        "componentes": "TEXT"
    }

    colunas_atuais = obter_colunas(
        conexao,
        TABELA_EVIDENCIAS
    )

    cursor = conexao.cursor()

    adicionadas = []

    for coluna, tipo in colunas_necessarias.items():

        if coluna not in colunas_atuais:

            cursor.execute(
                f"""
                ALTER TABLE {TABELA_EVIDENCIAS}
                ADD COLUMN {coluna} {tipo}
                """
            )

            adicionadas.append(coluna)

    conexao.commit()

    return adicionadas


# ============================================================
# CARREGAMENTO GENERICO
# ============================================================

def carregar_tabela(conexao, tabela):
    cursor = conexao.cursor()

    cursor.execute(
        f"""
        SELECT *
        FROM {tabela}
        """
    )

    return [dict(row) for row in cursor.fetchall()]


# ============================================================
# NORMALIZACAO DO HISTORICO
# ============================================================

def extrair_ip_registro(registro):
    return texto(
        primeiro_valor(
            registro,
            [
                "ip_origem",
                "ioc",
                "ioc_value",
                "valor_ioc",
                "ip"
            ],
            ""
        ),
        ""
    )


def extrair_categoria(registro):
    return texto(
        primeiro_valor(
            registro,
            [
                "categoria",
                "categoria_ml",
                "attack_category"
            ],
            "DESCONHECIDA"
        ),
        "DESCONHECIDA"
    )


def extrair_risk_score(registro):
    return valor_float(
        primeiro_valor(
            registro,
            [
                "risk_score_correlacionado",
                "risk_score",
                "risk_score_maximo",
                "risk_score_base"
            ],
            0
        )
    )


def indexar_historico(registros):
    indice = {}

    for registro in registros:

        ip = extrair_ip_registro(registro)

        if not ip:
            continue

        indice.setdefault(ip, [])
        indice[ip].append(registro)

    return indice


# ============================================================
# CAMPANHAS
# ============================================================

def calcular_score_campanha_por_contexto(
    ocorrencias,
    categorias_distintas,
    risk_medio,
    risk_maximo
):
    """
    Reconstrucao defensiva do Campaign Score quando o banco
    nao possui score_campanha persistido corretamente.

    Mantem o principio da Aula 36:
    frequencia + diversidade + risco medio + risco maximo.
    """

    score = 0.0

    # Frequencia
    if ocorrencias >= 5:
        score += 30
    elif ocorrencias >= 3:
        score += 25
    elif ocorrencias >= 2:
        score += 15
    else:
        score += 5

    # Diversidade
    if categorias_distintas >= 4:
        score += 25
    elif categorias_distintas >= 3:
        score += 20
    elif categorias_distintas >= 2:
        score += 10
    else:
        score += 5

    # Risco medio
    if risk_medio >= 80:
        score += 25
    elif risk_medio >= 60:
        score += 20
    elif risk_medio >= 40:
        score += 10
    else:
        score += 5

    # Risco maximo
    if risk_maximo >= 80:
        score += 20
    elif risk_maximo >= 60:
        score += 15
    elif risk_maximo >= 40:
        score += 10
    else:
        score += 5

    return min(round(score, 2), 100.0)


def normalizar_campanha(registro, historico_ioc):
    ocorrencias = len(historico_ioc)

    categorias = sorted(
        {
            extrair_categoria(item)
            for item in historico_ioc
            if extrair_categoria(item)
        }
    )

    categorias_distintas = len(categorias)

    scores = [
        extrair_risk_score(item)
        for item in historico_ioc
    ]

    scores_validos = [
        score
        for score in scores
        if score >= 0
    ]

    risk_medio = (
        sum(scores_validos) / len(scores_validos)
        if scores_validos
        else 0.0
    )

    risk_maximo = (
        max(scores_validos)
        if scores_validos
        else 0.0
    )

    if registro:
        status = texto(
            primeiro_valor(
                registro,
                [
                    "status",
                    "status_campanha",
                    "campaign_status"
                ],
                ""
            ),
            ""
        )

        detectada = (
            normalizar_booleano(
                primeiro_valor(
                    registro,
                    [
                        "campanha_detectada",
                        "detectada"
                    ],
                    False
                )
            )
            or status.upper() == "CAMPANHA_DETECTADA"
        )

        score_original = valor_float(
            primeiro_valor(
                registro,
                [
                    "score_campanha",
                    "campaign_score",
                    "score"
                ],
                0
            )
        )

        nivel_original = texto(
            primeiro_valor(
                registro,
                [
                    "nivel",
                    "nivel_campanha",
                    "campaign_level"
                ],
                ""
            ),
            ""
        )

    else:
        status = ""
        detectada = False
        score_original = 0.0
        nivel_original = ""

    score_reconstruido = calcular_score_campanha_por_contexto(
        ocorrencias,
        categorias_distintas,
        risk_medio,
        risk_maximo
    )

    # Se campanha foi detectada, score zero e inconsistente.
    # Nesse caso utilizamos o contexto reconstruido.
    if detectada and score_original <= 0:
        score_final = score_reconstruido
        origem_score = "RECONSTRUIDO"
    elif score_original > 0:
        score_final = score_original
        origem_score = "BANCO"
    else:
        score_final = score_original
        origem_score = "BANCO"

    if nivel_original:
        nivel_final = nivel_original
    else:
        nivel_final = nivel_score(score_final)

    if not status:
        status = (
            "CAMPANHA_DETECTADA"
            if detectada
            else "PADRAO_INSUFICIENTE"
        )

    return {
        "detectada": detectada,
        "score": round(score_final, 2),
        "score_original": round(score_original, 2),
        "score_reconstruido": round(
            score_reconstruido,
            2
        ),
        "origem_score": origem_score,
        "nivel": nivel_final,
        "status": status,
        "ocorrencias": ocorrencias,
        "categorias_distintas": categorias_distintas,
        "risk_medio": round(risk_medio, 2),
        "risk_maximo": round(risk_maximo, 2)
    }


def escolher_campanha(registros, ip, historico_ioc):
    candidatos = [
        registro
        for registro in registros
        if extrair_ip_registro(registro) == ip
    ]

    if not candidatos:
        return normalizar_campanha(
            None,
            historico_ioc
        )

    normalizados = [
        normalizar_campanha(
            registro,
            historico_ioc
        )
        for registro in candidatos
    ]

    # Prioridade:
    # 1 - campanha detectada
    # 2 - maior score
    # Isso evita selecionar execucao antiga inconsistente.
    melhor = max(
        normalizados,
        key=lambda item: (
            1 if item["detectada"] else 0,
            item["score"]
        )
    )

    return melhor


# ============================================================
# TIMELINES
# ============================================================

def calcular_variacao_timeline(registro):
    variacao = valor_float(
        primeiro_valor(
            registro,
            [
                "variacao_score",
                "variacao_risco",
                "risk_variation",
                "variacao"
            ],
            0
        )
    )

    score_inicial = valor_float(
        primeiro_valor(
            registro,
            [
                "score_inicial",
                "risk_score_inicial",
                "initial_score"
            ],
            0
        )
    )

    score_final = valor_float(
        primeiro_valor(
            registro,
            [
                "score_final",
                "risk_score_final",
                "final_score"
            ],
            0
        )
    )

    # Se existe score inicial/final, eles sao uma segunda
    # fonte para reconstruir a variacao.
    if variacao == 0 and (
        score_inicial != 0
        or score_final != 0
    ):
        variacao = score_final - score_inicial

    return round(variacao, 2)


def normalizar_timeline(registro):
    if not registro:
        return {
            "id": "NAO_DISPONIVEL",
            "status": "NAO_DISPONIVEL",
            "variacao": 0.0,
            "tendencia": "NAO_DISPONIVEL",
            "score_maximo": 0.0
        }

    return {
        "id": texto(
            primeiro_valor(
                registro,
                [
                    "timeline_id",
                    "id_timeline"
                ]
            )
        ),

        "status": texto(
            primeiro_valor(
                registro,
                [
                    "status",
                    "status_incidente",
                    "incident_status"
                ]
            )
        ),

        "variacao": calcular_variacao_timeline(
            registro
        ),

        "tendencia": texto(
            primeiro_valor(
                registro,
                [
                    "tendencia",
                    "tendencia_risco",
                    "trend"
                ]
            )
        ),

        "score_maximo": valor_float(
            primeiro_valor(
                registro,
                [
                    "score_maximo",
                    "risk_score_maximo",
                    "max_score"
                ],
                0
            )
        )
    }


def escolher_timeline(registros, ip):
    candidatos = [
        registro
        for registro in registros
        if extrair_ip_registro(registro) == ip
    ]

    if not candidatos:
        return normalizar_timeline(None)

    normalizados = [
        normalizar_timeline(registro)
        for registro in candidatos
    ]

    melhor = max(
        normalizados,
        key=lambda item: (
            item["score_maximo"],
            abs(item["variacao"])
        )
    )

    return melhor


# ============================================================
# PLAYBOOKS
# ============================================================

def prioridade_numero(prioridade):
    mapa = {
        "BAIXO": 1,
        "MEDIO": 2,
        "ALTO": 3,
        "CRITICO": 4
    }

    return mapa.get(
        str(prioridade).upper(),
        0
    )


def normalizar_playbook(registro):
    if not registro:
        return {
            "id": "NAO_DISPONIVEL",
            "prioridade": "NAO_DISPONIVEL",
            "acao": "NAO_DISPONIVEL"
        }

    return {
        "id": texto(
            primeiro_valor(
                registro,
                [
                    "playbook_id",
                    "id_playbook"
                ]
            )
        ),

        "prioridade": texto(
            primeiro_valor(
                registro,
                [
                    "prioridade",
                    "priority"
                ]
            )
        ),

        "acao": texto(
            primeiro_valor(
                registro,
                [
                    "acao_recomendada",
                    "recommended_action",
                    "acao"
                ]
            )
        )
    }


def escolher_playbook(registros, ip):
    candidatos = [
        registro
        for registro in registros
        if extrair_ip_registro(registro) == ip
    ]

    if not candidatos:
        return normalizar_playbook(None)

    normalizados = [
        normalizar_playbook(registro)
        for registro in candidatos
    ]

    melhor = max(
        normalizados,
        key=lambda item: prioridade_numero(
            item["prioridade"]
        )
    )

    return melhor


# ============================================================
# MITRE ATT&CK
# ============================================================

def confianca_mitre_numero(confianca):
    mapa = {
        "INSUFICIENTE": 1,
        "CONTEXTUAL": 2,
        "PROVAVEL": 3,
        "CONFIRMADA": 4
    }

    return mapa.get(
        str(confianca).upper(),
        0
    )


def normalizar_mitre(registro):
    if not registro:
        return {
            "contexto": "NAO_DISPONIVEL",
            "tatica": "NAO_ATRIBUIDA",
            "technique_id": "NAO_ATRIBUIDA",
            "confianca": "INSUFICIENTE"
        }

    return {
        "contexto": texto(
            primeiro_valor(
                registro,
                [
                    "contexto",
                    "contexto_ataque",
                    "attack_context"
                ]
            )
        ),

        "tatica": texto(
            primeiro_valor(
                registro,
                [
                    "tatica_candidata",
                    "tatica",
                    "tactic"
                ],
                "NAO_ATRIBUIDA"
            ),
            "NAO_ATRIBUIDA"
        ),

        "technique_id": texto(
            primeiro_valor(
                registro,
                [
                    "technique_id",
                    "mitre_technique_id"
                ],
                "NAO_ATRIBUIDA"
            ),
            "NAO_ATRIBUIDA"
        ),

        "confianca": texto(
            primeiro_valor(
                registro,
                [
                    "confianca_mapping",
                    "confianca",
                    "mapping_confidence"
                ],
                "INSUFICIENTE"
            ),
            "INSUFICIENTE"
        )
    }


def escolher_mitre(registros, ip):
    candidatos = [
        registro
        for registro in registros
        if extrair_ip_registro(registro) == ip
    ]

    if not candidatos:
        return normalizar_mitre(None)

    normalizados = [
        normalizar_mitre(registro)
        for registro in candidatos
    ]

    melhor = max(
        normalizados,
        key=lambda item: confianca_mitre_numero(
            item["confianca"]
        )
    )

    return melhor


# ============================================================
# EVIDENCE SCORE
# ============================================================

def calcular_evidence_score(
    total_eventos,
    categorias_distintas,
    risk_score_maximo,
    campanha,
    timeline,
    playbook,
    mitre
):
    score = 0.0
    componentes = []

    # --------------------------------------------------------
    # HISTORICO
    # --------------------------------------------------------

    if total_eventos >= 3:
        score += 15
        componentes.append(
            "HISTORICO_REINCIDENTE"
        )

    elif total_eventos >= 2:
        score += 10
        componentes.append(
            "HISTORICO_REINCIDENTE"
        )

    elif total_eventos == 1:
        score += 5
        componentes.append(
            "HISTORICO_ISOLADO"
        )

    # --------------------------------------------------------
    # DIVERSIDADE
    # --------------------------------------------------------

    if categorias_distintas >= 3:
        score += 12
        componentes.append(
            "DIVERSIDADE_ALTA"
        )

    elif categorias_distintas == 2:
        score += 7
        componentes.append(
            "DIVERSIDADE_MEDIA"
        )

    # --------------------------------------------------------
    # RISK SCORE HISTORICO
    # --------------------------------------------------------

    if risk_score_maximo >= 80:
        score += 15

    elif risk_score_maximo >= 60:
        score += 10

    elif risk_score_maximo >= 40:
        score += 5

    # --------------------------------------------------------
    # CAMPANHA
    # --------------------------------------------------------

    if campanha["detectada"]:
        score += 15
        componentes.append(
            "CAMPANHA_DETECTADA"
        )

        if campanha["score"] >= 80:
            score += 5

        elif campanha["score"] >= 60:
            score += 3

    # --------------------------------------------------------
    # TIMELINE
    # --------------------------------------------------------

    if timeline["status"] == "INCIDENTE_CRITICO":
        score += 10
        componentes.append(
            "TIMELINE_CRITICA"
        )

    elif timeline["status"] not in {
        "NAO_DISPONIVEL",
        "EVENTO_ISOLADO"
    }:
        score += 5

    if timeline["variacao"] >= 40:
        score += 5

    elif timeline["variacao"] >= 20:
        score += 3

    # --------------------------------------------------------
    # INCIDENT RESPONSE
    # --------------------------------------------------------

    prioridade = playbook["prioridade"].upper()

    if prioridade == "CRITICO":
        score += 10
        componentes.append(
            "PLAYBOOK_CRITICO"
        )

    elif prioridade == "ALTO":
        score += 7

    elif prioridade == "MEDIO":
        score += 3

    # --------------------------------------------------------
    # MITRE
    # --------------------------------------------------------

    confianca_mitre = mitre["confianca"].upper()

    if confianca_mitre == "CONFIRMADA":
        score += 8
        componentes.append(
            "MITRE_CONFIRMADO"
        )

    elif confianca_mitre == "PROVAVEL":
        score += 6
        componentes.append(
            "MITRE_PROVAVEL"
        )

    elif confianca_mitre == "CONTEXTUAL":
        score += 5
        componentes.append(
            "MITRE_CONTEXTUAL"
        )

    # Limite
    score = min(score, 100.0)

    return round(score, 2), componentes


def calcular_confianca(fontes_correlacionadas):
    if fontes_correlacionadas >= 5:
        return "ALTA"

    if fontes_correlacionadas >= 3:
        return "MEDIA"

    return "BAIXA"


# ============================================================
# CONTAGEM DE FONTES
# ============================================================

def contar_fontes(
    historico,
    campanha_existe,
    timeline,
    playbook,
    mitre
):
    total = 0

    if historico:
        total += 1

    if campanha_existe:
        total += 1

    if timeline["id"] != "NAO_DISPONIVEL":
        total += 1

    if playbook["id"] != "NAO_DISPONIVEL":
        total += 1

    if mitre["contexto"] != "NAO_DISPONIVEL":
        total += 1

    return total


# ============================================================
# PERSISTENCIA
# ============================================================

def persistir_evidencia(conexao, evidencia):
    cursor = conexao.cursor()

    cursor.execute(
        """
        INSERT OR REPLACE INTO incident_evidence (
            evidence_id,
            timestamp,
            ip_origem,
            total_eventos,
            categorias_distintas,
            categorias,
            risk_score_maximo,
            campanha_detectada,
            score_campanha,
            nivel_campanha,
            timeline_id,
            status_timeline,
            variacao_risco,
            tendencia_timeline,
            playbook_id,
            prioridade_playbook,
            acao_recomendada,
            mitre_contexto,
            mitre_tatica,
            mitre_technique_id,
            mitre_confianca,
            evidence_score,
            nivel_evidencia,
            confianca_evidencia,
            fontes_correlacionadas,
            componentes
        )
        VALUES (
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
            ?, ?, ?, ?, ?, ?
        )
        """,
        (
            evidencia["evidence_id"],
            evidencia["timestamp"],
            evidencia["ip_origem"],
            evidencia["total_eventos"],
            evidencia["categorias_distintas"],
            json.dumps(
                evidencia["categorias"],
                ensure_ascii=False
            ),
            evidencia["risk_score_maximo"],
            int(evidencia["campanha_detectada"]),
            evidencia["score_campanha"],
            evidencia["nivel_campanha"],
            evidencia["timeline_id"],
            evidencia["status_timeline"],
            evidencia["variacao_risco"],
            evidencia["tendencia_timeline"],
            evidencia["playbook_id"],
            evidencia["prioridade_playbook"],
            evidencia["acao_recomendada"],
            evidencia["mitre_contexto"],
            evidencia["mitre_tatica"],
            evidencia["mitre_technique_id"],
            evidencia["mitre_confianca"],
            evidencia["evidence_score"],
            evidencia["nivel_evidencia"],
            evidencia["confianca_evidencia"],
            evidencia["fontes_correlacionadas"],
            json.dumps(
                evidencia["componentes"],
                ensure_ascii=False
            )
        )
    )

    conexao.commit()


# ============================================================
# VALIDACOES DE CONSISTENCIA
# ============================================================

def validar_consistencia(evidencias):
    resultados = []

    # 1
    resultados.append(
        (
            "Evidencias geradas",
            len(evidencias) > 0
        )
    )

    # 2
    campanha_inconsistente = any(
        item["campanha_detectada"]
        and item["score_campanha"] <= 0
        for item in evidencias
    )

    resultados.append(
        (
            "Campanhas detectadas possuem score valido",
            not campanha_inconsistente
        )
    )

    # 3
    timeline_inconsistente = any(
        item["tendencia_timeline"]
        == "FORTE_CRESCIMENTO"
        and item["variacao_risco"] <= 0
        for item in evidencias
    )

    resultados.append(
        (
            "Timelines em forte crescimento possuem variacao positiva",
            not timeline_inconsistente
        )
    )

    # 4
    resultados.append(
        (
            "Todos os Evidence Scores estao entre 0 e 100",
            all(
                0 <= item["evidence_score"] <= 100
                for item in evidencias
            )
        )
    )

    # 5
    resultados.append(
        (
            "Todos os IOCs possuem identificacao",
            all(
                item["ip_origem"]
                for item in evidencias
            )
        )
    )

    return resultados


# ============================================================
# MAIN
# ============================================================

def main():

    titulo(
        "AULA 40 - INCIDENT EVIDENCE CORRELATION"
    )

    print("CyberSentinel-ML")
    print("Incident Evidence + Cross-Layer Correlation")
    print(
        "Versao corrigida V2 - "
        "Campaign Score + Timeline Variation"
    )
    print()
    print("Objetivo:")
    print(
        "Correlacionar evidencias produzidas pelo pipeline"
    )
    print(
        "e construir contexto estruturado para investigacao SOC."
    )
    print()
    print("IMPORTANTE:")
    print(
        "Nenhuma acao de bloqueio sera executada."
    )
    print(
        "O Evidence Score nao representa probabilidade de ataque."
    )
    print(
        "Ele representa a forca do contexto correlacionado."
    )
    print()

    validacoes = []

    # ========================================================
    # ETAPA 1
    # ========================================================

    titulo(
        "ETAPA 1 - PREPARANDO DIRETORIOS"
    )

    for diretorio, nome in [
        (DADOS_DIR, "dados"),
        (EVIDENCIAS_DIR, "evidencias"),
        (ALERTAS_DIR, "alertas")
    ]:
        diretorio.mkdir(
            parents=True,
            exist_ok=True
        )

        ok(
            f"Diretorio {nome} pronto"
        )

        validacoes.append(
            (
                f"Diretorio {nome} disponivel",
                diretorio.exists()
            )
        )

    # ========================================================
    # ETAPA 2
    # ========================================================

    titulo(
        "ETAPA 2 - VALIDANDO SQLITE"
    )

    if not DB_PATH.exists():
        erro(
            f"Banco SQLite nao encontrado: {DB_PATH}"
        )
        return

    ok("Banco SQLite encontrado")
    print(f"Banco: {DB_PATH.relative_to(BASE_DIR)}")

    validacoes.append(
        (
            "Banco SQLite encontrado",
            DB_PATH.exists()
        )
    )

    conexao = sqlite3.connect(DB_PATH)
    conexao.row_factory = sqlite3.Row

    # ========================================================
    # ETAPA 3
    # ========================================================

    titulo(
        "ETAPA 3 - VALIDANDO PIPELINE ANTERIOR"
    )

    tabelas_necessarias = [
        TABELA_CORRELACAO,
        TABELA_CAMPANHAS,
        TABELA_TIMELINES,
        TABELA_PLAYBOOKS,
        TABELA_MITRE
    ]

    for tabela in tabelas_necessarias:

        existe = tabela_existe(
            conexao,
            tabela
        )

        if existe:
            ok(
                f"Tabela encontrada: {tabela}"
            )
        else:
            erro(
                f"Tabela ausente: {tabela}"
            )

        validacoes.append(
            (
                f"Tabela {tabela} disponivel",
                existe
            )
        )

    if not all(
        tabela_existe(conexao, tabela)
        for tabela in tabelas_necessarias
    ):
        conexao.close()
        return

    # ========================================================
    # ETAPA 4
    # ========================================================

    titulo(
        "ETAPA 4 - PREPARANDO INCIDENT EVIDENCE"
    )

    preparar_tabela_evidencias(
        conexao
    )

    ok(
        "Tabela incident_evidence pronta"
    )

    adicionadas = migrar_tabela_evidencias(
        conexao
    )

    if adicionadas:
        ok(
            "Schema incident_evidence atualizado"
        )
        print(
            "Colunas adicionadas: "
            + ", ".join(adicionadas)
        )
    else:
        ok(
            "Schema incident_evidence compativel"
        )

    colunas_evidencia = obter_colunas(
        conexao,
        TABELA_EVIDENCIAS
    )

    ok(
        f"Colunas incident_evidence: "
        f"{len(colunas_evidencia)}"
    )

    validacoes.append(
        (
            "Tabela incident_evidence disponivel",
            tabela_existe(
                conexao,
                TABELA_EVIDENCIAS
            )
        )
    )

    # ========================================================
    # ETAPA 5
    # ========================================================

    titulo(
        "ETAPA 5 - CARREGANDO CONTEXTO DO PIPELINE"
    )

    correlacao = carregar_tabela(
        conexao,
        TABELA_CORRELACAO
    )

    campanhas = carregar_tabela(
        conexao,
        TABELA_CAMPANHAS
    )

    timelines = carregar_tabela(
        conexao,
        TABELA_TIMELINES
    )

    playbooks = carregar_tabela(
        conexao,
        TABELA_PLAYBOOKS
    )

    mitre = carregar_tabela(
        conexao,
        TABELA_MITRE
    )

    ok(
        f"correlacao: {len(correlacao)} registros"
    )
    ok(
        f"campanhas: {len(campanhas)} registros"
    )
    ok(
        f"timelines: {len(timelines)} registros"
    )
    ok(
        f"playbooks: {len(playbooks)} registros"
    )
    ok(
        f"mitre: {len(mitre)} registros"
    )

    validacoes.append(
        (
            "Historico carregado",
            len(correlacao) > 0
        )
    )

    # ========================================================
    # ETAPA 6
    # ========================================================

    titulo(
        "ETAPA 6 - INDEXANDO CONTEXTO POR IOC"
    )

    historico_por_ip = indexar_historico(
        correlacao
    )

    iocs = sorted(
        historico_por_ip.keys()
    )

    ok(
        f"IOCs encontrados: {len(iocs)}"
    )

    for ip in iocs:
        print(f"- {ip}")

    validacoes.append(
        (
            "IOCs historicos encontrados",
            len(iocs) > 0
        )
    )

    # ========================================================
    # ETAPA 7
    # ========================================================

    titulo(
        "ETAPA 7 - EXECUTANDO EVIDENCE CORRELATION"
    )

    evidencias = []

    campanhas_integradas = 0
    timelines_integradas = 0
    playbooks_integrados = 0
    mitre_integrados = 0

    for indice, ip in enumerate(
        iocs,
        start=1
    ):

        separador()
        print(
            f"IOC {indice}/{len(iocs)}"
        )
        separador()

        print(f"IOC: {ip}")
        print()

        historico_ioc = historico_por_ip[
            ip
        ]

        categorias = sorted(
            {
                extrair_categoria(registro)
                for registro in historico_ioc
            }
        )

        scores = [
            extrair_risk_score(registro)
            for registro in historico_ioc
        ]

        risk_score_maximo = (
            max(scores)
            if scores
            else 0.0
        )

        # ----------------------------------------------------
        # HISTORICO
        # ----------------------------------------------------

        print("HISTORICO:")
        print(
            f"Eventos: {len(historico_ioc)}"
        )
        print(
            f"Categorias distintas: "
            f"{len(categorias)}"
        )
        print(
            f"Categorias: {categorias}"
        )
        print(
            f"Risk Score maximo: "
            f"{risk_score_maximo:.2f}/100"
        )
        print()

        # ----------------------------------------------------
        # CAMPANHA
        # ----------------------------------------------------

        candidatos_campanha = [
            registro
            for registro in campanhas
            if extrair_ip_registro(
                registro
            ) == ip
        ]

        campanha = escolher_campanha(
            campanhas,
            ip,
            historico_ioc
        )

        campanha_existe = (
            len(candidatos_campanha) > 0
        )

        if campanha["detectada"]:
            campanhas_integradas += 1

        print("CAMPANHA:")
        print(
            "Detectada: "
            + (
                "SIM"
                if campanha["detectada"]
                else "NAO"
            )
        )

        print(
            f"Score: "
            f"{campanha['score']:.2f}/100"
        )

        print(
            f"Nivel: {campanha['nivel']}"
        )

        if (
            campanha["origem_score"]
            == "RECONSTRUIDO"
        ):
            print(
                "Origem score: "
                "RECONSTRUIDO DO CONTEXTO"
            )
            print(
                "Motivo: campanha detectada "
                "com score persistido igual a zero"
            )

        else:
            print(
                "Origem score: BANCO"
            )

        print()

        # ----------------------------------------------------
        # TIMELINE
        # ----------------------------------------------------

        timeline = escolher_timeline(
            timelines,
            ip
        )

        if (
            timeline["id"]
            != "NAO_DISPONIVEL"
        ):
            timelines_integradas += 1

        print("TIMELINE:")
        print(
            f"ID: {timeline['id']}"
        )
        print(
            f"Status: {timeline['status']}"
        )
        print(
            f"Variacao risco: "
            f"{timeline['variacao']:+.2f}"
        )
        print(
            f"Tendencia: "
            f"{timeline['tendencia']}"
        )
        print()

        # ----------------------------------------------------
        # INCIDENT RESPONSE
        # ----------------------------------------------------

        playbook = escolher_playbook(
            playbooks,
            ip
        )

        if (
            playbook["id"]
            != "NAO_DISPONIVEL"
        ):
            playbooks_integrados += 1

        print("INCIDENT RESPONSE:")
        print(
            f"Playbook: {playbook['id']}"
        )
        print(
            f"Prioridade: "
            f"{playbook['prioridade']}"
        )
        print(
            f"Acao: {playbook['acao']}"
        )
        print()

        # ----------------------------------------------------
        # MITRE
        # ----------------------------------------------------

        mitre_contexto = escolher_mitre(
            mitre,
            ip
        )

        if (
            mitre_contexto["contexto"]
            != "NAO_DISPONIVEL"
        ):
            mitre_integrados += 1

        print("MITRE ATT&CK:")
        print(
            f"Contexto: "
            f"{mitre_contexto['contexto']}"
        )
        print(
            f"Tatica: "
            f"{mitre_contexto['tatica']}"
        )
        print(
            f"Technique ID: "
            f"{mitre_contexto['technique_id']}"
        )
        print(
            f"Confianca: "
            f"{mitre_contexto['confianca']}"
        )
        print()

        # ----------------------------------------------------
        # FONTES
        # ----------------------------------------------------

        fontes = contar_fontes(
            historico_ioc,
            campanha_existe,
            timeline,
            playbook,
            mitre_contexto
        )

        # ----------------------------------------------------
        # EVIDENCE SCORE
        # ----------------------------------------------------

        evidence_score, componentes = (
            calcular_evidence_score(
                total_eventos=len(
                    historico_ioc
                ),
                categorias_distintas=len(
                    categorias
                ),
                risk_score_maximo=(
                    risk_score_maximo
                ),
                campanha=campanha,
                timeline=timeline,
                playbook=playbook,
                mitre=mitre_contexto
            )
        )

        nivel_evidencia = nivel_score(
            evidence_score
        )

        confianca_evidencia = (
            calcular_confianca(fontes)
        )

        evidence_id = gerar_id(
            "EVD-40"
        )

        evidencia = {
            "evidence_id": evidence_id,
            "timestamp": agora_iso(),
            "ip_origem": ip,

            "total_eventos": len(
                historico_ioc
            ),

            "categorias_distintas": len(
                categorias
            ),

            "categorias": categorias,

            "risk_score_maximo": round(
                risk_score_maximo,
                2
            ),

            "campanha_detectada": (
                campanha["detectada"]
            ),

            "score_campanha": (
                campanha["score"]
            ),

            "nivel_campanha": (
                campanha["nivel"]
            ),

            "origem_score_campanha": (
                campanha["origem_score"]
            ),

            "timeline_id": (
                timeline["id"]
            ),

            "status_timeline": (
                timeline["status"]
            ),

            "variacao_risco": (
                timeline["variacao"]
            ),

            "tendencia_timeline": (
                timeline["tendencia"]
            ),

            "playbook_id": (
                playbook["id"]
            ),

            "prioridade_playbook": (
                playbook["prioridade"]
            ),

            "acao_recomendada": (
                playbook["acao"]
            ),

            "mitre_contexto": (
                mitre_contexto["contexto"]
            ),

            "mitre_tatica": (
                mitre_contexto["tatica"]
            ),

            "mitre_technique_id": (
                mitre_contexto[
                    "technique_id"
                ]
            ),

            "mitre_confianca": (
                mitre_contexto["confianca"]
            ),

            "evidence_score": (
                evidence_score
            ),

            "nivel_evidencia": (
                nivel_evidencia
            ),

            "confianca_evidencia": (
                confianca_evidencia
            ),

            "fontes_correlacionadas": (
                fontes
            ),

            "componentes": componentes
        }

        persistir_evidencia(
            conexao,
            evidencia
        )

        evidencias.append(
            evidencia
        )

        print("INCIDENT EVIDENCE:")
        print(
            f"Evidence Score: "
            f"{evidence_score:.2f}/100"
        )
        print(
            f"Nivel: {nivel_evidencia}"
        )
        print(
            f"Confianca: "
            f"{confianca_evidencia}"
        )
        print(
            f"Fontes correlacionadas: "
            f"{fontes}/5"
        )
        print(
            f"Componentes: {componentes}"
        )

        ok(
            f"Evidencia: {evidence_id}"
        )

    # ========================================================
    # ETAPA 8
    # ========================================================

    titulo(
        "ETAPA 8 - ANALISANDO COBERTURA DE EVIDENCIAS"
    )

    distribuicao = {
        "BAIXO": 0,
        "MEDIO": 0,
        "ALTO": 0,
        "CRITICO": 0
    }

    confiancas = {
        "BAIXA": 0,
        "MEDIA": 0,
        "ALTA": 0
    }

    for evidencia in evidencias:

        distribuicao[
            evidencia["nivel_evidencia"]
        ] += 1

        confiancas[
            evidencia[
                "confianca_evidencia"
            ]
        ] += 1

    print(
        f"Evidencias geradas: "
        f"{len(evidencias)}"
    )
    print(
        f"Campanhas integradas: "
        f"{campanhas_integradas}"
    )
    print(
        f"Timelines integradas: "
        f"{timelines_integradas}"
    )
    print(
        f"Playbooks integrados: "
        f"{playbooks_integrados}"
    )
    print(
        f"Contextos MITRE integrados: "
        f"{mitre_integrados}"
    )

    print()
    print(
        "Distribuicao Evidence Score:"
    )

    for nivel in [
        "BAIXO",
        "MEDIO",
        "ALTO",
        "CRITICO"
    ]:
        print(
            f"{nivel}: "
            f"{distribuicao[nivel]}"
        )

    print()
    print(
        "Confianca das evidencias:"
    )

    for nivel in [
        "BAIXA",
        "MEDIA",
        "ALTA"
    ]:
        print(
            f"{nivel}: "
            f"{confiancas[nivel]}"
        )

    # ========================================================
    # ETAPA 9
    # ========================================================

    titulo(
        "ETAPA 9 - VALIDANDO CONSISTENCIA CROSS-LAYER"
    )

    validacoes_consistencia = (
        validar_consistencia(
            evidencias
        )
    )

    for nome, resultado in (
        validacoes_consistencia
    ):
        if resultado:
            ok(nome)
        else:
            erro(nome)

        validacoes.append(
            (nome, resultado)
        )

    # ========================================================
    # ETAPA 10
    # ========================================================

    titulo(
        "ETAPA 10 - PERSISTINDO RESULTADOS"
    )

    salvar_json(
        ARQUIVO_EVIDENCIAS,
        evidencias
    )

    ok(
        "Evidencias salvas"
    )
    print(
        "Arquivo: "
        f"{ARQUIVO_EVIDENCIAS.relative_to(BASE_DIR)}"
    )

    validacoes.append(
        (
            "Arquivo de evidencias criado",
            ARQUIVO_EVIDENCIAS.exists()
        )
    )

    # Relatorio sera finalizado depois das
    # validacoes completas.

    # ========================================================
    # ETAPA 11
    # ========================================================

    titulo(
        "ETAPA 11 - VALIDACAO FINAL"
    )

    validacoes_extras = [
        (
            "Todos os IOCs processados",
            len(evidencias) == len(iocs)
            and len(iocs) > 0
        ),
        (
            "Risk Score historico integrado",
            all(
                "risk_score_maximo" in e
                for e in evidencias
            )
        ),
        (
            "Timeline correlacionada",
            timelines_integradas > 0
        ),
        (
            "Incident Response correlacionado",
            playbooks_integrados > 0
        ),
        (
            "MITRE correlacionado",
            mitre_integrados > 0
        ),
        (
            "Evidence Score calculado",
            all(
                "evidence_score" in e
                for e in evidencias
            )
        ),
        (
            "Confianca de evidencia calculada",
            all(
                e["confianca_evidencia"]
                in {
                    "BAIXA",
                    "MEDIA",
                    "ALTA"
                }
                for e in evidencias
            )
        )
    ]

    for nome, resultado in (
        validacoes_extras
    ):
        validacoes.append(
            (nome, resultado)
        )

    # Evita duplicar nomes de validacao
    # quando etapas anteriores ja adicionaram.
    validacoes_unicas = []
    nomes_vistos = set()

    for nome, resultado in validacoes:

        if nome in nomes_vistos:
            continue

        nomes_vistos.add(nome)

        validacoes_unicas.append(
            (nome, resultado)
        )

    for nome, resultado in (
        validacoes_unicas
    ):
        if resultado:
            ok(nome)
        else:
            erro(nome)

    total_validacoes = len(
        validacoes_unicas
    )

    total_ok = sum(
        1
        for _, resultado
        in validacoes_unicas
        if resultado
    )

    saude = (
        total_ok
        / total_validacoes
        * 100
        if total_validacoes
        else 0
    )

    print()
    print(
        f"Validacoes: "
        f"{total_ok}/{total_validacoes}"
    )
    print(
        f"Saude: {saude:.2f}%"
    )

    # ========================================================
    # RELATORIO
    # ========================================================

    relatorio = {
        "aula": 40,
        "nome": (
            "INCIDENT EVIDENCE CORRELATION"
        ),
        "versao": (
            "V2 - Campaign Score + "
            "Timeline Variation"
        ),
        "timestamp": agora_iso(),

        "iocs_analisados": len(iocs),
        "evidencias_geradas": len(
            evidencias
        ),

        "campanhas_integradas": (
            campanhas_integradas
        ),

        "timelines_integradas": (
            timelines_integradas
        ),

        "playbooks_integrados": (
            playbooks_integrados
        ),

        "contextos_mitre_integrados": (
            mitre_integrados
        ),

        "distribuicao_evidence_score": (
            distribuicao
        ),

        "confianca_evidencias": (
            confiancas
        ),

        "validacoes": {
            "total": total_validacoes,
            "ok": total_ok,
            "saude": round(
                saude,
                2
            )
        },

        "status": (
            "AULA 40 CONCLUIDA"
            if total_ok
            == total_validacoes
            else
            "AULA 40 COM INCONSISTENCIAS"
        )
    }

    salvar_json(
        ARQUIVO_RELATORIO,
        relatorio
    )

    ok(
        "Relatorio salvo"
    )
    print(
        "Arquivo: "
        f"{ARQUIVO_RELATORIO.relative_to(BASE_DIR)}"
    )

    # ========================================================
    # RESUMO
    # ========================================================

    titulo(
        "RESUMO FINAL DA AULA 40"
    )

    print(
        f"IOCs analisados: {len(iocs)}"
    )
    print(
        f"Evidencias geradas: "
        f"{len(evidencias)}"
    )
    print(
        f"Campanhas integradas: "
        f"{campanhas_integradas}"
    )
    print(
        f"Timelines integradas: "
        f"{timelines_integradas}"
    )
    print(
        f"Playbooks integrados: "
        f"{playbooks_integrados}"
    )
    print(
        f"Contextos MITRE integrados: "
        f"{mitre_integrados}"
    )

    print()
    print(
        "Distribuicao Evidence Score:"
    )

    for nivel in [
        "BAIXO",
        "MEDIO",
        "ALTO",
        "CRITICO"
    ]:
        print(
            f"{nivel}: "
            f"{distribuicao[nivel]}"
        )

    print()
    print(
        f"Validacoes: "
        f"{total_ok}/{total_validacoes}"
    )
    print(
        f"Saude: {saude:.2f}%"
    )

    if (
        total_ok
        == total_validacoes
    ):
        print(
            "Status: AULA 40 CONCLUIDA"
        )
    else:
        print(
            "Status: "
            "AULA 40 COM INCONSISTENCIAS"
        )

    # ========================================================
    # ARQUITETURA
    # ========================================================

    titulo(
        "ARQUITETURA DA AULA 40"
    )

    print(
        r"""
       CYBERSENTINEL-ML
              |
              v
     EVENTOS CORRELACIONADOS
              |
              v
       IOC / IP ORIGEM
              |
      +-------+-------+
      |       |       |
      v       v       v
 HISTORICO  CAMPANHA TIMELINE
      |       |       |
      |       |       +---- variacao_score
      |       |
      |       +---- score_campanha
      |       |
      |       +---- reconstrucao segura
      |            se necessario
      |
      +-------+-------+
              |
              v
       INCIDENT RESPONSE
              |
              v
        MITRE ATT&CK
              |
              v
   EVIDENCE CORRELATION ENGINE
              |
       +------+------+ 
       |      |      |
       v      v      v
 HISTORICO CAMPANHA TIMELINE
       |      |      |
       +------+------+ 
              |
       +------+------+ 
       |             |
       v             v
 INCIDENT         MITRE
 RESPONSE         CONTEXT
       |             |
       +------+------+ 
              |
              v
       EVIDENCE SCORE
           0 - 100
              |
       +------+------+------+
       |      |      |      |
       v      v      v      v
     BAIXO  MEDIO   ALTO  CRITICO
              |
              v
    EVIDENCE CONFIDENCE
              |
       +------+------+ 
       |      |      |
       v      v      v
     BAIXA  MEDIA   ALTA
              |
              v
   VALIDACAO CROSS-LAYER
              |
       +------+------+
       |             |
       v             v
 CAMPANHA         TIMELINE
 SCORE > 0       VARIACAO > 0
 quando          quando existe
 detectada       forte crescimento
       |             |
       +------+------+
              |
              v
     CONTEXTO SOC UNIFICADO
              |
              v
      INVESTIGACAO HUMANA


IMPORTANTE:

Evidence Score != probabilidade de ataque.

O Evidence Score mede a forca do conjunto
de evidencias correlacionadas.

Uma campanha detectada nao pode ser aceita
silenciosamente com score igual a zero.

Uma timeline FORTE_CRESCIMENTO nao pode ser
aceita silenciosamente com variacao igual a zero.

MITRE Technique ID continua dependendo de
evidencia suficiente.

Nenhuma acao de bloqueio e executada.
"""
    )

    linha()
    print("CYBERSENTINEL-ML")
    linha()
    print(
        "AULA 40 - INCIDENT EVIDENCE CORRELATION"
    )

    if (
        total_ok
        == total_validacoes
    ):
        print(
            "AULA 40 CONCLUIDA"
        )
    else:
        print(
            "AULA 40 COM INCONSISTENCIAS"
        )

    conexao.close()


# ============================================================
# EXECUCAO
# ============================================================

if __name__ == "__main__":
    main()