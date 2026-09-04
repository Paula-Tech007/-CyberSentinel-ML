# ============================================================
# CyberSentinel-ML
# AULA 41 - SOC INCIDENT DECISION ENGINE
# Evidence Correlation + Decision Support + SOC Prioritization
# ============================================================

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
DECISOES_DIR = BASE_DIR / "decisoes"
ALERTAS_DIR = BASE_DIR / "alertas"

DB_PATH = DADOS_DIR / "cybersentinel.db"

ARQUIVO_DECISOES = DECISOES_DIR / "decisoes_aula_41.json"
ARQUIVO_ALERTAS = ALERTAS_DIR / "alertas_decision_engine_aula_41.json"
ARQUIVO_RELATORIO = ALERTAS_DIR / "relatorio_aula_41.json"

TABELA_EVIDENCIAS = "incident_evidence"
TABELA_DECISOES = "soc_incident_decisions"

LARGURA = 72


# ============================================================
# VISUAL
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
# UTILITARIOS
# ============================================================

def agora_iso():
    return datetime.now(timezone.utc).isoformat()


def gerar_id(prefixo):
    timestamp = datetime.now(timezone.utc).strftime(
        "%Y%m%d%H%M%S%f"
    )
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

    return [registro[1] for registro in cursor.fetchall()]


def primeiro_valor(dados, nomes, padrao=None):
    if not dados:
        return padrao

    for nome in nomes:
        if nome in dados:
            valor = dados.get(nome)

            if valor is not None:
                return valor

    return padrao


def texto(valor, padrao="NAO_DISPONIVEL"):
    if valor is None:
        return padrao

    valor = str(valor).strip()

    if not valor:
        return padrao

    return valor


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


def normalizar_booleano(valor):
    if isinstance(valor, bool):
        return valor

    if valor is None:
        return False

    if isinstance(valor, (int, float)):
        return valor != 0

    return str(valor).strip().upper() in {
        "1",
        "TRUE",
        "SIM",
        "YES",
        "DETECTADA",
        "CAMPANHA_DETECTADA"
    }


def nivel_para_numero(nivel):
    mapa = {
        "BAIXO": 1,
        "MEDIO": 2,
        "ALTO": 3,
        "CRITICO": 4
    }

    return mapa.get(
        str(nivel).upper(),
        0
    )


# ============================================================
# BANCO - TABELA DE DECISOES
# ============================================================

def preparar_tabela_decisoes(conexao):
    cursor = conexao.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS soc_incident_decisions (
            decision_id TEXT PRIMARY KEY,
            timestamp TEXT,
            evidence_id TEXT,
            ip_origem TEXT,
            evidence_score REAL,
            nivel_evidencia TEXT,
            confianca_evidencia TEXT,
            risk_score_maximo REAL,
            campanha_detectada INTEGER,
            score_campanha REAL,
            status_timeline TEXT,
            variacao_risco REAL,
            prioridade_playbook TEXT,
            mitre_confianca TEXT,
            decision_score REAL,
            prioridade_soc TEXT,
            classificacao_decisao TEXT,
            acao_recomendada TEXT,
            sla_recomendado TEXT,
            requer_analista INTEGER,
            requer_escalacao INTEGER,
            requer_contencao INTEGER,
            auto_block INTEGER,
            motivos TEXT,
            modo_operacional TEXT
        )
        """
    )

    conexao.commit()


def migrar_tabela_decisoes(conexao):
    colunas_necessarias = {
        "decision_id": "TEXT",
        "timestamp": "TEXT",
        "evidence_id": "TEXT",
        "ip_origem": "TEXT",
        "evidence_score": "REAL",
        "nivel_evidencia": "TEXT",
        "confianca_evidencia": "TEXT",
        "risk_score_maximo": "REAL",
        "campanha_detectada": "INTEGER",
        "score_campanha": "REAL",
        "status_timeline": "TEXT",
        "variacao_risco": "REAL",
        "prioridade_playbook": "TEXT",
        "mitre_confianca": "TEXT",
        "decision_score": "REAL",
        "prioridade_soc": "TEXT",
        "classificacao_decisao": "TEXT",
        "acao_recomendada": "TEXT",
        "sla_recomendado": "TEXT",
        "requer_analista": "INTEGER",
        "requer_escalacao": "INTEGER",
        "requer_contencao": "INTEGER",
        "auto_block": "INTEGER",
        "motivos": "TEXT",
        "modo_operacional": "TEXT"
    }

    atuais = obter_colunas(
        conexao,
        TABELA_DECISOES
    )

    cursor = conexao.cursor()
    adicionadas = []

    for coluna, tipo in colunas_necessarias.items():

        if coluna not in atuais:

            cursor.execute(
                f"""
                ALTER TABLE {TABELA_DECISOES}
                ADD COLUMN {coluna} {tipo}
                """
            )

            adicionadas.append(coluna)

    conexao.commit()

    return adicionadas


# ============================================================
# CARREGAMENTO DE EVIDENCIAS
# ============================================================

def carregar_evidencias(conexao):
    cursor = conexao.cursor()

    cursor.execute(
        f"""
        SELECT *
        FROM {TABELA_EVIDENCIAS}
        ORDER BY timestamp ASC
        """
    )

    registros = [
        dict(row)
        for row in cursor.fetchall()
    ]

    return registros


def deduplicar_evidencias(registros):
    """
    A Aula 40 pode ter sido executada mais de uma vez.
    Mantemos a evidencia mais recente de cada IOC para
    evitar que uma execucao antiga gere uma nova decisao.
    """

    indice = {}

    for registro in registros:

        ip = texto(
            primeiro_valor(
                registro,
                ["ip_origem", "ioc", "ip"],
                ""
            ),
            ""
        )

        if not ip:
            continue

        timestamp = texto(
            primeiro_valor(
                registro,
                ["timestamp"],
                ""
            ),
            ""
        )

        atual = indice.get(ip)

        if atual is None:
            indice[ip] = registro
            continue

        timestamp_atual = texto(
            primeiro_valor(
                atual,
                ["timestamp"],
                ""
            ),
            ""
        )

        if timestamp >= timestamp_atual:
            indice[ip] = registro

    return [
        indice[ip]
        for ip in sorted(indice.keys())
    ]


# ============================================================
# NORMALIZACAO DA EVIDENCIA
# ============================================================

def normalizar_evidencia(registro):
    return {
        "evidence_id": texto(
            primeiro_valor(
                registro,
                ["evidence_id"]
            )
        ),

        "ip_origem": texto(
            primeiro_valor(
                registro,
                ["ip_origem", "ioc", "ip"]
            )
        ),

        "evidence_score": valor_float(
            primeiro_valor(
                registro,
                ["evidence_score"],
                0
            )
        ),

        "nivel_evidencia": texto(
            primeiro_valor(
                registro,
                ["nivel_evidencia"],
                "BAIXO"
            ),
            "BAIXO"
        ).upper(),

        "confianca_evidencia": texto(
            primeiro_valor(
                registro,
                ["confianca_evidencia"],
                "BAIXA"
            ),
            "BAIXA"
        ).upper(),

        "risk_score_maximo": valor_float(
            primeiro_valor(
                registro,
                ["risk_score_maximo"],
                0
            )
        ),

        "campanha_detectada": normalizar_booleano(
            primeiro_valor(
                registro,
                ["campanha_detectada"],
                False
            )
        ),

        "score_campanha": valor_float(
            primeiro_valor(
                registro,
                ["score_campanha"],
                0
            )
        ),

        "nivel_campanha": texto(
            primeiro_valor(
                registro,
                ["nivel_campanha"],
                "BAIXO"
            ),
            "BAIXO"
        ).upper(),

        "timeline_id": texto(
            primeiro_valor(
                registro,
                ["timeline_id"]
            )
        ),

        "status_timeline": texto(
            primeiro_valor(
                registro,
                ["status_timeline"],
                "NAO_DISPONIVEL"
            )
        ).upper(),

        "variacao_risco": valor_float(
            primeiro_valor(
                registro,
                ["variacao_risco"],
                0
            )
        ),

        "tendencia_timeline": texto(
            primeiro_valor(
                registro,
                ["tendencia_timeline"],
                "NAO_DISPONIVEL"
            )
        ).upper(),

        "playbook_id": texto(
            primeiro_valor(
                registro,
                ["playbook_id"]
            )
        ),

        "prioridade_playbook": texto(
            primeiro_valor(
                registro,
                ["prioridade_playbook"],
                "BAIXO"
            ),
            "BAIXO"
        ).upper(),

        "acao_recomendada_playbook": texto(
            primeiro_valor(
                registro,
                ["acao_recomendada"],
                "NAO_DISPONIVEL"
            )
        ),

        "mitre_contexto": texto(
            primeiro_valor(
                registro,
                ["mitre_contexto"],
                "NAO_DISPONIVEL"
            )
        ),

        "mitre_tatica": texto(
            primeiro_valor(
                registro,
                ["mitre_tatica"],
                "NAO_ATRIBUIDA"
            )
        ),

        "mitre_technique_id": texto(
            primeiro_valor(
                registro,
                ["mitre_technique_id"],
                "NAO_ATRIBUIDA"
            )
        ),

        "mitre_confianca": texto(
            primeiro_valor(
                registro,
                ["mitre_confianca"],
                "INSUFICIENTE"
            ),
            "INSUFICIENTE"
        ).upper(),

        "fontes_correlacionadas": valor_int(
            primeiro_valor(
                registro,
                ["fontes_correlacionadas"],
                0
            )
        )
    }


# ============================================================
# DECISION ENGINE
# ============================================================

def calcular_decision_score(evidencia):
    """
    Decision Score != probabilidade de ataque.

    O score representa a urgencia operacional para o SOC,
    utilizando somente contexto defensivo ja produzido
    pelo pipeline.
    """

    score = 0.0
    motivos = []

    # --------------------------------------------------------
    # EVIDENCE SCORE - MAX 40
    # --------------------------------------------------------

    score += evidencia["evidence_score"] * 0.40

    if evidencia["evidence_score"] >= 80:
        motivos.append("EVIDENCIA_CRITICA")

    elif evidencia["evidence_score"] >= 60:
        motivos.append("EVIDENCIA_ALTA")

    elif evidencia["evidence_score"] >= 40:
        motivos.append("EVIDENCIA_MEDIA")

    else:
        motivos.append("EVIDENCIA_BAIXA")

    # --------------------------------------------------------
    # RISK SCORE HISTORICO - MAX 20
    # --------------------------------------------------------

    score += evidencia["risk_score_maximo"] * 0.20

    if evidencia["risk_score_maximo"] >= 80:
        motivos.append("RISCO_HISTORICO_CRITICO")

    elif evidencia["risk_score_maximo"] >= 60:
        motivos.append("RISCO_HISTORICO_ALTO")

    # --------------------------------------------------------
    # CAMPANHA - MAX 15
    # --------------------------------------------------------

    if evidencia["campanha_detectada"]:

        score += min(
            evidencia["score_campanha"] * 0.15,
            15
        )

        motivos.append("CAMPANHA_DETECTADA")

    # --------------------------------------------------------
    # TIMELINE - MAX 10
    # --------------------------------------------------------

    if (
        evidencia["status_timeline"]
        == "INCIDENTE_CRITICO"
    ):
        score += 7
        motivos.append("TIMELINE_CRITICA")

        if evidencia["variacao_risco"] >= 40:
            score += 3
            motivos.append("ESCALADA_TEMPORAL_FORTE")

        elif evidencia["variacao_risco"] >= 20:
            score += 2
            motivos.append("ESCALADA_TEMPORAL")

    elif evidencia["variacao_risco"] >= 20:
        score += 3
        motivos.append("CRESCIMENTO_TEMPORAL")

    # --------------------------------------------------------
    # PLAYBOOK - MAX 10
    # --------------------------------------------------------

    prioridade_playbook = (
        evidencia["prioridade_playbook"]
    )

    if prioridade_playbook == "CRITICO":
        score += 10
        motivos.append("PLAYBOOK_CRITICO")

    elif prioridade_playbook == "ALTO":
        score += 7
        motivos.append("PLAYBOOK_ALTO")

    elif prioridade_playbook == "MEDIO":
        score += 4
        motivos.append("PLAYBOOK_MEDIO")

    # --------------------------------------------------------
    # CONFIANCA DE EVIDENCIA - MAX 5
    # --------------------------------------------------------

    confianca = evidencia[
        "confianca_evidencia"
    ]

    if confianca == "ALTA":
        score += 5
        motivos.append("CONFIANCA_EVIDENCIA_ALTA")

    elif confianca == "MEDIA":
        score += 3

    elif confianca == "BAIXA":
        score += 1

    return min(
        round(score, 2),
        100.0
    ), motivos


def classificar_decisao(score):
    if score >= 80:
        return {
            "prioridade": "CRITICO",
            "classificacao": "INCIDENTE_PRIORITARIO",
            "acao": "ESCALAR_E_PREPARAR_CONTENCAO",
            "sla": "IMEDIATO",
            "requer_analista": True,
            "requer_escalacao": True,
            "requer_contencao": True
        }

    if score >= 60:
        return {
            "prioridade": "ALTO",
            "classificacao": "INVESTIGACAO_PRIORITARIA",
            "acao": "ESCALAR_PARA_ANALISTA",
            "sla": "ATE_30_MINUTOS",
            "requer_analista": True,
            "requer_escalacao": True,
            "requer_contencao": False
        }

    if score >= 40:
        return {
            "prioridade": "MEDIO",
            "classificacao": "TRIAGEM_REQUERIDA",
            "acao": "TRIAGEM_SOC",
            "sla": "ATE_2_HORAS",
            "requer_analista": True,
            "requer_escalacao": False,
            "requer_contencao": False
        }

    return {
        "prioridade": "BAIXO",
        "classificacao": "MONITORAMENTO",
        "acao": "MONITORAR_E_REGISTRAR",
        "sla": "ATE_8_HORAS",
        "requer_analista": False,
        "requer_escalacao": False,
        "requer_contencao": False
    }


def gerar_decisao(evidencia):
    decision_score, motivos = (
        calcular_decision_score(
            evidencia
        )
    )

    tratamento = classificar_decisao(
        decision_score
    )

    return {
        "decision_id": gerar_id("DEC-41"),
        "timestamp": agora_iso(),

        "evidence_id": evidencia[
            "evidence_id"
        ],

        "ip_origem": evidencia[
            "ip_origem"
        ],

        "evidence_score": evidencia[
            "evidence_score"
        ],

        "nivel_evidencia": evidencia[
            "nivel_evidencia"
        ],

        "confianca_evidencia": evidencia[
            "confianca_evidencia"
        ],

        "risk_score_maximo": evidencia[
            "risk_score_maximo"
        ],

        "campanha_detectada": evidencia[
            "campanha_detectada"
        ],

        "score_campanha": evidencia[
            "score_campanha"
        ],

        "status_timeline": evidencia[
            "status_timeline"
        ],

        "variacao_risco": evidencia[
            "variacao_risco"
        ],

        "prioridade_playbook": evidencia[
            "prioridade_playbook"
        ],

        "mitre_confianca": evidencia[
            "mitre_confianca"
        ],

        "decision_score": decision_score,

        "prioridade_soc": tratamento[
            "prioridade"
        ],

        "classificacao_decisao": tratamento[
            "classificacao"
        ],

        "acao_recomendada": tratamento[
            "acao"
        ],

        "sla_recomendado": tratamento[
            "sla"
        ],

        "requer_analista": tratamento[
            "requer_analista"
        ],

        "requer_escalacao": tratamento[
            "requer_escalacao"
        ],

        "requer_contencao": tratamento[
            "requer_contencao"
        ],

        # REGRA DE SEGURANCA:
        # nenhuma decisao desta aula executa bloqueio.
        "auto_block": False,

        "motivos": motivos,

        "modo_operacional": "SIMULACAO"
    }


# ============================================================
# PERSISTENCIA
# ============================================================

def persistir_decisao(conexao, decisao):
    cursor = conexao.cursor()

    cursor.execute(
        """
        INSERT OR REPLACE INTO soc_incident_decisions (
            decision_id,
            timestamp,
            evidence_id,
            ip_origem,
            evidence_score,
            nivel_evidencia,
            confianca_evidencia,
            risk_score_maximo,
            campanha_detectada,
            score_campanha,
            status_timeline,
            variacao_risco,
            prioridade_playbook,
            mitre_confianca,
            decision_score,
            prioridade_soc,
            classificacao_decisao,
            acao_recomendada,
            sla_recomendado,
            requer_analista,
            requer_escalacao,
            requer_contencao,
            auto_block,
            motivos,
            modo_operacional
        )
        VALUES (
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
            ?, ?, ?, ?, ?
        )
        """,
        (
            decisao["decision_id"],
            decisao["timestamp"],
            decisao["evidence_id"],
            decisao["ip_origem"],
            decisao["evidence_score"],
            decisao["nivel_evidencia"],
            decisao["confianca_evidencia"],
            decisao["risk_score_maximo"],
            int(decisao["campanha_detectada"]),
            decisao["score_campanha"],
            decisao["status_timeline"],
            decisao["variacao_risco"],
            decisao["prioridade_playbook"],
            decisao["mitre_confianca"],
            decisao["decision_score"],
            decisao["prioridade_soc"],
            decisao["classificacao_decisao"],
            decisao["acao_recomendada"],
            decisao["sla_recomendado"],
            int(decisao["requer_analista"]),
            int(decisao["requer_escalacao"]),
            int(decisao["requer_contencao"]),
            int(decisao["auto_block"]),
            json.dumps(
                decisao["motivos"],
                ensure_ascii=False
            ),
            decisao["modo_operacional"]
        )
    )

    conexao.commit()


# ============================================================
# VALIDACAO CROSS-LAYER
# ============================================================

def validar_decisoes(decisoes):
    validacoes = []

    validacoes.append(
        (
            "Decisoes SOC geradas",
            len(decisoes) > 0
        )
    )

    validacoes.append(
        (
            "Decision Scores entre 0 e 100",
            all(
                0 <= d["decision_score"] <= 100
                for d in decisoes
            )
        )
    )

    validacoes.append(
        (
            "Todas as decisoes possuem IOC",
            all(
                d["ip_origem"]
                and d["ip_origem"]
                != "NAO_DISPONIVEL"
                for d in decisoes
            )
        )
    )

    validacoes.append(
        (
            "Todas as decisoes possuem Evidence ID",
            all(
                d["evidence_id"]
                and d["evidence_id"]
                != "NAO_DISPONIVEL"
                for d in decisoes
            )
        )
    )

    validacoes.append(
        (
            "Nenhum bloqueio automatico habilitado",
            all(
                d["auto_block"] is False
                for d in decisoes
            )
        )
    )

    validacoes.append(
        (
            "Modo operacional permanece SIMULACAO",
            all(
                d["modo_operacional"]
                == "SIMULACAO"
                for d in decisoes
            )
        )
    )

    criticos = [
        d
        for d in decisoes
        if d["prioridade_soc"] == "CRITICO"
    ]

    validacoes.append(
        (
            "Decisoes criticas exigem analista",
            all(
                d["requer_analista"]
                for d in criticos
            )
        )
    )

    validacoes.append(
        (
            "Decisoes criticas exigem escalacao",
            all(
                d["requer_escalacao"]
                for d in criticos
            )
        )
    )

    validacoes.append(
        (
            "Decisoes criticas preparam contencao",
            all(
                d["requer_contencao"]
                for d in criticos
            )
        )
    )

    return validacoes


# ============================================================
# MAIN
# ============================================================

def main():

    titulo(
        "AULA 41 - SOC INCIDENT DECISION ENGINE"
    )

    print("CyberSentinel-ML")
    print(
        "Evidence Correlation + "
        "Decision Support + SOC Prioritization"
    )
    print()
    print("Objetivo:")
    print(
        "Transformar evidencias correlacionadas em "
        "decisoes estruturadas para o SOC."
    )
    print()
    print("IMPORTANTE:")
    print(
        "Decision Score nao representa probabilidade de ataque."
    )
    print(
        "Ele representa urgencia operacional para tratamento."
    )
    print(
        "Nenhum bloqueio automatico sera executado."
    )
    print(
        "Todas as decisoes permanecem em modo SIMULACAO."
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
        (DECISOES_DIR, "decisoes"),
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
    print(
        f"Banco: {DB_PATH.relative_to(BASE_DIR)}"
    )

    validacoes.append(
        (
            "Banco SQLite encontrado",
            True
        )
    )

    conexao = sqlite3.connect(
        DB_PATH
    )

    conexao.row_factory = sqlite3.Row

    # ========================================================
    # ETAPA 3
    # ========================================================

    titulo(
        "ETAPA 3 - VALIDANDO AULA 40"
    )

    evidencia_existe = tabela_existe(
        conexao,
        TABELA_EVIDENCIAS
    )

    if evidencia_existe:
        ok(
            "Tabela incident_evidence encontrada"
        )
    else:
        erro(
            "Tabela incident_evidence nao encontrada"
        )
        conexao.close()
        return

    colunas_evidencia = obter_colunas(
        conexao,
        TABELA_EVIDENCIAS
    )

    ok(
        f"Colunas incident_evidence: "
        f"{len(colunas_evidencia)}"
    )

    colunas_criticas = [
        "evidence_id",
        "ip_origem",
        "evidence_score",
        "nivel_evidencia",
        "confianca_evidencia",
        "risk_score_maximo",
        "campanha_detectada",
        "score_campanha",
        "status_timeline",
        "variacao_risco",
        "prioridade_playbook",
        "mitre_confianca"
    ]

    schema_ok = True

    for coluna in colunas_criticas:

        if coluna in colunas_evidencia:
            ok(
                f"Coluna encontrada: {coluna}"
            )
        else:
            erro(
                f"Coluna ausente: {coluna}"
            )
            schema_ok = False

    validacoes.append(
        (
            "Tabela incident_evidence disponivel",
            evidencia_existe
        )
    )

    validacoes.append(
        (
            "Schema Aula 40 compativel",
            schema_ok
        )
    )

    if not schema_ok:
        conexao.close()
        return

    # ========================================================
    # ETAPA 4
    # ========================================================

    titulo(
        "ETAPA 4 - PREPARANDO DECISION ENGINE"
    )

    preparar_tabela_decisoes(
        conexao
    )

    ok(
        "Tabela soc_incident_decisions pronta"
    )

    adicionadas = migrar_tabela_decisoes(
        conexao
    )

    if adicionadas:
        ok(
            "Schema de decisoes atualizado"
        )
        print(
            "Colunas adicionadas: "
            + ", ".join(adicionadas)
        )
    else:
        ok(
            "Schema de decisoes compativel"
        )

    colunas_decisoes = obter_colunas(
        conexao,
        TABELA_DECISOES
    )

    ok(
        f"Colunas soc_incident_decisions: "
        f"{len(colunas_decisoes)}"
    )

    validacoes.append(
        (
            "Tabela de decisoes disponivel",
            tabela_existe(
                conexao,
                TABELA_DECISOES
            )
        )
    )

    # ========================================================
    # ETAPA 5
    # ========================================================

    titulo(
        "ETAPA 5 - CARREGANDO INCIDENT EVIDENCE"
    )

    evidencias_brutas = carregar_evidencias(
        conexao
    )

    ok(
        f"Evidencias historicas carregadas: "
        f"{len(evidencias_brutas)}"
    )

    evidencias_recentes = (
        deduplicar_evidencias(
            evidencias_brutas
        )
    )

    ok(
        "Evidencias deduplicadas por IOC: "
        f"{len(evidencias_recentes)}"
    )

    evidencias = [
        normalizar_evidencia(registro)
        for registro in evidencias_recentes
    ]

    for evidencia in evidencias:
        print(
            f"- {evidencia['ip_origem']} | "
            f"Evidence Score: "
            f"{evidencia['evidence_score']:.2f} | "
            f"{evidencia['nivel_evidencia']}"
        )

    validacoes.append(
        (
            "Evidencias carregadas",
            len(evidencias) > 0
        )
    )

    validacoes.append(
        (
            "Evidencias deduplicadas",
            len(evidencias)
            <= len(evidencias_brutas)
        )
    )

    # ========================================================
    # ETAPA 6
    # ========================================================

    titulo(
        "ETAPA 6 - EXECUTANDO SOC DECISION ENGINE"
    )

    decisoes = []
    alertas_soc = []

    for indice, evidencia in enumerate(
        evidencias,
        start=1
    ):

        separador()

        print(
            f"INCIDENTE {indice}/{len(evidencias)}"
        )

        separador()

        print(
            f"Evidence ID: "
            f"{evidencia['evidence_id']}"
        )

        print(
            f"IOC: {evidencia['ip_origem']}"
        )

        print()
        print("CONTEXTO:")

        print(
            f"Evidence Score: "
            f"{evidencia['evidence_score']:.2f}/100"
        )

        print(
            f"Nivel evidencia: "
            f"{evidencia['nivel_evidencia']}"
        )

        print(
            f"Confianca evidencia: "
            f"{evidencia['confianca_evidencia']}"
        )

        print(
            f"Risk Score maximo: "
            f"{evidencia['risk_score_maximo']:.2f}/100"
        )

        print(
            "Campanha detectada: "
            + (
                "SIM"
                if evidencia[
                    "campanha_detectada"
                ]
                else "NAO"
            )
        )

        print(
            f"Campaign Score: "
            f"{evidencia['score_campanha']:.2f}/100"
        )

        print(
            f"Timeline: "
            f"{evidencia['status_timeline']}"
        )

        print(
            f"Variacao temporal: "
            f"{evidencia['variacao_risco']:+.2f}"
        )

        print(
            f"Playbook: "
            f"{evidencia['prioridade_playbook']}"
        )

        print(
            f"MITRE confidence: "
            f"{evidencia['mitre_confianca']}"
        )

        decisao = gerar_decisao(
            evidencia
        )

        persistir_decisao(
            conexao,
            decisao
        )

        decisoes.append(
            decisao
        )

        print()
        print("SOC DECISION:")

        print(
            f"Decision Score: "
            f"{decisao['decision_score']:.2f}/100"
        )

        print(
            f"Prioridade SOC: "
            f"{decisao['prioridade_soc']}"
        )

        print(
            f"Classificacao: "
            f"{decisao['classificacao_decisao']}"
        )

        print(
            f"Acao recomendada: "
            f"{decisao['acao_recomendada']}"
        )

        print(
            f"SLA recomendado: "
            f"{decisao['sla_recomendado']}"
        )

        print(
            "Requer analista: "
            + (
                "SIM"
                if decisao["requer_analista"]
                else "NAO"
            )
        )

        print(
            "Requer escalacao: "
            + (
                "SIM"
                if decisao["requer_escalacao"]
                else "NAO"
            )
        )

        print(
            "Preparar contencao: "
            + (
                "SIM"
                if decisao["requer_contencao"]
                else "NAO"
            )
        )

        print(
            "Bloqueio automatico: NAO"
        )

        print(
            f"Modo: "
            f"{decisao['modo_operacional']}"
        )

        print(
            f"Motivos: "
            f"{decisao['motivos']}"
        )

        ok(
            f"Decisao: "
            f"{decisao['decision_id']}"
        )

        if decisao[
            "prioridade_soc"
        ] in {
            "ALTO",
            "CRITICO"
        }:

            alerta_id = gerar_id(
                "DEC-ALT-41"
            )

            alerta_soc = {
                "alerta_id": alerta_id,
                "timestamp": agora_iso(),
                "decision_id": decisao[
                    "decision_id"
                ],
                "evidence_id": decisao[
                    "evidence_id"
                ],
                "ip_origem": decisao[
                    "ip_origem"
                ],
                "decision_score": decisao[
                    "decision_score"
                ],
                "prioridade": decisao[
                    "prioridade_soc"
                ],
                "classificacao": decisao[
                    "classificacao_decisao"
                ],
                "acao_recomendada": decisao[
                    "acao_recomendada"
                ],
                "modo": "SIMULACAO"
            }

            alertas_soc.append(
                alerta_soc
            )

            alerta(
                "Decisao SOC requer priorizacao"
            )

            ok(
                f"Alerta SOC: {alerta_id}"
            )

        else:
            ok(
                "Decisao registrada sem "
                "escalacao critica"
            )

    # ========================================================
    # ETAPA 7
    # ========================================================

    titulo(
        "ETAPA 7 - ANALISANDO FILA DE PRIORIZACAO"
    )

    fila = sorted(
        decisoes,
        key=lambda d: (
            nivel_para_numero(
                d["prioridade_soc"]
            ),
            d["decision_score"]
        ),
        reverse=True
    )

    print(
        f"Decisoes na fila: {len(fila)}"
    )
    print()

    for posicao, decisao in enumerate(
        fila,
        start=1
    ):

        print(
            f"{posicao:02d} | "
            f"{decisao['ip_origem']} | "
            f"{decisao['prioridade_soc']} | "
            f"Decision Score "
            f"{decisao['decision_score']:.2f}"
        )

    # ========================================================
    # ETAPA 8
    # ========================================================

    titulo(
        "ETAPA 8 - VALIDANDO SEGURANCA E CONSISTENCIA"
    )

    validacoes_decisoes = (
        validar_decisoes(
            decisoes
        )
    )

    for nome, resultado in (
        validacoes_decisoes
    ):

        if resultado:
            ok(nome)
        else:
            erro(nome)

        validacoes.append(
            (nome, resultado)
        )

    # ========================================================
    # ETAPA 9
    # ========================================================

    titulo(
        "ETAPA 9 - PERSISTINDO RESULTADOS"
    )

    salvar_json(
        ARQUIVO_DECISOES,
        decisoes
    )

    ok(
        "Decisoes SOC salvas"
    )

    print(
        "Arquivo: "
        f"{ARQUIVO_DECISOES.relative_to(BASE_DIR)}"
    )

    salvar_json(
        ARQUIVO_ALERTAS,
        alertas_soc
    )

    ok(
        "Alertas Decision Engine salvos"
    )

    print(
        "Arquivo: "
        f"{ARQUIVO_ALERTAS.relative_to(BASE_DIR)}"
    )

    validacoes.append(
        (
            "Arquivo de decisoes criado",
            ARQUIVO_DECISOES.exists()
        )
    )

    validacoes.append(
        (
            "Arquivo de alertas criado",
            ARQUIVO_ALERTAS.exists()
        )
    )

    # ========================================================
    # ETAPA 10
    # ========================================================

    titulo(
        "ETAPA 10 - VALIDACAO FINAL"
    )

    validacoes_extras = [
        (
            "Todos os IOCs possuem decisao",
            len(decisoes)
            == len(evidencias)
            and len(evidencias) > 0
        ),

        (
            "Fila SOC criada",
            len(fila)
            == len(decisoes)
        ),

        (
            "Decision Score calculado",
            all(
                "decision_score" in d
                for d in decisoes
            )
        ),

        (
            "Prioridade SOC calculada",
            all(
                d["prioridade_soc"]
                in {
                    "BAIXO",
                    "MEDIO",
                    "ALTO",
                    "CRITICO"
                }
                for d in decisoes
            )
        ),

        (
            "SLA recomendado calculado",
            all(
                d["sla_recomendado"]
                != "NAO_DISPONIVEL"
                for d in decisoes
            )
        ),

        (
            "Analise humana preservada",
            all(
                not d["auto_block"]
                for d in decisoes
            )
        )
    ]

    for nome, resultado in validacoes_extras:
        validacoes.append(
            (nome, resultado)
        )

    # Remover validacoes duplicadas
    validacoes_unicas = []
    nomes_vistos = set()

    for nome, resultado in validacoes:

        if nome in nomes_vistos:
            continue

        nomes_vistos.add(nome)

        validacoes_unicas.append(
            (nome, resultado)
        )

    for nome, resultado in validacoes_unicas:

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
    # ESTATISTICAS
    # ========================================================

    distribuicao = {
        "BAIXO": 0,
        "MEDIO": 0,
        "ALTO": 0,
        "CRITICO": 0
    }

    for decisao in decisoes:
        distribuicao[
            decisao["prioridade_soc"]
        ] += 1

    requer_analista = sum(
        1
        for d in decisoes
        if d["requer_analista"]
    )

    requer_escalacao = sum(
        1
        for d in decisoes
        if d["requer_escalacao"]
    )

    requer_contencao = sum(
        1
        for d in decisoes
        if d["requer_contencao"]
    )

    # ========================================================
    # RELATORIO
    # ========================================================

    relatorio = {
        "aula": 41,

        "nome": (
            "SOC INCIDENT DECISION ENGINE"
        ),

        "timestamp": agora_iso(),

        "evidencias_historicas": len(
            evidencias_brutas
        ),

        "evidencias_processadas": len(
            evidencias
        ),

        "decisoes_geradas": len(
            decisoes
        ),

        "alertas_soc": len(
            alertas_soc
        ),

        "requer_analista": requer_analista,

        "requer_escalacao": (
            requer_escalacao
        ),

        "requer_contencao": (
            requer_contencao
        ),

        "distribuicao_prioridade": (
            distribuicao
        ),

        "modo_operacional": "SIMULACAO",

        "bloqueio_automatico": False,

        "validacoes": {
            "total": total_validacoes,
            "ok": total_ok,
            "saude": round(
                saude,
                2
            )
        },

        "status": (
            "AULA 41 CONCLUIDA"
            if total_ok
            == total_validacoes
            else
            "AULA 41 COM INCONSISTENCIAS"
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
    # RESUMO FINAL
    # ========================================================

    titulo(
        "RESUMO FINAL DA AULA 41"
    )

    print(
        f"Evidencias historicas: "
        f"{len(evidencias_brutas)}"
    )

    print(
        f"Evidencias processadas: "
        f"{len(evidencias)}"
    )

    print(
        f"Decisoes SOC: "
        f"{len(decisoes)}"
    )

    print(
        f"Alertas SOC: "
        f"{len(alertas_soc)}"
    )

    print()
    print("Distribuicao de prioridade:")

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
        f"Requer analista: "
        f"{requer_analista}"
    )

    print(
        f"Requer escalacao: "
        f"{requer_escalacao}"
    )

    print(
        f"Preparar contencao: "
        f"{requer_contencao}"
    )

    print(
        "Bloqueios automaticos: 0"
    )

    print()

    print(
        f"Validacoes: "
        f"{total_ok}/{total_validacoes}"
    )

    print(
        f"Saude: {saude:.2f}%"
    )

    print(
        "Modo operacional: SIMULACAO"
    )

    if (
        total_ok
        == total_validacoes
    ):
        print(
            "Status: AULA 41 CONCLUIDA"
        )
    else:
        print(
            "Status: "
            "AULA 41 COM INCONSISTENCIAS"
        )

    # ========================================================
    # ARQUITETURA
    # ========================================================

    titulo(
        "ARQUITETURA DA AULA 41"
    )

    print(
        r"""
              CYBERSENTINEL-ML
                     |
                     v
             INCIDENT EVIDENCE
                  AULA 40
                     |
          +----------+----------+
          |          |          |
          v          v          v
      EVIDENCE     RISK      CAMPANHA
       SCORE       SCORE       SCORE
          |          |          |
          +----------+----------+
                     |
          +----------+----------+
          |                     |
          v                     v
       TIMELINE             PLAYBOOK
          |                     |
          +----------+----------+
                     |
                     v
                MITRE CONTEXT
                     |
                     v
           SOC DECISION ENGINE
                     |
          +----------+----------+
          |          |          |
          v          v          v
      URGENCIA   PRIORIDADE    SLA
          |          |          |
          +----------+----------+
                     |
                     v
              DECISION SCORE
                  0 - 100
                     |
        +------------+------------+
        |            |            |
        v            v            v
      BAIXO        MEDIO        ALTO
        |            |            |
        |            |            |
        +------------+------------+
                     |
                     v
                  CRITICO
                     |
                     v
             FILA PRIORIZADA SOC
                     |
          +----------+----------+
          |          |          |
          v          v          v
       TRIAGEM   ESCALACAO   PREPARAR
                            CONTENCAO
                     |
                     v
              ANALISE HUMANA
                     |
                     v
             DECISAO OPERACIONAL


IMPORTANTE:

Decision Score != probabilidade de ataque.

Decision Score mede urgencia operacional
com base no contexto correlacionado.

PREPARAR CONTENCAO != EXECUTAR CONTENCAO.

Nenhum IP e bloqueado automaticamente.

Nenhuma regra de firewall e alterada.

Nenhuma acao destrutiva e executada.

O analista humano permanece no fluxo.

Modo operacional: SIMULACAO.
"""
    )

    linha()
    print("CYBERSENTINEL-ML")
    linha()
    print(
        "AULA 41 - SOC INCIDENT DECISION ENGINE"
    )

    if (
        total_ok
        == total_validacoes
    ):
        print(
            "AULA 41 CONCLUIDA"
        )
    else:
        print(
            "AULA 41 COM INCONSISTENCIAS"
        )

    conexao.close()


# ============================================================
# EXECUCAO
# ============================================================

if __name__ == "__main__":
    main()