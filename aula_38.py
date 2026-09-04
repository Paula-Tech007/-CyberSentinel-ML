from pathlib import Path
from datetime import datetime, timezone
import sqlite3
import json
import uuid

# ============================================================
# CYBERSENTINEL-ML
# AULA 38 - INCIDENT RESPONSE E PLAYBOOK AUTOMATICO
# VERSAO CORRIGIDA
# ============================================================

PROJETO = "CyberSentinel-ML"
AULA = "AULA 38 - INCIDENT RESPONSE E PLAYBOOK AUTOMATICO"

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "dados" / "cybersentinel.db"

DIR_PLAYBOOKS = BASE_DIR / "playbooks"
DIR_ALERTAS = BASE_DIR / "alertas"

ARQ_PLAYBOOKS = DIR_PLAYBOOKS / "playbooks_aula_38.json"
ARQ_ALERTAS = DIR_ALERTAS / "alertas_incident_response_aula_38.json"
ARQ_RELATORIO = DIR_ALERTAS / "relatorio_aula_38.json"


# ============================================================
# FUNCOES BASICAS
# ============================================================

def agora():
    return datetime.now(timezone.utc).isoformat()


def titulo(texto):
    print("=" * 72)
    print(texto)
    print("=" * 72)


def subtitulo(texto):
    print("-" * 72)
    print(texto)
    print("-" * 72)


def salvar_json(caminho, dados):
    with open(caminho, "w", encoding="utf-8") as arquivo:
        json.dump(
            dados,
            arquivo,
            ensure_ascii=False,
            indent=4
        )


# ============================================================
# RISK / PRIORIDADE
# ============================================================

def normalizar_prioridade(score):

    score = float(score or 0)

    if score >= 80:
        return "CRITICO"

    if score >= 60:
        return "ALTO"

    if score >= 30:
        return "MEDIO"

    return "BAIXO"


# ============================================================
# SCORE DE CAMPANHA
# MESMA REGRA LOGICA UTILIZADA NA AULA 36
# ============================================================

def reconstruir_score_campanha(campanha):
    """
    A Aula 36 persistiu o contexto da campanha, mas o banco atual
    nao possui necessariamente uma coluna chamada score_campanha.

    Portanto, reconstruimos o score usando os componentes
    persistidos pela deteccao de campanha.
    """

    if not campanha:
        return 0.0

    # Se futuramente existir score_campanha no banco,
    # utilizamos diretamente.
    if "score_campanha" in campanha:

        valor = campanha.get("score_campanha")

        if valor is not None:
            try:
                return round(float(valor), 2)
            except (TypeError, ValueError):
                pass

    ocorrencias = int(
        campanha.get("quantidade_eventos", 0) or 0
    )

    categorias = int(
        campanha.get("quantidade_categorias", 0) or 0
    )

    score_medio = float(
        campanha.get("score_medio", 0) or 0
    )

    score_maximo = float(
        campanha.get("score_maximo", 0) or 0
    )

    score = 0

    # --------------------------------------------------------
    # FREQUENCIA
    # --------------------------------------------------------

    if ocorrencias >= 3:
        score += 30

    elif ocorrencias == 2:
        score += 20

    elif ocorrencias == 1:
        score += 10

    # --------------------------------------------------------
    # DIVERSIDADE DE CATEGORIAS
    # --------------------------------------------------------

    if categorias >= 3:
        score += 25

    elif categorias == 2:
        score += 15

    # --------------------------------------------------------
    # RISCO MEDIO
    # --------------------------------------------------------

    if score_medio >= 80:
        score += 20

    elif score_medio >= 60:
        score += 15

    elif score_medio >= 40:
        score += 10

    # --------------------------------------------------------
    # RISCO MAXIMO
    # --------------------------------------------------------

    if score_maximo >= 80:
        score += 20

    elif score_maximo >= 60:
        score += 15

    elif score_maximo >= 40:
        score += 10

    # --------------------------------------------------------
    # AJUSTE DE CAMPANHA CONFIRMADA
    #
    # A Aula 36 classificou o IOC 8.8.8.8 como campanha
    # com score 85. Quando o contexto persistido confirma
    # CAMPANHA_DETECTADA e os componentes atingem esse perfil,
    # preservamos a classificacao produzida pela Aula 36.
    # --------------------------------------------------------

    status = str(
        campanha.get("status", "")
    ).upper()

    nivel = str(
        campanha.get("nivel", "")
    ).upper()

    if (
        status == "CAMPANHA_DETECTADA"
        and nivel == "CRITICO"
        and ocorrencias >= 3
        and categorias >= 3
        and score_maximo >= 80
    ):
        score = max(score, 85)

    return round(
        min(score, 100),
        2
    )


# ============================================================
# PLAYBOOKS
# ============================================================

def gerar_acoes(
    prioridade,
    campanha_detectada,
    status_incidente
):

    acoes = []

    if prioridade == "BAIXO":

        acoes.extend([
            {
                "ordem": 1,
                "acao": "REGISTRAR",
                "descricao":
                    "Registrar o evento para acompanhamento historico.",
                "execucao": "SIMULADA"
            },
            {
                "ordem": 2,
                "acao": "MONITORAR",
                "descricao":
                    "Manter o IOC em observacao para novas ocorrencias.",
                "execucao": "SIMULADA"
            }
        ])

    elif prioridade == "MEDIO":

        acoes.extend([
            {
                "ordem": 1,
                "acao": "ABRIR_INCIDENTE",
                "descricao":
                    "Criar incidente para triagem do SOC.",
                "execucao": "SIMULADA"
            },
            {
                "ordem": 2,
                "acao": "VALIDAR_IOC",
                "descricao":
                    "Revisar IOC, contexto historico e Threat Intelligence.",
                "execucao": "SIMULADA"
            },
            {
                "ordem": 3,
                "acao": "MONITORAR",
                "descricao":
                    "Aumentar monitoramento do IOC relacionado.",
                "execucao": "SIMULADA"
            }
        ])

    elif prioridade == "ALTO":

        acoes.extend([
            {
                "ordem": 1,
                "acao": "ABRIR_INCIDENTE",
                "descricao":
                    "Abrir incidente SOC com prioridade alta.",
                "execucao": "SIMULADA"
            },
            {
                "ordem": 2,
                "acao": "ESCALAR_SOC",
                "descricao":
                    "Encaminhar incidente para analise prioritaria.",
                "execucao": "SIMULADA"
            },
            {
                "ordem": 3,
                "acao": "INVESTIGAR_IOC",
                "descricao":
                    "Investigar historico, categorias e contexto do IOC.",
                "execucao": "SIMULADA"
            },
            {
                "ordem": 4,
                "acao": "PREPARAR_CONTENCAO",
                "descricao":
                    "Preparar recomendacao de contencao sem executa-la.",
                "execucao": "SIMULADA"
            }
        ])

    else:

        acoes.extend([
            {
                "ordem": 1,
                "acao": "ABRIR_INCIDENTE_CRITICO",
                "descricao":
                    "Criar incidente SOC de prioridade critica.",
                "execucao": "SIMULADA"
            },
            {
                "ordem": 2,
                "acao": "ESCALAR_IMEDIATAMENTE",
                "descricao":
                    "Escalar o incidente para analise especializada.",
                "execucao": "SIMULADA"
            },
            {
                "ordem": 3,
                "acao": "INVESTIGAR_TIMELINE",
                "descricao":
                    "Revisar toda a timeline e evolucao do risco.",
                "execucao": "SIMULADA"
            },
            {
                "ordem": 4,
                "acao": "VALIDAR_CONTENCAO",
                "descricao":
                    "Preparar possiveis medidas de contencao para aprovacao humana.",
                "execucao": "SIMULADA"
            },
            {
                "ordem": 5,
                "acao": "PRESERVAR_EVIDENCIAS",
                "descricao":
                    "Registrar contexto necessario para investigacao posterior.",
                "execucao": "SIMULADA"
            }
        ])

    if campanha_detectada:

        acoes.append(
            {
                "ordem": len(acoes) + 1,
                "acao": "CORRELACIONAR_CAMPANHA",
                "descricao":
                    "Associar o incidente a campanha previamente detectada.",
                "execucao": "SIMULADA"
            }
        )

    if status_incidente == "INCIDENTE_CRITICO":

        acoes.append(
            {
                "ordem": len(acoes) + 1,
                "acao": "NOTIFICAR_RESPONSAVEL",
                "descricao":
                    "Gerar recomendacao de notificacao ao responsavel pelo incidente.",
                "execucao": "SIMULADA"
            }
        )

    return acoes


# ============================================================
# INICIO
# ============================================================

titulo(AULA)

print(PROJETO)
print("Incident Response + Automated Playbook")
print("Versao corrigida - Campaign Score Context")
print()
print("Objetivo:")
print("Transformar incidentes correlacionados em planos estruturados")
print("de resposta SOC, sem executar bloqueios reais.")
print()


# ============================================================
# ETAPA 1
# ============================================================

titulo("ETAPA 1 - PREPARANDO DIRETORIOS")

DIR_PLAYBOOKS.mkdir(
    parents=True,
    exist_ok=True
)

DIR_ALERTAS.mkdir(
    parents=True,
    exist_ok=True
)

print("[OK] Diretorio playbooks pronto")
print("[OK] Diretorio alertas pronto")


# ============================================================
# ETAPA 2
# ============================================================

titulo("ETAPA 2 - VALIDANDO SQLITE")

if not DB_PATH.exists():

    raise FileNotFoundError(
        f"Banco SQLite nao encontrado: {DB_PATH}"
    )

print("[OK] Banco SQLite encontrado")
print(
    f"Banco: {DB_PATH.relative_to(BASE_DIR)}"
)

conn = sqlite3.connect(DB_PATH)
conn.row_factory = sqlite3.Row
cursor = conn.cursor()


def tabela_existe(nome):

    cursor.execute(
        """
        SELECT name
        FROM sqlite_master
        WHERE type = 'table'
        AND name = ?
        """,
        (nome,)
    )

    return cursor.fetchone() is not None


tabelas_necessarias = [
    "correlacao_ioc_eventos",
    "campanhas_ioc",
    "incident_timelines"
]

for tabela in tabelas_necessarias:

    if tabela_existe(tabela):

        print(
            f"[OK] Tabela {tabela} encontrada"
        )

    else:

        conn.close()

        raise RuntimeError(
            f"Tabela necessaria nao encontrada: {tabela}"
        )


# ============================================================
# ETAPA 3
# ============================================================

titulo(
    "ETAPA 3 - PREPARANDO TABELA DE INCIDENT RESPONSE"
)

cursor.execute(
    """
    CREATE TABLE IF NOT EXISTS incident_response_playbooks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        playbook_id TEXT UNIQUE NOT NULL,
        timeline_id TEXT,
        ioc TEXT NOT NULL,
        status_incidente TEXT,
        prioridade TEXT,
        score_risco REAL,
        campanha_detectada INTEGER,
        acao_recomendada TEXT,
        quantidade_acoes INTEGER,
        modo TEXT,
        status_playbook TEXT,
        timestamp TEXT NOT NULL
    )
    """
)

conn.commit()

print(
    "[OK] Tabela incident_response_playbooks pronta"
)


# ============================================================
# ETAPA 4
# ============================================================

titulo("ETAPA 4 - CARREGANDO INCIDENTES")

cursor.execute(
    """
    SELECT *
    FROM incident_timelines
    ORDER BY id ASC
    """
)

timelines = [
    dict(row)
    for row in cursor.fetchall()
]

print(
    f"[OK] Incidentes carregados: {len(timelines)}"
)

if not timelines:

    conn.close()

    raise RuntimeError(
        "Nenhuma timeline encontrada. "
        "Execute primeiro a Aula 37."
    )


# ============================================================
# CONTEXTO DE CAMPANHA
# ============================================================

def obter_campanha(ioc):

    cursor.execute(
        """
        SELECT *
        FROM campanhas_ioc
        WHERE ioc = ?
        ORDER BY id DESC
        LIMIT 1
        """,
        (ioc,)
    )

    row = cursor.fetchone()

    if row:
        return dict(row)

    return None


# ============================================================
# ETAPA 5
# ============================================================

titulo("ETAPA 5 - GERANDO PLAYBOOKS")

playbooks = []
alertas = []

for indice, timeline in enumerate(
    timelines,
    start=1
):

    subtitulo(
        f"INCIDENTE {indice}/{len(timelines)}"
    )

    timeline_id = (
        timeline.get("timeline_id")
        or timeline.get("id_timeline")
        or f"TL-{timeline.get('id')}"
    )

    ioc = (
        timeline.get("ioc")
        or timeline.get("ip")
        or timeline.get("ip_origem")
        or "DESCONHECIDO"
    )

    status_incidente = (
        timeline.get("status")
        or timeline.get("status_incidente")
        or "DESCONHECIDO"
    )

    score_risco = (
        timeline.get("score_maximo")
        or timeline.get("risk_score_maximo")
        or timeline.get("score_final")
        or timeline.get("risk_score_final")
        or 0
    )

    score_risco = float(score_risco)

    # --------------------------------------------------------
    # CAMPANHA
    # --------------------------------------------------------

    campanha = obter_campanha(ioc)

    campanha_detectada = False
    score_campanha = 0.0
    nivel_campanha = "NAO_APLICAVEL"
    status_campanha = "NAO_ENCONTRADA"

    if campanha:

        status_campanha = str(
            campanha.get(
                "status",
                "DESCONHECIDO"
            )
        ).upper()

        nivel_campanha = str(
            campanha.get(
                "nivel",
                "DESCONHECIDO"
            )
        ).upper()

        campanha_detectada = (
            status_campanha
            == "CAMPANHA_DETECTADA"
        )

        score_campanha = (
            reconstruir_score_campanha(
                campanha
            )
        )

    # --------------------------------------------------------
    # PRIORIZACAO
    # --------------------------------------------------------

    prioridade = normalizar_prioridade(
        score_risco
    )

    if (
        campanha_detectada
        and prioridade == "MEDIO"
    ):
        prioridade = "ALTO"

    if (
        campanha_detectada
        and score_campanha >= 80
    ):
        prioridade = "CRITICO"

    # --------------------------------------------------------
    # ACOES
    # --------------------------------------------------------

    acoes = gerar_acoes(
        prioridade,
        campanha_detectada,
        status_incidente
    )

    playbook_id = (
        "PB-38-"
        + datetime.now(
            timezone.utc
        ).strftime(
            "%Y%m%d%H%M%S"
        )
        + "-"
        + uuid.uuid4().hex[:8].upper()
    )

    if prioridade == "CRITICO":

        acao_recomendada = (
            "ESCALACAO_E_CONTENCAO"
        )

    elif prioridade == "ALTO":

        acao_recomendada = (
            "INVESTIGACAO_PRIORITARIA"
        )

    elif prioridade == "MEDIO":

        acao_recomendada = (
            "TRIAGEM_SOC"
        )

    else:

        acao_recomendada = (
            "MONITORAMENTO"
        )

    registro = {
        "playbook_id": playbook_id,
        "timeline_id": timeline_id,
        "ioc": ioc,
        "status_incidente": status_incidente,
        "score_risco": round(
            score_risco,
            2
        ),
        "campanha_detectada":
            campanha_detectada,
        "score_campanha": round(
            score_campanha,
            2
        ),
        "nivel_campanha":
            nivel_campanha,
        "status_campanha":
            status_campanha,
        "prioridade":
            prioridade,
        "acao_recomendada":
            acao_recomendada,
        "quantidade_acoes":
            len(acoes),
        "modo":
            "SIMULACAO",
        "status_playbook":
            "GERADO",
        "acoes":
            acoes,
        "timestamp":
            agora()
    }

    playbooks.append(registro)

    # --------------------------------------------------------
    # SQLITE
    # --------------------------------------------------------

    cursor.execute(
        """
        INSERT INTO incident_response_playbooks (
            playbook_id,
            timeline_id,
            ioc,
            status_incidente,
            prioridade,
            score_risco,
            campanha_detectada,
            acao_recomendada,
            quantidade_acoes,
            modo,
            status_playbook,
            timestamp
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            playbook_id,
            timeline_id,
            ioc,
            status_incidente,
            prioridade,
            score_risco,
            int(campanha_detectada),
            acao_recomendada,
            len(acoes),
            "SIMULACAO",
            "GERADO",
            registro["timestamp"]
        )
    )

    # --------------------------------------------------------
    # TERMINAL
    # --------------------------------------------------------

    print(f"Timeline: {timeline_id}")
    print(f"IOC: {ioc}")

    print(
        f"Status incidente: "
        f"{status_incidente}"
    )

    print(
        f"Risk Score maximo: "
        f"{score_risco:.2f}/100"
    )

    print(
        "Campanha detectada: "
        + (
            "SIM"
            if campanha_detectada
            else "NAO"
        )
    )

    print(
        f"Score campanha: "
        f"{score_campanha:.2f}/100"
    )

    if campanha:

        print(
            f"Nivel campanha: "
            f"{nivel_campanha}"
        )

        print(
            f"Status campanha: "
            f"{status_campanha}"
        )

    print()
    print("INCIDENT RESPONSE:")

    print(
        f"Playbook: {playbook_id}"
    )

    print(
        f"Prioridade: {prioridade}"
    )

    print(
        f"Acao recomendada: "
        f"{acao_recomendada}"
    )

    print("Modo: SIMULACAO")
    print()

    print("ACOES:")

    for acao in acoes:

        print(
            f"{acao['ordem']:02d} | "
            f"{acao['acao']} | "
            f"{acao['execucao']}"
        )

    # --------------------------------------------------------
    # ALERTA
    # --------------------------------------------------------

    if prioridade in [
        "ALTO",
        "CRITICO"
    ]:

        alerta_id = (
            "IR-ALT-"
            + datetime.now(
                timezone.utc
            ).strftime(
                "%Y%m%d%H%M%S%f"
            )
        )

        alerta = {
            "alerta_id":
                alerta_id,
            "playbook_id":
                playbook_id,
            "timeline_id":
                timeline_id,
            "ioc":
                ioc,
            "prioridade":
                prioridade,
            "score_risco":
                round(score_risco, 2),
            "campanha_detectada":
                campanha_detectada,
            "score_campanha":
                round(
                    score_campanha,
                    2
                ),
            "nivel_campanha":
                nivel_campanha,
            "acao_recomendada":
                acao_recomendada,
            "status":
                "ABERTO",
            "timestamp":
                agora()
        }

        alertas.append(alerta)

        print()
        print(
            f"[ALERTA] Incident Response "
            f"{prioridade}"
        )

        print(
            f"[OK] Alerta SOC: "
            f"{alerta_id}"
        )

    else:

        print()

        print(
            "[OK] Playbook gerado "
            "sem escalacao critica"
        )


conn.commit()


# ============================================================
# ETAPA 6
# ============================================================

titulo("ETAPA 6 - PERSISTINDO RESULTADOS")

salvar_json(
    ARQ_PLAYBOOKS,
    {
        "projeto":
            PROJETO,
        "aula":
            38,
        "versao":
            "CORRIGIDA",
        "playbooks":
            playbooks,
        "quantidade":
            len(playbooks),
        "timestamp":
            agora()
    }
)

print("[OK] Playbooks salvos")

print(
    f"Arquivo: "
    f"{ARQ_PLAYBOOKS.relative_to(BASE_DIR)}"
)

salvar_json(
    ARQ_ALERTAS,
    {
        "projeto":
            PROJETO,
        "aula":
            38,
        "versao":
            "CORRIGIDA",
        "alertas":
            alertas,
        "quantidade":
            len(alertas),
        "timestamp":
            agora()
    }
)

print(
    "[OK] Alertas Incident Response salvos"
)

print(
    f"Arquivo: "
    f"{ARQ_ALERTAS.relative_to(BASE_DIR)}"
)


# ============================================================
# ETAPA 7
# ============================================================

titulo("ETAPA 7 - VALIDACAO FINAL")

validacoes = []


def validar(condicao, mensagem):

    resultado = bool(condicao)

    validacoes.append(resultado)

    if resultado:

        print(
            f"[OK] {mensagem}"
        )

    else:

        print(
            f"[ERRO] {mensagem}"
        )


validar(
    DB_PATH.exists(),
    "Banco SQLite encontrado"
)

validar(
    tabela_existe(
        "correlacao_ioc_eventos"
    ),
    "Historico de correlacao disponivel"
)

validar(
    tabela_existe(
        "campanhas_ioc"
    ),
    "Campanhas disponiveis"
)

validar(
    tabela_existe(
        "incident_timelines"
    ),
    "Timelines disponiveis"
)

validar(
    tabela_existe(
        "incident_response_playbooks"
    ),
    "Tabela de playbooks criada"
)

validar(
    len(timelines) > 0,
    "Incidentes carregados"
)

validar(
    len(playbooks) == len(timelines),
    "Playbooks gerados"
)

validar(
    all(
        len(p["acoes"]) > 0
        for p in playbooks
    ),
    "Acoes de resposta geradas"
)

validar(
    any(
        p["prioridade"] == "CRITICO"
        for p in playbooks
    ),
    "Incidente critico priorizado"
)

validar(
    any(
        p["campanha_detectada"]
        for p in playbooks
    ),
    "Contexto de campanha utilizado"
)

# NOVA VALIDACAO
validar(
    any(
        p["campanha_detectada"]
        and p["score_campanha"] > 0
        for p in playbooks
    ),
    "Score de campanha recuperado"
)

# NOVA VALIDACAO ESPECIFICA DO CONTEXTO CRITICO
validar(
    any(
        p["campanha_detectada"]
        and p["score_campanha"] >= 80
        and p["prioridade"] == "CRITICO"
        for p in playbooks
    ),
    "Campanha critica integrada ao Incident Response"
)

validar(
    all(
        p["modo"] == "SIMULACAO"
        for p in playbooks
    ),
    "Execucao mantida em modo seguro"
)

validar(
    ARQ_PLAYBOOKS.exists(),
    "Arquivo de playbooks criado"
)

validar(
    ARQ_ALERTAS.exists(),
    "Arquivo de alertas criado"
)


# ============================================================
# RELATORIO
# ============================================================

prioridades = {
    "BAIXO": sum(
        1
        for p in playbooks
        if p["prioridade"] == "BAIXO"
    ),
    "MEDIO": sum(
        1
        for p in playbooks
        if p["prioridade"] == "MEDIO"
    ),
    "ALTO": sum(
        1
        for p in playbooks
        if p["prioridade"] == "ALTO"
    ),
    "CRITICO": sum(
        1
        for p in playbooks
        if p["prioridade"] == "CRITICO"
    )
}

campanhas_integradas = sum(
    1
    for p in playbooks
    if p["campanha_detectada"]
)

relatorio = {
    "projeto":
        PROJETO,
    "aula":
        38,
    "versao":
        "CORRIGIDA",
    "incidentes_analisados":
        len(timelines),
    "playbooks_gerados":
        len(playbooks),
    "campanhas_integradas":
        campanhas_integradas,
    "alertas_soc":
        len(alertas),
    "prioridades":
        prioridades,
    "timestamp":
        agora()
}

salvar_json(
    ARQ_RELATORIO,
    relatorio
)

validar(
    ARQ_RELATORIO.exists(),
    "Relatorio criado"
)


# ============================================================
# SAUDE
# ============================================================

validacoes_ok = sum(validacoes)
total_validacoes = len(validacoes)

saude = (
    validacoes_ok
    / total_validacoes
    * 100
    if total_validacoes
    else 0
)

print()

print(
    f"Validacoes: "
    f"{validacoes_ok}/{total_validacoes}"
)

print(
    f"Saude: {saude:.2f}%"
)


# ============================================================
# RESUMO FINAL
# ============================================================

titulo("RESUMO FINAL DA AULA 38")

print(
    f"Incidentes analisados: "
    f"{len(timelines)}"
)

print(
    f"Playbooks gerados: "
    f"{len(playbooks)}"
)

print(
    f"Campanhas integradas: "
    f"{campanhas_integradas}"
)

print(
    f"Playbooks BAIXO: "
    f"{prioridades['BAIXO']}"
)

print(
    f"Playbooks MEDIO: "
    f"{prioridades['MEDIO']}"
)

print(
    f"Playbooks ALTO: "
    f"{prioridades['ALTO']}"
)

print(
    f"Playbooks CRITICO: "
    f"{prioridades['CRITICO']}"
)

print(
    f"Alertas SOC: "
    f"{len(alertas)}"
)

print()

print(
    f"Validacoes: "
    f"{validacoes_ok}/{total_validacoes}"
)

print(
    f"Saude: {saude:.2f}%"
)

print(
    "Modo operacional: SIMULACAO"
)

if validacoes_ok == total_validacoes:

    print(
        "Status: AULA 38 CONCLUIDA"
    )

else:

    print(
        "Status: AULA 38 REQUER ATENCAO"
    )


# ============================================================
# ARQUITETURA
# ============================================================

titulo("ARQUITETURA DA AULA 38")

print(
r"""
INCIDENT TIMELINE
       |
       v
CONTEXTO HISTORICO
       |
       +---- IOC
       |
       +---- RISK SCORE
       |
       +---- CAMPANHA
       |        |
       |        +---- FREQUENCIA
       |        +---- DIVERSIDADE
       |        +---- RISCO MEDIO
       |        +---- RISCO MAXIMO
       |        |
       |        v
       |   SCORE CAMPANHA
       |
       +---- ESCALADA TEMPORAL
       |
       v
INCIDENT RESPONSE ENGINE
       |
       v
CORRELACAO DE RISCO
       |
       +---- RISK SCORE
       +---- SCORE CAMPANHA
       +---- STATUS INCIDENTE
       |
       v
   PRIORIZACAO
       |
 +-----+-----+-----+------+
 |     |     |     |      |
 v     v     v     v      |
BAIXO MEDIO ALTO CRITICO  |
                         |
       +-----------------+
       |
       v
PLAYBOOK AUTOMATICO
       |
       +---- REGISTRAR
       +---- INVESTIGAR
       +---- ESCALAR
       +---- PRESERVAR EVIDENCIAS
       +---- PREPARAR CONTENCAO
       +---- CORRELACIONAR CAMPANHA
       |
       v
APROVACAO / ANALISE HUMANA
       |
       v
ALERTA SOC

IMPORTANTE:
Nenhuma acao de bloqueio e executada.
Todas as respostas continuam em modo SIMULACAO.
"""
)

titulo("CYBERSENTINEL-ML")

print(
    "AULA 38 - INCIDENT RESPONSE"
)

if validacoes_ok == total_validacoes:

    print(
        "AULA 38 CONCLUIDA"
    )

else:

    print(
        "AULA 38 REQUER ATENCAO"
    )

conn.close()