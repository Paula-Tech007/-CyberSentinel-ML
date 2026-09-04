from pathlib import Path
from datetime import datetime, timezone
import sqlite3
import json


# ============================================================
# CYBERSENTINEL-ML
# AULA 37 - TIMELINE DE INCIDENTE
# ============================================================

BASE_DIR = Path(__file__).resolve().parent
BANCO = BASE_DIR / "dados" / "cybersentinel.db"

DIR_TIMELINES = BASE_DIR / "timelines"
DIR_ALERTAS = BASE_DIR / "alertas"

ARQUIVO_TIMELINES = DIR_TIMELINES / "timelines_aula_37.json"
ARQUIVO_ALERTAS = DIR_ALERTAS / "alertas_timeline_aula_37.json"
ARQUIVO_RELATORIO = DIR_ALERTAS / "relatorio_aula_37.json"


def titulo(texto):
    print("=" * 72)
    print(texto)
    print("=" * 72)


def agora():
    return datetime.now(timezone.utc).isoformat()


def salvar_json(caminho, dados):
    with open(caminho, "w", encoding="utf-8") as arquivo:
        json.dump(
            dados,
            arquivo,
            indent=4,
            ensure_ascii=False
        )


def conectar():
    conexao = sqlite3.connect(BANCO)
    conexao.row_factory = sqlite3.Row
    return conexao


def tabela_existe(conexao, nome):
    cursor = conexao.execute(
        """
        SELECT name
        FROM sqlite_master
        WHERE type = 'table'
        AND name = ?
        """,
        (nome,)
    )

    return cursor.fetchone() is not None


def preparar_tabela(conexao):
    conexao.execute(
        """
        CREATE TABLE IF NOT EXISTS incident_timelines (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timeline_id TEXT UNIQUE NOT NULL,
            ioc TEXT NOT NULL,
            primeiro_evento TEXT,
            ultimo_evento TEXT,
            quantidade_eventos INTEGER,
            quantidade_categorias INTEGER,
            categorias TEXT,
            score_inicial REAL,
            score_final REAL,
            score_maximo REAL,
            tendencia TEXT,
            status TEXT,
            timestamp TEXT
        )
        """
    )

    conexao.commit()


def carregar_eventos(conexao):
    cursor = conexao.execute(
        """
        SELECT *
        FROM correlacao_ioc_eventos
        ORDER BY timestamp ASC
        """
    )

    return [
        dict(linha)
        for linha in cursor.fetchall()
    ]


def campo(registro, nomes, padrao=None):
    for nome in nomes:
        if nome in registro:
            valor = registro[nome]

            if valor is not None:
                return valor

    return padrao


def normalizar(registro):
    ioc = campo(
        registro,
        ["ioc", "ip", "ip_origem", "valor_ioc"],
        "DESCONHECIDO"
    )

    evento = campo(
        registro,
        ["id_evento", "evento_id"],
        "SEM_ID"
    )

    categoria = campo(
        registro,
        ["categoria", "categoria_ataque"],
        "DESCONHECIDA"
    )

    score = campo(
        registro,
        [
            "risk_score_correlacionado",
            "score_correlacionado",
            "risk_score",
            "score",
            "score_final"
        ],
        0.0
    )

    prioridade = campo(
        registro,
        [
            "prioridade_soc",
            "prioridade",
            "severidade"
        ],
        "DESCONHECIDA"
    )

    timestamp = campo(
        registro,
        ["timestamp"],
        agora()
    )

    try:
        score = float(score)
    except (ValueError, TypeError):
        score = 0.0

    return {
        "id_evento": str(evento),
        "ioc": str(ioc),
        "categoria": str(categoria),
        "risk_score": round(score, 2),
        "prioridade": str(prioridade),
        "timestamp": str(timestamp)
    }


def agrupar_eventos(registros):
    grupos = {}

    for registro in registros:
        evento = normalizar(registro)

        grupos.setdefault(
            evento["ioc"],
            []
        ).append(evento)

    for ioc in grupos:
        grupos[ioc] = sorted(
            grupos[ioc],
            key=lambda item: item["timestamp"]
        )

    return grupos


def calcular_tendencia(scores):
    if len(scores) < 2:
        return "SEM_HISTORICO"

    inicial = scores[0]
    final = scores[-1]

    diferenca = final - inicial

    if diferenca >= 20:
        return "FORTE_CRESCIMENTO"

    if diferenca >= 5:
        return "CRESCIMENTO"

    if diferenca <= -20:
        return "FORTE_REDUCAO"

    if diferenca <= -5:
        return "REDUCAO"

    return "ESTAVEL"


def determinar_status(
    quantidade_eventos,
    quantidade_categorias,
    score_maximo,
    tendencia
):
    if (
        quantidade_eventos >= 3
        and quantidade_categorias >= 2
        and score_maximo >= 80
    ):
        return "INCIDENTE_CRITICO"

    if (
        quantidade_eventos >= 2
        and quantidade_categorias >= 2
    ):
        return "INCIDENTE_CORRELACIONADO"

    if tendencia in (
        "FORTE_CRESCIMENTO",
        "CRESCIMENTO"
    ):
        return "ATIVIDADE_EM_ESCALADA"

    return "EVENTO_ISOLADO"


def criar_timelines(grupos):
    timelines = []

    contador = 1

    for ioc, eventos in grupos.items():
        categorias = sorted(
            set(
                evento["categoria"]
                for evento in eventos
                if evento["categoria"] != "DESCONHECIDA"
            )
        )

        scores = [
            evento["risk_score"]
            for evento in eventos
        ]

        score_inicial = scores[0] if scores else 0.0
        score_final = scores[-1] if scores else 0.0
        score_maximo = max(scores) if scores else 0.0

        tendencia = calcular_tendencia(scores)

        status = determinar_status(
            len(eventos),
            len(categorias),
            score_maximo,
            tendencia
        )

        timeline = {
            "timeline_id":
                f"TL-37-{contador:04d}",

            "ioc": ioc,

            "primeiro_evento":
                eventos[0]["timestamp"],

            "ultimo_evento":
                eventos[-1]["timestamp"],

            "quantidade_eventos":
                len(eventos),

            "quantidade_categorias":
                len(categorias),

            "categorias":
                categorias,

            "score_inicial":
                round(score_inicial, 2),

            "score_final":
                round(score_final, 2),

            "score_maximo":
                round(score_maximo, 2),

            "variacao_score":
                round(
                    score_final - score_inicial,
                    2
                ),

            "tendencia":
                tendencia,

            "status":
                status,

            "eventos":
                eventos,

            "timestamp":
                agora()
        }

        timelines.append(timeline)
        contador += 1

    return timelines


def persistir_timeline(conexao, timeline):
    conexao.execute(
        """
        INSERT OR REPLACE INTO incident_timelines (
            timeline_id,
            ioc,
            primeiro_evento,
            ultimo_evento,
            quantidade_eventos,
            quantidade_categorias,
            categorias,
            score_inicial,
            score_final,
            score_maximo,
            tendencia,
            status,
            timestamp
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            timeline["timeline_id"],
            timeline["ioc"],
            timeline["primeiro_evento"],
            timeline["ultimo_evento"],
            timeline["quantidade_eventos"],
            timeline["quantidade_categorias"],
            json.dumps(
                timeline["categorias"],
                ensure_ascii=False
            ),
            timeline["score_inicial"],
            timeline["score_final"],
            timeline["score_maximo"],
            timeline["tendencia"],
            timeline["status"],
            timeline["timestamp"]
        )
    )

    conexao.commit()


def criar_alerta(timeline):
    if timeline["status"] not in (
        "INCIDENTE_CRITICO",
        "INCIDENTE_CORRELACIONADO",
        "ATIVIDADE_EM_ESCALADA"
    ):
        return None

    alerta_id = (
        "TL-ALT-"
        + datetime.now(
            timezone.utc
        ).strftime("%Y%m%d%H%M%S%f")
    )

    severidade = "MEDIO"

    if timeline["status"] == "INCIDENTE_CRITICO":
        severidade = "CRITICO"

    elif timeline["status"] == "INCIDENTE_CORRELACIONADO":
        severidade = "ALTO"

    elif timeline["status"] == "ATIVIDADE_EM_ESCALADA":
        severidade = "ALTO"

    return {
        "alerta_id": alerta_id,
        "timeline_id": timeline["timeline_id"],
        "ioc": timeline["ioc"],
        "tipo": "CORRELACAO_TEMPORAL",
        "status_incidente": timeline["status"],
        "severidade": severidade,
        "quantidade_eventos":
            timeline["quantidade_eventos"],
        "categorias":
            timeline["categorias"],
        "score_inicial":
            timeline["score_inicial"],
        "score_final":
            timeline["score_final"],
        "score_maximo":
            timeline["score_maximo"],
        "tendencia":
            timeline["tendencia"],
        "status": "ABERTO",
        "timestamp": agora()
    }


def main():

    titulo(
        "AULA 37 - TIMELINE DE INCIDENTE E CORRELACAO TEMPORAL"
    )

    print("CyberSentinel-ML")
    print("Incident Timeline + Temporal Correlation")
    print()
    print("Objetivo:")
    print(
        "Reconstruir a sequencia temporal de eventos "
        "correlacionados e identificar escalada de risco."
    )

    # ========================================================
    # ETAPA 1
    # ========================================================

    titulo("ETAPA 1 - PREPARANDO DIRETORIOS")

    DIR_TIMELINES.mkdir(
        parents=True,
        exist_ok=True
    )

    DIR_ALERTAS.mkdir(
        parents=True,
        exist_ok=True
    )

    print("[OK] Diretorio timelines pronto")
    print("[OK] Diretorio alertas pronto")

    # ========================================================
    # ETAPA 2
    # ========================================================

    titulo("ETAPA 2 - VALIDANDO SQLITE")

    if not BANCO.exists():
        print("[ERRO] Banco SQLite nao encontrado")
        print("Execute primeiro as aulas anteriores.")
        return

    print("[OK] Banco SQLite encontrado")
    print(f"Banco: {BANCO.relative_to(BASE_DIR)}")

    conexao = conectar()

    try:

        if not tabela_existe(
            conexao,
            "correlacao_ioc_eventos"
        ):
            print(
                "[ERRO] Tabela correlacao_ioc_eventos "
                "nao encontrada"
            )
            print("Execute primeiro a Aula 35.")
            return

        print(
            "[OK] Tabela correlacao_ioc_eventos encontrada"
        )

        if not tabela_existe(
            conexao,
            "campanhas_ioc"
        ):
            print(
                "[ERRO] Tabela campanhas_ioc "
                "nao encontrada"
            )
            print("Execute primeiro a Aula 36.")
            return

        print("[OK] Tabela campanhas_ioc encontrada")

        # ====================================================
        # ETAPA 3
        # ====================================================

        titulo(
            "ETAPA 3 - PREPARANDO TIMELINE SQLITE"
        )

        preparar_tabela(conexao)

        print("[OK] Tabela incident_timelines pronta")

        # ====================================================
        # ETAPA 4
        # ====================================================

        titulo(
            "ETAPA 4 - CARREGANDO EVENTOS HISTORICOS"
        )

        registros = carregar_eventos(conexao)

        print(
            f"[OK] Eventos carregados: {len(registros)}"
        )

        if not registros:
            print("[ERRO] Historico vazio")
            return

        # ====================================================
        # ETAPA 5
        # ====================================================

        titulo(
            "ETAPA 5 - CONSTRUINDO LINHAS DO TEMPO"
        )

        grupos = agrupar_eventos(registros)

        print(
            f"[OK] Timelines candidatas: {len(grupos)}"
        )

        timelines = criar_timelines(grupos)
        alertas = []

        # ====================================================
        # ETAPA 6
        # ====================================================

        titulo(
            "ETAPA 6 - ANALISANDO CORRELACAO TEMPORAL"
        )

        for indice, timeline in enumerate(
            timelines,
            start=1
        ):
            print()
            print("-" * 72)
            print(
                f"TIMELINE {indice}/{len(timelines)}"
            )
            print("-" * 72)

            print(f"ID: {timeline['timeline_id']}")
            print(f"IOC: {timeline['ioc']}")

            print(
                f"Eventos: "
                f"{timeline['quantidade_eventos']}"
            )

            print(
                f"Categorias: "
                f"{timeline['categorias']}"
            )

            print(
                f"Primeiro evento: "
                f"{timeline['primeiro_evento']}"
            )

            print(
                f"Ultimo evento: "
                f"{timeline['ultimo_evento']}"
            )

            print()
            print("EVOLUCAO DO RISCO:")

            print(
                f"Score inicial: "
                f"{timeline['score_inicial']}/100"
            )

            print(
                f"Score final: "
                f"{timeline['score_final']}/100"
            )

            print(
                f"Score maximo: "
                f"{timeline['score_maximo']}/100"
            )

            variacao = timeline["variacao_score"]

            sinal = "+" if variacao > 0 else ""

            print(
                f"Variacao: "
                f"{sinal}{variacao}"
            )

            print(
                f"Tendencia: "
                f"{timeline['tendencia']}"
            )

            print()
            print(
                f"Status: {timeline['status']}"
            )

            print()
            print("SEQUENCIA:")

            for posicao, evento in enumerate(
                timeline["eventos"],
                start=1
            ):
                print(
                    f"{posicao:02d} | "
                    f"{evento['id_evento']} | "
                    f"{evento['categoria']} | "
                    f"Risk {evento['risk_score']}"
                )

            persistir_timeline(
                conexao,
                timeline
            )

            alerta = criar_alerta(timeline)

            if alerta:
                alertas.append(alerta)

                print()
                print(
                    f"[ALERTA] {timeline['status']}"
                )

                print(
                    f"[OK] Alerta SOC: "
                    f"{alerta['alerta_id']}"
                )

            else:
                print()
                print(
                    "[OK] Nenhuma escalada temporal "
                    "relevante"
                )

        # ====================================================
        # ETAPA 7
        # ====================================================

        titulo(
            "ETAPA 7 - PERSISTINDO RESULTADOS"
        )

        salvar_json(
            ARQUIVO_TIMELINES,
            timelines
        )

        print("[OK] Timelines salvas")
        print(
            "Arquivo: "
            "timelines\\timelines_aula_37.json"
        )

        salvar_json(
            ARQUIVO_ALERTAS,
            alertas
        )

        print("[OK] Alertas temporais salvos")
        print(
            "Arquivo: "
            "alertas\\alertas_timeline_aula_37.json"
        )

        incidentes_criticos = sum(
            1
            for timeline in timelines
            if timeline["status"]
            == "INCIDENTE_CRITICO"
        )

        incidentes_correlacionados = sum(
            1
            for timeline in timelines
            if timeline["status"]
            == "INCIDENTE_CORRELACIONADO"
        )

        escaladas = sum(
            1
            for timeline in timelines
            if timeline["tendencia"] in (
                "CRESCIMENTO",
                "FORTE_CRESCIMENTO"
            )
        )

        relatorio = {
            "projeto": "CyberSentinel-ML",
            "aula": 37,
            "titulo":
                "Timeline de Incidente e "
                "Correlacao Temporal",
            "eventos_historicos":
                len(registros),
            "timelines":
                len(timelines),
            "incidentes_criticos":
                incidentes_criticos,
            "incidentes_correlacionados":
                incidentes_correlacionados,
            "escaladas_detectadas":
                escaladas,
            "alertas_soc":
                len(alertas),
            "timestamp":
                agora()
        }

        salvar_json(
            ARQUIVO_RELATORIO,
            relatorio
        )

        print("[OK] Relatorio salvo")
        print(
            "Arquivo: "
            "alertas\\relatorio_aula_37.json"
        )

        # ====================================================
        # ETAPA 8
        # ====================================================

        titulo("ETAPA 8 - VALIDACAO FINAL")

        validacoes = [
            (
                "Banco SQLite encontrado",
                BANCO.exists()
            ),
            (
                "Historico Aula 35 disponivel",
                tabela_existe(
                    conexao,
                    "correlacao_ioc_eventos"
                )
            ),
            (
                "Campanhas Aula 36 disponiveis",
                tabela_existe(
                    conexao,
                    "campanhas_ioc"
                )
            ),
            (
                "Tabela timeline criada",
                tabela_existe(
                    conexao,
                    "incident_timelines"
                )
            ),
            (
                "Eventos historicos carregados",
                len(registros) > 0
            ),
            (
                "Timelines construidas",
                len(timelines) > 0
            ),
            (
                "IOC reincidente encontrado",
                any(
                    t["quantidade_eventos"] >= 3
                    for t in timelines
                )
            ),
            (
                "Categorias correlacionadas",
                any(
                    t["quantidade_categorias"] >= 2
                    for t in timelines
                )
            ),
            (
                "Evolucao de Risk Score encontrada",
                any(
                    t["score_final"]
                    != t["score_inicial"]
                    for t in timelines
                )
            ),
            (
                "Escalada temporal detectada",
                escaladas > 0
            ),
            (
                "Incidente critico identificado",
                incidentes_criticos > 0
            ),
            (
                "Alerta SOC criado",
                len(alertas) > 0
            ),
            (
                "Arquivo timeline criado",
                ARQUIVO_TIMELINES.exists()
            ),
            (
                "Arquivo alertas criado",
                ARQUIVO_ALERTAS.exists()
            ),
            (
                "Relatorio criado",
                ARQUIVO_RELATORIO.exists()
            )
        ]

        ok = 0

        for descricao, resultado in validacoes:
            if resultado:
                print(f"[OK] {descricao}")
                ok += 1
            else:
                print(f"[ERRO] {descricao}")

        total = len(validacoes)

        saude = (
            ok / total * 100
            if total
            else 0
        )

        print()
        print(f"Validacoes: {ok}/{total}")
        print(f"Saude: {saude:.2f}%")

        # ====================================================
        # RESUMO
        # ====================================================

        titulo("RESUMO FINAL DA AULA 37")

        print(
            f"Eventos historicos: {len(registros)}"
        )

        print(
            f"Timelines construidas: {len(timelines)}"
        )

        print(
            f"Escaladas detectadas: {escaladas}"
        )

        print(
            f"Incidentes criticos: "
            f"{incidentes_criticos}"
        )

        print(
            f"Incidentes correlacionados: "
            f"{incidentes_correlacionados}"
        )

        print(
            f"Alertas SOC: {len(alertas)}"
        )

        print()
        print(f"Validacoes: {ok}/{total}")
        print(f"Saude: {saude:.2f}%")

        if ok == total:
            print("Status: AULA 37 CONCLUIDA")
        else:
            print(
                "Status: AULA 37 REQUER ATENCAO"
            )

        # ====================================================
        # ARQUITETURA
        # ====================================================

        titulo("ARQUITETURA DA AULA 37")

        print(
            """
EVENTOS CORRELACIONADOS
          |
          v
      IOC / IP
          |
          v
ORDENACAO TEMPORAL
          |
          v
   INCIDENT TIMELINE
          |
     +----+----+
     |         |
     v         v
 CATEGORIAS  RISK SCORES
     |         |
     +----+----+
          |
          v
 ANALISE DE EVOLUCAO
          |
     +----+----------------+
     |                     |
     v                     v
  ESTAVEL              ESCALADA
                           |
                           v
                  CORRELACAO TEMPORAL
                           |
                           v
                   INCIDENTE CRITICO
                           |
                           v
                      ALERTA SOC
"""
        )

        titulo("CYBERSENTINEL-ML")

        print(
            "AULA 37 - TIMELINE DE INCIDENTE"
        )

        if ok == total:
            print("AULA 37 CONCLUIDA")
        else:
            print("AULA 37 REQUER ATENCAO")

    finally:
        conexao.close()


if __name__ == "__main__":
    main()