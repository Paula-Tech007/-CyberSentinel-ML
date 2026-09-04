from pathlib import Path
from datetime import datetime, timezone
import sqlite3
import json
import statistics


# ============================================================
# CYBERSENTINEL-ML
# AULA 36 - DETECCAO DE CAMPANHAS POR IOC
# ============================================================

BASE_DIR = Path(__file__).resolve().parent
BANCO = BASE_DIR / "dados" / "cybersentinel.db"
DIR_CAMPANHAS = BASE_DIR / "campanhas"
DIR_ALERTAS = BASE_DIR / "alertas"

ARQUIVO_CAMPANHAS = DIR_CAMPANHAS / "campanhas_aula_36.json"
ARQUIVO_ALERTAS = DIR_ALERTAS / "alertas_campanhas_aula_36.json"
ARQUIVO_RELATORIO = DIR_ALERTAS / "relatorio_aula_36.json"


def titulo(texto):
    print("=" * 72)
    print(texto)
    print("=" * 72)


def agora():
    return datetime.now(timezone.utc).isoformat()


def salvar_json(caminho, dados):
    with open(caminho, "w", encoding="utf-8") as arquivo:
        json.dump(dados, arquivo, indent=4, ensure_ascii=False)


def conectar_banco():
    return sqlite3.connect(BANCO)


def obter_colunas_tabela(conexao, tabela):
    cursor = conexao.cursor()
    cursor.execute(f"PRAGMA table_info({tabela})")
    return [linha[1] for linha in cursor.fetchall()]


def tabela_existe(conexao, tabela):
    cursor = conexao.cursor()
    cursor.execute(
        """
        SELECT name
        FROM sqlite_master
        WHERE type = 'table'
        AND name = ?
        """,
        (tabela,),
    )
    return cursor.fetchone() is not None


def preparar_tabela_campanhas(conexao):
    cursor = conexao.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS campanhas_ioc (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            campanha_id TEXT NOT NULL UNIQUE,
            ioc TEXT NOT NULL,
            quantidade_eventos INTEGER NOT NULL,
            quantidade_categorias INTEGER NOT NULL,
            categorias TEXT,
            score_medio REAL,
            score_maximo REAL,
            nivel TEXT,
            status TEXT,
            timestamp TEXT NOT NULL
        )
        """
    )

    conexao.commit()


def carregar_historico_aula_35(conexao):
    if not tabela_existe(conexao, "correlacao_ioc_eventos"):
        raise RuntimeError(
            "Tabela correlacao_ioc_eventos nao encontrada. "
            "Execute a Aula 35 antes da Aula 36."
        )

    colunas = obter_colunas_tabela(
        conexao,
        "correlacao_ioc_eventos"
    )

    print("[OK] Tabela correlacao_ioc_eventos encontrada")
    print(f"[OK] Colunas detectadas: {len(colunas)}")

    cursor = conexao.cursor()
    cursor.execute("SELECT * FROM correlacao_ioc_eventos")

    nomes = [descricao[0] for descricao in cursor.description]

    registros = []

    for linha in cursor.fetchall():
        registros.append(dict(zip(nomes, linha)))

    return registros, colunas


def localizar_campo(registro, candidatos, padrao=None):
    for campo in candidatos:
        if campo in registro and registro[campo] is not None:
            return registro[campo]

    return padrao


def normalizar_registro(registro):
    ioc = localizar_campo(
        registro,
        ["ioc", "ip", "ip_origem", "valor_ioc"],
        "DESCONHECIDO",
    )

    categoria = localizar_campo(
        registro,
        ["categoria", "categoria_ataque"],
        "DESCONHECIDA",
    )

    score = localizar_campo(
        registro,
        [
            "risk_score_correlacionado",
            "score_correlacionado",
            "risk_score",
            "score",
            "score_final",
        ],
        0.0,
    )

    prioridade = localizar_campo(
        registro,
        [
            "prioridade_soc",
            "prioridade",
            "nivel_risco",
            "severidade",
        ],
        "DESCONHECIDA",
    )

    timestamp = localizar_campo(
        registro,
        ["timestamp"],
        agora(),
    )

    try:
        score = float(score)
    except (TypeError, ValueError):
        score = 0.0

    return {
        "ioc": str(ioc),
        "categoria": str(categoria),
        "risk_score": score,
        "prioridade": str(prioridade),
        "timestamp": str(timestamp),
    }


def agrupar_por_ioc(registros):
    grupos = {}

    for registro in registros:
        normalizado = normalizar_registro(registro)

        ioc = normalizado["ioc"]

        if ioc not in grupos:
            grupos[ioc] = []

        grupos[ioc].append(normalizado)

    return grupos


def calcular_nivel_campanha(
    quantidade_eventos,
    quantidade_categorias,
    score_medio,
    score_maximo,
):
    pontos = 0

    # Reincidencia / volume
    if quantidade_eventos >= 5:
        pontos += 35
    elif quantidade_eventos >= 3:
        pontos += 25
    elif quantidade_eventos >= 2:
        pontos += 15

    # Diversidade de tecnicas/categorias
    if quantidade_categorias >= 3:
        pontos += 30
    elif quantidade_categorias >= 2:
        pontos += 20

    # Risco medio
    if score_medio >= 80:
        pontos += 25
    elif score_medio >= 60:
        pontos += 20
    elif score_medio >= 40:
        pontos += 10

    # Pico de risco
    if score_maximo >= 80:
        pontos += 10
    elif score_maximo >= 60:
        pontos += 5

    pontos = min(pontos, 100)

    if pontos >= 80:
        nivel = "CRITICO"
    elif pontos >= 60:
        nivel = "ALTO"
    elif pontos >= 35:
        nivel = "MEDIO"
    else:
        nivel = "BAIXO"

    return pontos, nivel


def detectar_campanhas(grupos):
    resultados = []

    contador = 1

    for ioc, eventos in grupos.items():
        categorias = sorted(
            {
                evento["categoria"]
                for evento in eventos
                if evento["categoria"] != "DESCONHECIDA"
            }
        )

        scores = [
            evento["risk_score"]
            for evento in eventos
        ]

        quantidade_eventos = len(eventos)
        quantidade_categorias = len(categorias)

        score_medio = (
            round(statistics.mean(scores), 2)
            if scores
            else 0.0
        )

        score_maximo = (
            round(max(scores), 2)
            if scores
            else 0.0
        )

        pontos_campanha, nivel = calcular_nivel_campanha(
            quantidade_eventos,
            quantidade_categorias,
            score_medio,
            score_maximo,
        )

        campanha_detectada = (
            quantidade_eventos >= 3
            and quantidade_categorias >= 2
        )

        status = (
            "CAMPANHA_DETECTADA"
            if campanha_detectada
            else "PADRAO_INSUFICIENTE"
        )

        campanha_id = (
            f"CAMP-36-{contador:04d}"
        )

        resultado = {
            "campanha_id": campanha_id,
            "ioc": ioc,
            "quantidade_eventos": quantidade_eventos,
            "quantidade_categorias": quantidade_categorias,
            "categorias": categorias,
            "risk_score_medio": score_medio,
            "risk_score_maximo": score_maximo,
            "score_campanha": pontos_campanha,
            "nivel": nivel,
            "status": status,
            "campanha_detectada": campanha_detectada,
            "eventos": eventos,
            "timestamp": agora(),
        }

        resultados.append(resultado)
        contador += 1

    return resultados


def persistir_campanha(conexao, campanha):
    cursor = conexao.cursor()

    cursor.execute(
        """
        INSERT OR REPLACE INTO campanhas_ioc (
            campanha_id,
            ioc,
            quantidade_eventos,
            quantidade_categorias,
            categorias,
            score_medio,
            score_maximo,
            nivel,
            status,
            timestamp
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            campanha["campanha_id"],
            campanha["ioc"],
            campanha["quantidade_eventos"],
            campanha["quantidade_categorias"],
            json.dumps(
                campanha["categorias"],
                ensure_ascii=False
            ),
            campanha["risk_score_medio"],
            campanha["risk_score_maximo"],
            campanha["nivel"],
            campanha["status"],
            campanha["timestamp"],
        ),
    )

    conexao.commit()


def criar_alerta(campanha):
    if not campanha["campanha_detectada"]:
        return None

    alerta_id = (
        "CAMP-ALT-"
        + datetime.now(timezone.utc).strftime(
            "%Y%m%d%H%M%S%f"
        )
    )

    return {
        "alerta_id": alerta_id,
        "campanha_id": campanha["campanha_id"],
        "ioc": campanha["ioc"],
        "tipo": "CAMPANHA_IOC",
        "quantidade_eventos":
            campanha["quantidade_eventos"],
        "categorias":
            campanha["categorias"],
        "risk_score_medio":
            campanha["risk_score_medio"],
        "risk_score_maximo":
            campanha["risk_score_maximo"],
        "score_campanha":
            campanha["score_campanha"],
        "severidade":
            campanha["nivel"],
        "status": "ABERTO",
        "descricao":
            "Padrao de campanha detectado por "
            "reincidencia e diversidade de categorias.",
        "timestamp": agora(),
    }


def main():
    titulo("AULA 36 - DETECCAO DE CAMPANHAS POR IOC")

    print("CyberSentinel-ML")
    print("Correlacao Historica + Campaign Detection")
    print()
    print("Objetivo:")
    print(
        "Identificar quando eventos historicamente "
        "correlacionados formam um padrao de campanha."
    )

    # ========================================================
    # ETAPA 1
    # ========================================================

    titulo("ETAPA 1 - PREPARANDO DIRETORIOS")

    DIR_CAMPANHAS.mkdir(
        parents=True,
        exist_ok=True
    )

    DIR_ALERTAS.mkdir(
        parents=True,
        exist_ok=True
    )

    print("[OK] Diretorio campanhas pronto")
    print("[OK] Diretorio alertas pronto")

    # ========================================================
    # ETAPA 2
    # ========================================================

    titulo("ETAPA 2 - VALIDANDO BANCO SQLITE")

    if not BANCO.exists():
        print("[ERRO] Banco SQLite nao encontrado")
        print(f"Esperado: {BANCO}")
        print("Execute primeiro a Aula 35.")
        return

    print("[OK] Banco SQLite encontrado")
    print(f"Banco: {BANCO.relative_to(BASE_DIR)}")

    conexao = conectar_banco()

    try:
        # ====================================================
        # ETAPA 3
        # ====================================================

        titulo(
            "ETAPA 3 - VALIDANDO HISTORICO DA AULA 35"
        )

        registros, colunas = carregar_historico_aula_35(
            conexao
        )

        print(
            f"[OK] Registros historicos carregados: "
            f"{len(registros)}"
        )

        if not registros:
            print(
                "[ERRO] Nenhum registro historico encontrado."
            )
            print(
                "Execute a Aula 35 para gerar o historico."
            )
            return

        # ====================================================
        # ETAPA 4
        # ====================================================

        titulo(
            "ETAPA 4 - PREPARANDO TABELA DE CAMPANHAS"
        )

        preparar_tabela_campanhas(conexao)

        print("[OK] Tabela campanhas_ioc pronta")

        # ====================================================
        # ETAPA 5
        # ====================================================

        titulo(
            "ETAPA 5 - AGRUPANDO EVENTOS POR IOC"
        )

        grupos = agrupar_por_ioc(registros)

        print(
            f"[OK] IOCs unicos encontrados: "
            f"{len(grupos)}"
        )

        for ioc, eventos in grupos.items():
            print(
                f"- {ioc} | ocorrencias: {len(eventos)}"
            )

        # ====================================================
        # ETAPA 6
        # ====================================================

        titulo(
            "ETAPA 6 - EXECUTANDO DETECCAO DE CAMPANHAS"
        )

        campanhas = detectar_campanhas(grupos)

        alertas = []

        for indice, campanha in enumerate(
            campanhas,
            start=1
        ):
            print()
            print("-" * 72)
            print(
                f"ANALISE IOC {indice}/{len(campanhas)}"
            )
            print("-" * 72)

            print(f"IOC: {campanha['ioc']}")
            print(
                "Ocorrencias: "
                f"{campanha['quantidade_eventos']}"
            )
            print(
                "Categorias distintas: "
                f"{campanha['quantidade_categorias']}"
            )
            print(
                f"Categorias: {campanha['categorias']}"
            )
            print(
                "Risk Score medio: "
                f"{campanha['risk_score_medio']}/100"
            )
            print(
                "Risk Score maximo: "
                f"{campanha['risk_score_maximo']}/100"
            )

            print()
            print("ANALISE DE CAMPANHA:")
            print(
                f"Score campanha: "
                f"{campanha['score_campanha']}/100"
            )
            print(
                f"Nivel: {campanha['nivel']}"
            )
            print(
                f"Status: {campanha['status']}"
            )

            if campanha["campanha_detectada"]:
                print(
                    "[ALERTA] Padrao de campanha detectado"
                )
            else:
                print(
                    "[OK] Sem evidencia suficiente "
                    "de campanha"
                )

            persistir_campanha(
                conexao,
                campanha
            )

            alerta = criar_alerta(campanha)

            if alerta:
                alertas.append(alerta)

                print(
                    f"[OK] Alerta SOC: "
                    f"{alerta['alerta_id']}"
                )

        # ====================================================
        # ETAPA 7
        # ====================================================

        titulo(
            "ETAPA 7 - PERSISTINDO RESULTADOS"
        )

        salvar_json(
            ARQUIVO_CAMPANHAS,
            campanhas
        )

        print("[OK] Analises de campanha salvas")
        print(
            "Arquivo: "
            "campanhas\\campanhas_aula_36.json"
        )

        salvar_json(
            ARQUIVO_ALERTAS,
            alertas
        )

        print("[OK] Alertas de campanha salvos")
        print(
            "Arquivo: "
            "alertas\\alertas_campanhas_aula_36.json"
        )

        campanhas_detectadas = sum(
            1
            for item in campanhas
            if item["campanha_detectada"]
        )

        relatorio = {
            "projeto": "CyberSentinel-ML",
            "aula": 36,
            "titulo":
                "Deteccao de Campanhas por IOC",
            "registros_historicos":
                len(registros),
            "iocs_unicos":
                len(grupos),
            "analises_realizadas":
                len(campanhas),
            "campanhas_detectadas":
                campanhas_detectadas,
            "alertas_soc":
                len(alertas),
            "timestamp":
                agora(),
        }

        salvar_json(
            ARQUIVO_RELATORIO,
            relatorio
        )

        print("[OK] Relatorio salvo")
        print(
            "Arquivo: "
            "alertas\\relatorio_aula_36.json"
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
                "Tabela historica encontrada",
                tabela_existe(
                    conexao,
                    "correlacao_ioc_eventos"
                )
            ),
            (
                "Historico carregado",
                len(registros) > 0
            ),
            (
                "Tabela campanhas criada",
                tabela_existe(
                    conexao,
                    "campanhas_ioc"
                )
            ),
            (
                "IOCs agrupados",
                len(grupos) > 0
            ),
            (
                "Analises realizadas",
                len(campanhas) > 0
            ),
            (
                "Campanha reincidente identificada",
                any(
                    c["quantidade_eventos"] >= 3
                    for c in campanhas
                )
            ),
            (
                "Diversidade de categorias identificada",
                any(
                    c["quantidade_categorias"] >= 2
                    for c in campanhas
                )
            ),
            (
                "Campanha detectada",
                campanhas_detectadas > 0
            ),
            (
                "Alerta SOC gerado",
                len(alertas) > 0
            ),
            (
                "Arquivo campanhas criado",
                ARQUIVO_CAMPANHAS.exists()
            ),
            (
                "Arquivo alertas criado",
                ARQUIVO_ALERTAS.exists()
            ),
            (
                "Relatorio criado",
                ARQUIVO_RELATORIO.exists()
            ),
        ]

        quantidade_ok = 0

        for descricao, resultado in validacoes:
            if resultado:
                print(f"[OK] {descricao}")
                quantidade_ok += 1
            else:
                print(f"[ERRO] {descricao}")

        total_validacoes = len(validacoes)

        saude = (
            quantidade_ok
            / total_validacoes
            * 100
        )

        print()
        print(
            f"Validacoes: "
            f"{quantidade_ok}/{total_validacoes}"
        )
        print(f"Saude: {saude:.2f}%")

        # ====================================================
        # RESUMO
        # ====================================================

        titulo("RESUMO FINAL DA AULA 36")

        print(
            f"Registros historicos: {len(registros)}"
        )
        print(
            f"IOCs unicos: {len(grupos)}"
        )
        print(
            f"Analises de campanha: {len(campanhas)}"
        )
        print(
            f"Campanhas detectadas: "
            f"{campanhas_detectadas}"
        )
        print(
            f"Alertas SOC: {len(alertas)}"
        )

        print()
        print(
            f"Validacoes: "
            f"{quantidade_ok}/{total_validacoes}"
        )
        print(f"Saude: {saude:.2f}%")

        if quantidade_ok == total_validacoes:
            print("Status: AULA 36 CONCLUIDA")
        else:
            print(
                "Status: AULA 36 REQUER ATENCAO"
            )

        # ====================================================
        # ARQUITETURA
        # ====================================================

        titulo("ARQUITETURA DA AULA 36")

        print(
            """
HISTORICO AULA 35
       |
       v
SQLITE
       |
       v
AGRUPAMENTO POR IOC
       |
       +---- OCORRENCIAS
       |
       +---- CATEGORIAS
       |
       +---- RISK SCORES
       |
       v
ANALISE DE CAMPANHA
       |
       +---- FREQUENCIA
       |
       +---- DIVERSIDADE
       |
       +---- RISCO MEDIO
       |
       +---- RISCO MAXIMO
       |
       v
SCORE DE CAMPANHA
       |
       +---- PADRAO INSUFICIENTE
       |
       +---- CAMPANHA DETECTADA
                    |
                    v
              PRIORIDADE SOC
                    |
                    v
                ALERTA SOC
"""
        )

        titulo("CYBERSENTINEL-ML")
        print(
            "AULA 36 - DETECCAO DE CAMPANHAS POR IOC"
        )

        if quantidade_ok == total_validacoes:
            print("AULA 36 CONCLUIDA")
        else:
            print("AULA 36 REQUER ATENCAO")

    finally:
        conexao.close()


if __name__ == "__main__":
    main()