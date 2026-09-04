"""
CyberSentinel-ML
AULA 39 - MITRE ATT&CK MAPPING
Versao corrigida V2 - Schema Migration + IOC Context

Objetivo:
Adicionar contexto MITRE ATT&CK aos eventos correlacionados
produzidos pelo pipeline CyberSentinel-ML.

IMPORTANTE:
Esta aula realiza somente mapeamento defensivo/contextual.
Nenhuma tecnica ofensiva e executada.
Nenhuma Technique ID e atribuida sem evidencia suficiente.
"""

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path


# ============================================================
# CONFIGURACOES
# ============================================================

PROJETO = "CyberSentinel-ML"
AULA = 39
VERSAO = "2.0"

BASE_DIR = Path(__file__).resolve().parent

DADOS_DIR = BASE_DIR / "dados"
MITRE_DIR = BASE_DIR / "mitre"
ALERTAS_DIR = BASE_DIR / "alertas"

DB_PATH = DADOS_DIR / "cybersentinel.db"

MITRE_JSON = MITRE_DIR / "mitre_mapping_aula_39.json"
RELATORIO_JSON = ALERTAS_DIR / "relatorio_aula_39.json"

TABELA_HISTORICO = "correlacao_ioc_eventos"
TABELA_MITRE = "mitre_attack_mapping"


# ============================================================
# FUNCOES AUXILIARES
# ============================================================

def agora_iso():
    return datetime.now(timezone.utc).isoformat()


def linha():
    print("=" * 72)


def sublinha():
    print("-" * 72)


def titulo(texto):
    linha()
    print(texto)
    linha()


def gerar_mapping_id():
    timestamp = datetime.now(timezone.utc).strftime(
        "%Y%m%d%H%M%S%f"
    )

    sufixo = uuid.uuid4().hex[:6].upper()

    return f"MITRE-39-{timestamp}-{sufixo}"


def salvar_json(caminho, dados):
    caminho.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with open(
        caminho,
        "w",
        encoding="utf-8"
    ) as arquivo:

        json.dump(
            dados,
            arquivo,
            indent=4,
            ensure_ascii=False,
            default=str
        )


# ============================================================
# SQLITE
# ============================================================

def conectar_banco():
    conexao = sqlite3.connect(DB_PATH)
    conexao.row_factory = sqlite3.Row

    return conexao


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

    cursor.execute(
        f"PRAGMA table_info({tabela})"
    )

    return [
        registro["name"]
        for registro in cursor.fetchall()
    ]


# ============================================================
# SCHEMA HISTORICO
# ============================================================

def validar_schema_historico(conexao):
    colunas = obter_colunas(
        conexao,
        TABELA_HISTORICO
    )

    obrigatorias = [
        "id_evento",
        "timestamp",
        "ip_origem",
        "categoria",
        "probabilidade_ataque",
        "confianca_categoria",
        "abuse_score",
        "total_reports",
        "risk_score_base",
        "bonus_correlacao",
        "risk_score_correlacionado",
        "nivel_risco",
        "alerta_id"
    ]

    ausentes = [
        coluna
        for coluna in obrigatorias
        if coluna not in colunas
    ]

    return {
        "valido": len(ausentes) == 0,
        "colunas": colunas,
        "obrigatorias": obrigatorias,
        "ausentes": ausentes
    }


# ============================================================
# TABELA MITRE
# ============================================================

def criar_tabela_mitre(conexao):
    cursor = conexao.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS mitre_attack_mapping (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mapping_id TEXT NOT NULL,
            id_evento TEXT,
            timestamp TEXT,
            ip_origem TEXT,
            categoria_ml TEXT,
            risk_score REAL,
            contexto TEXT,
            tatica_candidata TEXT,
            technique_id TEXT,
            technique TEXT,
            confianca_mapping TEXT,
            observacao TEXT
        )
        """
    )

    conexao.commit()


def migrar_schema_mitre(conexao):
    """
    Atualiza automaticamente tabelas criadas por versoes
    anteriores da Aula 39.

    Nenhum registro historico e apagado.
    """

    colunas_existentes = obter_colunas(
        conexao,
        TABELA_MITRE
    )

    colunas_necessarias = {
        "mapping_id": "TEXT",
        "id_evento": "TEXT",
        "timestamp": "TEXT",
        "ip_origem": "TEXT",
        "categoria_ml": "TEXT",
        "risk_score": "REAL",
        "contexto": "TEXT",
        "tatica_candidata": "TEXT",
        "technique_id": "TEXT",
        "technique": "TEXT",
        "confianca_mapping": "TEXT",
        "observacao": "TEXT"
    }

    adicionadas = []

    cursor = conexao.cursor()

    for coluna, tipo in colunas_necessarias.items():

        if coluna not in colunas_existentes:

            cursor.execute(
                f"""
                ALTER TABLE {TABELA_MITRE}
                ADD COLUMN {coluna} {tipo}
                """
            )

            adicionadas.append(coluna)

    conexao.commit()

    return adicionadas


def validar_schema_mitre(conexao):
    colunas = obter_colunas(
        conexao,
        TABELA_MITRE
    )

    obrigatorias = [
        "id",
        "mapping_id",
        "id_evento",
        "timestamp",
        "ip_origem",
        "categoria_ml",
        "risk_score",
        "contexto",
        "tatica_candidata",
        "technique_id",
        "technique",
        "confianca_mapping",
        "observacao"
    ]

    ausentes = [
        coluna
        for coluna in obrigatorias
        if coluna not in colunas
    ]

    return {
        "valido": len(ausentes) == 0,
        "colunas": colunas,
        "ausentes": ausentes
    }


# ============================================================
# EVENTOS HISTORICOS
# ============================================================

def carregar_eventos(conexao):
    cursor = conexao.cursor()

    cursor.execute(
        """
        SELECT
            id,
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
        FROM correlacao_ioc_eventos
        ORDER BY id ASC
        """
    )

    return [
        dict(registro)
        for registro in cursor.fetchall()
    ]


# ============================================================
# IOC
# ============================================================

def validar_ioc(valor):
    if valor is None:
        return False

    valor = str(valor).strip()

    if not valor:
        return False

    if valor.upper() in {
        "DESCONHECIDO",
        "UNKNOWN",
        "NONE",
        "NULL"
    }:
        return False

    return True


# ============================================================
# MITRE ATT&CK CONTEXTUAL MAPPING
# ============================================================

def mapear_categoria_mitre(categoria):
    """
    Mapeamento conservador.

    A categoria ML nao equivale automaticamente
    a uma Technique ID MITRE ATT&CK.

    Technique IDs somente devem ser utilizadas quando
    houver evidencia suficiente para sustentacao.
    """

    categoria_normalizada = (
        str(categoria)
        .strip()
        .lower()
    )

    if categoria_normalizada == "dos":

        return {
            "contexto": "IMPACTO",
            "tatica_candidata": "Impact",
            "technique_id": "NAO_ATRIBUIDA",
            "technique": "NAO_ATRIBUIDA",
            "confianca_mapping": "CONTEXTUAL",
            "observacao": (
                "Categoria DoS sugere contexto de impacto, "
                "mas nao e suficiente isoladamente para "
                "determinar uma tecnica ATT&CK especifica."
            )
        }

    if categoria_normalizada == "shellcode":

        return {
            "contexto": "EXECUCAO_POTENCIAL",
            "tatica_candidata": "Execution",
            "technique_id": "NAO_ATRIBUIDA",
            "technique": "NAO_ATRIBUIDA",
            "confianca_mapping": "CONTEXTUAL",
            "observacao": (
                "Shellcode pode indicar contexto de execucao, "
                "mas a categoria isolada nao identifica uma "
                "tecnica ATT&CK especifica."
            )
        }

    if categoria_normalizada == "exploits":

        return {
            "contexto": "EXPLORACAO",
            "tatica_candidata": "NAO_ATRIBUIDA",
            "technique_id": "NAO_ATRIBUIDA",
            "technique": "NAO_ATRIBUIDA",
            "confianca_mapping": "INSUFICIENTE",
            "observacao": (
                "A categoria Exploits e generica. "
                "Sao necessarias evidencias adicionais sobre "
                "vulnerabilidade, servico, vetor e comportamento "
                "observado."
            )
        }

    if categoria_normalizada == "reconnaissance":

        return {
            "contexto": "RECONHECIMENTO",
            "tatica_candidata": "Reconnaissance",
            "technique_id": "NAO_ATRIBUIDA",
            "technique": "NAO_ATRIBUIDA",
            "confianca_mapping": "CONTEXTUAL",
            "observacao": (
                "A categoria sugere contexto de reconhecimento, "
                "mas nao existe evidencia suficiente para atribuir "
                "uma Technique ID especifica."
            )
        }

    if categoria_normalizada == "backdoor":

        return {
            "contexto": "PERSISTENCIA_POTENCIAL",
            "tatica_candidata": "Persistence",
            "technique_id": "NAO_ATRIBUIDA",
            "technique": "NAO_ATRIBUIDA",
            "confianca_mapping": "CONTEXTUAL",
            "observacao": (
                "Backdoor pode estar associado a persistencia, "
                "mas sao necessarias evidencias comportamentais "
                "adicionais para confirmar uma tecnica ATT&CK."
            )
        }

    if categoria_normalizada == "worms":

        return {
            "contexto": "PROPAGACAO_POTENCIAL",
            "tatica_candidata": "NAO_ATRIBUIDA",
            "technique_id": "NAO_ATRIBUIDA",
            "technique": "NAO_ATRIBUIDA",
            "confianca_mapping": "INSUFICIENTE",
            "observacao": (
                "A categoria Worms sugere propagacao, mas "
                "nao existem evidencias suficientes para "
                "determinar uma tecnica ATT&CK especifica."
            )
        }

    if categoria_normalizada == "fuzzers":

        return {
            "contexto": "TESTE_OU_EXPLORACAO",
            "tatica_candidata": "NAO_ATRIBUIDA",
            "technique_id": "NAO_ATRIBUIDA",
            "technique": "NAO_ATRIBUIDA",
            "confianca_mapping": "INSUFICIENTE",
            "observacao": (
                "A categoria Fuzzers isoladamente nao fornece "
                "evidencia suficiente para atribuir uma tecnica "
                "MITRE ATT&CK."
            )
        }

    if categoria_normalizada == "generic":

        return {
            "contexto": "GENERICO",
            "tatica_candidata": "NAO_ATRIBUIDA",
            "technique_id": "NAO_ATRIBUIDA",
            "technique": "NAO_ATRIBUIDA",
            "confianca_mapping": "INSUFICIENTE",
            "observacao": (
                "Categoria generica sem evidencia suficiente "
                "para mapeamento ATT&CK especifico."
            )
        }

    if categoria_normalizada == "analysis":

        return {
            "contexto": "CONTEXTO_GENERICO",
            "tatica_candidata": "NAO_ATRIBUIDA",
            "technique_id": "NAO_ATRIBUIDA",
            "technique": "NAO_ATRIBUIDA",
            "confianca_mapping": "INSUFICIENTE",
            "observacao": (
                "Categoria generica sem evidencia suficiente "
                "para determinar tatica ou tecnica ATT&CK."
            )
        }

    return {
        "contexto": "NAO_CLASSIFICADO",
        "tatica_candidata": "NAO_ATRIBUIDA",
        "technique_id": "NAO_ATRIBUIDA",
        "technique": "NAO_ATRIBUIDA",
        "confianca_mapping": "INSUFICIENTE",
        "observacao": (
            "Nao existem evidencias suficientes para produzir "
            "mapeamento MITRE ATT&CK confiavel."
        )
    }


# ============================================================
# PERSISTENCIA MITRE
# ============================================================

def persistir_mapping(conexao, mapping):
    cursor = conexao.cursor()

    cursor.execute(
        """
        INSERT INTO mitre_attack_mapping (
            mapping_id,
            id_evento,
            timestamp,
            ip_origem,
            categoria_ml,
            risk_score,
            contexto,
            tatica_candidata,
            technique_id,
            technique,
            confianca_mapping,
            observacao
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            mapping["mapping_id"],
            mapping["id_evento"],
            mapping["timestamp"],
            mapping["ip_origem"],
            mapping["categoria_ml"],
            mapping["risk_score"],
            mapping["contexto"],
            mapping["tatica_candidata"],
            mapping["technique_id"],
            mapping["technique"],
            mapping["confianca_mapping"],
            mapping["observacao"]
        )
    )

    conexao.commit()


# ============================================================
# MAIN
# ============================================================

def main():

    titulo(
        "AULA 39 - MITRE ATT&CK MAPPING"
    )

    print(PROJETO)
    print("MITRE ATT&CK Contextual Mapping")
    print("Versao corrigida V2 - Schema Migration + IOC Context")
    print()

    print("Objetivo:")
    print(
        "Adicionar contexto MITRE ATT&CK aos incidentes"
    )
    print(
        "produzidos pelo pipeline CyberSentinel-ML."
    )
    print()

    print("IMPORTANTE:")
    print(
        "Nenhuma tecnica ofensiva sera executada."
    )
    print(
        "O mapeamento desta aula e exclusivamente defensivo."
    )
    print()

    validacoes = []

    conexao = None

    try:

        # ====================================================
        # ETAPA 1
        # ====================================================

        titulo(
            "ETAPA 1 - PREPARANDO DIRETORIOS"
        )

        DADOS_DIR.mkdir(
            parents=True,
            exist_ok=True
        )

        MITRE_DIR.mkdir(
            parents=True,
            exist_ok=True
        )

        ALERTAS_DIR.mkdir(
            parents=True,
            exist_ok=True
        )

        print("[OK] Diretorio dados pronto")
        print("[OK] Diretorio mitre pronto")
        print("[OK] Diretorio alertas pronto")

        validacoes.append(
            (
                "Diretorio dados disponivel",
                DADOS_DIR.exists()
            )
        )

        validacoes.append(
            (
                "Diretorio MITRE disponivel",
                MITRE_DIR.exists()
            )
        )

        validacoes.append(
            (
                "Diretorio alertas disponivel",
                ALERTAS_DIR.exists()
            )
        )

        # ====================================================
        # ETAPA 2
        # ====================================================

        titulo(
            "ETAPA 2 - VALIDANDO SQLITE"
        )

        if not DB_PATH.exists():

            print(
                "[ERRO] Banco SQLite nao encontrado"
            )

            print(
                f"Banco esperado: {DB_PATH}"
            )

            return

        print(
            "[OK] Banco SQLite encontrado"
        )

        print(
            f"Banco: {DB_PATH.relative_to(BASE_DIR)}"
        )

        conexao = conectar_banco()

        historico_existe = tabela_existe(
            conexao,
            TABELA_HISTORICO
        )

        if historico_existe:

            print(
                "[OK] Tabela correlacao_ioc_eventos encontrada"
            )

        else:

            print(
                "[ERRO] Tabela correlacao_ioc_eventos nao encontrada"
            )

            return

        validacoes.append(
            (
                "Banco SQLite encontrado",
                DB_PATH.exists()
            )
        )

        validacoes.append(
            (
                "Historico correlacionado disponivel",
                historico_existe
            )
        )

        # ====================================================
        # ETAPA 3
        # ====================================================

        titulo(
            "ETAPA 3 - VALIDANDO SCHEMA HISTORICO"
        )

        schema_historico = validar_schema_historico(
            conexao
        )

        print(
            f"[OK] Colunas detectadas: "
            f"{len(schema_historico['colunas'])}"
        )

        for coluna in schema_historico[
            "obrigatorias"
        ]:

            if coluna in schema_historico["colunas"]:

                print(
                    f"[OK] Coluna encontrada: {coluna}"
                )

            else:

                print(
                    f"[ERRO] Coluna ausente: {coluna}"
                )

        validacoes.append(
            (
                "Schema historico compativel",
                schema_historico["valido"]
            )
        )

        if not schema_historico["valido"]:

            print()
            print(
                "[ERRO] O schema historico nao e "
                "compativel com a Aula 39."
            )

            return

        # ====================================================
        # ETAPA 4
        # ====================================================

        titulo(
            "ETAPA 4 - PREPARANDO TABELA MITRE"
        )

        criar_tabela_mitre(
            conexao
        )

        print(
            "[OK] Tabela mitre_attack_mapping localizada/criada"
        )

        # ====================================================
        # MIGRACAO
        # ====================================================

        titulo(
            "ETAPA 5 - VALIDANDO E MIGRANDO SCHEMA MITRE"
        )

        colunas_antes = obter_colunas(
            conexao,
            TABELA_MITRE
        )

        print(
            f"[OK] Colunas antes da validacao: "
            f"{len(colunas_antes)}"
        )

        adicionadas = migrar_schema_mitre(
            conexao
        )

        if adicionadas:

            print(
                "[INFO] Schema antigo detectado"
            )

            print(
                "[OK] Migracao automatica iniciada"
            )

            for coluna in adicionadas:

                print(
                    f"[OK] Coluna adicionada: {coluna}"
                )

            print(
                "[OK] Historico existente preservado"
            )

        else:

            print(
                "[OK] Schema MITRE ja esta atualizado"
            )

        schema_mitre = validar_schema_mitre(
            conexao
        )

        if schema_mitre["valido"]:

            print(
                "[OK] Schema MITRE validado"
            )

        else:

            print(
                "[ERRO] Schema MITRE continua incompleto"
            )

            for coluna in schema_mitre["ausentes"]:

                print(
                    f"[ERRO] Coluna ausente: {coluna}"
                )

            return

        validacoes.append(
            (
                "Tabela MITRE disponivel",
                tabela_existe(
                    conexao,
                    TABELA_MITRE
                )
            )
        )

        validacoes.append(
            (
                "Schema MITRE atualizado",
                schema_mitre["valido"]
            )
        )

        validacoes.append(
            (
                "Coluna ip_origem disponivel no MITRE",
                "ip_origem"
                in schema_mitre["colunas"]
            )
        )

        # ====================================================
        # ETAPA 6
        # ====================================================

        titulo(
            "ETAPA 6 - CARREGANDO EVENTOS CORRELACIONADOS"
        )

        eventos = carregar_eventos(
            conexao
        )

        print(
            f"[OK] Eventos carregados: "
            f"{len(eventos)}"
        )

        eventos_carregados = (
            len(eventos) > 0
        )

        validacoes.append(
            (
                "Eventos carregados",
                eventos_carregados
            )
        )

        if not eventos_carregados:

            print(
                "[ERRO] Nenhum evento encontrado"
            )

            return

        # ====================================================
        # IOC
        # ====================================================

        iocs_validos = all(
            validar_ioc(
                evento.get("ip_origem")
            )
            for evento in eventos
        )

        if iocs_validos:

            print(
                "[OK] Todos os IOCs recuperados via ip_origem"
            )

        else:

            print(
                "[ERRO] Existem IOCs invalidos ou desconhecidos"
            )

        validacoes.append(
            (
                "IOCs recuperados corretamente do historico",
                iocs_validos
            )
        )

        if not iocs_validos:

            print()
            print(
                "[ERRO] A Aula 39 nao continuara com IOC "
                "DESCONHECIDO."
            )

            return

        # ====================================================
        # ETAPA 7
        # ====================================================

        titulo(
            "ETAPA 7 - EXECUTANDO MITRE ATT&CK MAPPING"
        )

        mappings = []

        for indice, evento in enumerate(
            eventos,
            start=1
        ):

            sublinha()

            print(
                f"EVENTO {indice}/{len(eventos)}"
            )

            sublinha()

            id_evento = evento.get(
                "id_evento"
            )

            ip_origem = evento.get(
                "ip_origem"
            )

            categoria = evento.get(
                "categoria"
            )

            risk_score = float(
                evento.get(
                    "risk_score_correlacionado"
                )
                or 0.0
            )

            print(
                f"ID evento: {id_evento}"
            )

            print(
                f"IOC: {ip_origem}"
            )

            print(
                f"Categoria ML: {categoria}"
            )

            print(
                f"Risk Score: {risk_score:.2f}/100"
            )

            print()

            contexto_mitre = (
                mapear_categoria_mitre(
                    categoria
                )
            )

            mapping = {
                "mapping_id":
                    gerar_mapping_id(),

                "id_evento":
                    id_evento,

                "timestamp":
                    agora_iso(),

                "ip_origem":
                    ip_origem,

                "categoria_ml":
                    categoria,

                "probabilidade_ataque":
                    evento.get(
                        "probabilidade_ataque"
                    ),

                "confianca_categoria":
                    evento.get(
                        "confianca_categoria"
                    ),

                "abuse_score":
                    evento.get(
                        "abuse_score"
                    ),

                "total_reports":
                    evento.get(
                        "total_reports"
                    ),

                "risk_score_base":
                    evento.get(
                        "risk_score_base"
                    ),

                "bonus_correlacao":
                    evento.get(
                        "bonus_correlacao"
                    ),

                "risk_score":
                    risk_score,

                "nivel_risco":
                    evento.get(
                        "nivel_risco"
                    ),

                "alerta_origem":
                    evento.get(
                        "alerta_id"
                    ),

                **contexto_mitre
            }

            print(
                "MITRE ATT&CK CONTEXT:"
            )

            print(
                f"Contexto: "
                f"{mapping['contexto']}"
            )

            print(
                f"Tatica candidata: "
                f"{mapping['tatica_candidata']}"
            )

            print(
                f"Technique ID: "
                f"{mapping['technique_id']}"
            )

            print(
                f"Technique: "
                f"{mapping['technique']}"
            )

            print(
                f"Confianca mapping: "
                f"{mapping['confianca_mapping']}"
            )

            print(
                f"Observacao: "
                f"{mapping['observacao']}"
            )

            persistir_mapping(
                conexao,
                mapping
            )

            mappings.append(
                mapping
            )

            print(
                f"[OK] Mapping: "
                f"{mapping['mapping_id']}"
            )

        # ====================================================
        # ETAPA 8
        # ====================================================

        titulo(
            "ETAPA 8 - ANALISANDO COBERTURA ATT&CK"
        )

        contextuais = sum(
            1
            for mapping in mappings
            if mapping[
                "confianca_mapping"
            ] == "CONTEXTUAL"
        )

        insuficientes = sum(
            1
            for mapping in mappings
            if mapping[
                "confianca_mapping"
            ] == "INSUFICIENTE"
        )

        techniques_confirmadas = sum(
            1
            for mapping in mappings
            if mapping[
                "technique_id"
            ] != "NAO_ATRIBUIDA"
        )

        categorias = sorted(
            {
                mapping["categoria_ml"]
                for mapping in mappings
                if mapping.get(
                    "categoria_ml"
                )
            }
        )

        taticas = sorted(
            {
                mapping["tatica_candidata"]
                for mapping in mappings
                if mapping.get(
                    "tatica_candidata"
                )
                and mapping[
                    "tatica_candidata"
                ] != "NAO_ATRIBUIDA"
            }
        )

        iocs = sorted(
            {
                mapping["ip_origem"]
                for mapping in mappings
                if validar_ioc(
                    mapping.get(
                        "ip_origem"
                    )
                )
            }
        )

        print(
            f"Mapeamentos: "
            f"{len(mappings)}"
        )

        print(
            f"Contextuais: "
            f"{contextuais}"
        )

        print(
            f"Evidencia insuficiente: "
            f"{insuficientes}"
        )

        print(
            f"Techniques confirmadas: "
            f"{techniques_confirmadas}"
        )

        print(
            f"Categorias distintas: "
            f"{len(categorias)}"
        )

        print(
            f"Taticas candidatas distintas: "
            f"{len(taticas)}"
        )

        print(
            f"IOCs distintos: "
            f"{len(iocs)}"
        )

        print()
        print("IOCs:")

        for ioc in iocs:
            print(
                f"- {ioc}"
            )

        print()
        print("Categorias:")

        for categoria in categorias:
            print(
                f"- {categoria}"
            )

        print()
        print(
            "Taticas candidatas:"
        )

        for tatica in taticas:
            print(
                f"- {tatica}"
            )

        # ====================================================
        # ETAPA 9
        # ====================================================

        titulo(
            "ETAPA 9 - PERSISTINDO RESULTADOS"
        )

        payload_mitre = {
            "projeto": PROJETO,
            "aula": AULA,
            "versao": VERSAO,
            "timestamp": agora_iso(),
            "fonte_eventos":
                TABELA_HISTORICO,
            "quantidade":
                len(mappings),
            "iocs_distintos":
                iocs,
            "mappings":
                mappings
        }

        salvar_json(
            MITRE_JSON,
            payload_mitre
        )

        print(
            "[OK] MITRE mappings salvos"
        )

        print(
            f"Arquivo: "
            f"{MITRE_JSON.relative_to(BASE_DIR)}"
        )

        relatorio = {
            "projeto": PROJETO,
            "aula": AULA,
            "versao": VERSAO,
            "timestamp": agora_iso(),

            "eventos_analisados":
                len(eventos),

            "mappings_mitre":
                len(mappings),

            "mappings_contextuais":
                contextuais,

            "evidencia_insuficiente":
                insuficientes,

            "techniques_confirmadas":
                techniques_confirmadas,

            "categorias_distintas":
                len(categorias),

            "taticas_candidatas":
                len(taticas),

            "iocs_distintos":
                len(iocs),

            "iocs":
                iocs,

            "categorias":
                categorias,

            "taticas":
                taticas,

            "schema_mitre_migrado":
                len(adicionadas) > 0,

            "colunas_adicionadas":
                adicionadas
        }

        salvar_json(
            RELATORIO_JSON,
            relatorio
        )

        print(
            "[OK] Relatorio salvo"
        )

        print(
            f"Arquivo: "
            f"{RELATORIO_JSON.relative_to(BASE_DIR)}"
        )

        # ====================================================
        # VALIDACOES FINAIS
        # ====================================================

        todos_mapeados = (
            len(mappings)
            == len(eventos)
            and len(eventos) > 0
        )

        contexto_atribuido = all(
            bool(
                mapping.get(
                    "contexto"
                )
            )
            for mapping in mappings
        )

        confianca_registrada = all(
            bool(
                mapping.get(
                    "confianca_mapping"
                )
            )
            for mapping in mappings
        )

        ioc_preservado_mapping = all(
            validar_ioc(
                mapping.get(
                    "ip_origem"
                )
            )
            for mapping in mappings
        )

        nenhuma_technique_inventada = all(
            (
                mapping[
                    "technique_id"
                ] == "NAO_ATRIBUIDA"
                or mapping[
                    "confianca_mapping"
                ] == "CONFIRMADA"
            )
            for mapping in mappings
        )

        arquivo_mitre_criado = (
            MITRE_JSON.exists()
        )

        relatorio_criado = (
            RELATORIO_JSON.exists()
        )

        validacoes.extend(
            [
                (
                    "Todos os eventos mapeados",
                    todos_mapeados
                ),
                (
                    "IOCs preservados nos mappings",
                    ioc_preservado_mapping
                ),
                (
                    "Contexto de seguranca atribuido",
                    contexto_atribuido
                ),
                (
                    "Nivel de confianca registrado",
                    confianca_registrada
                ),
                (
                    "Nenhuma Technique ID inventada sem evidencia",
                    nenhuma_technique_inventada
                ),
                (
                    "Arquivo MITRE criado",
                    arquivo_mitre_criado
                ),
                (
                    "Relatorio criado",
                    relatorio_criado
                )
            ]
        )

        # ====================================================
        # ETAPA 10
        # ====================================================

        titulo(
            "ETAPA 10 - VALIDACAO FINAL"
        )

        quantidade_ok = 0

        for descricao, resultado in validacoes:

            if resultado:

                print(
                    f"[OK] {descricao}"
                )

                quantidade_ok += 1

            else:

                print(
                    f"[ERRO] {descricao}"
                )

        total_validacoes = len(
            validacoes
        )

        if total_validacoes:

            saude = (
                quantidade_ok
                / total_validacoes
                * 100
            )

        else:

            saude = 0.0

        print()

        print(
            f"Validacoes: "
            f"{quantidade_ok}/"
            f"{total_validacoes}"
        )

        print(
            f"Saude: "
            f"{saude:.2f}%"
        )

        # ====================================================
        # RESUMO
        # ====================================================

        titulo(
            "RESUMO FINAL DA AULA 39"
        )

        print(
            f"Eventos analisados: "
            f"{len(eventos)}"
        )

        print(
            f"Mappings MITRE: "
            f"{len(mappings)}"
        )

        print(
            f"Mappings contextuais: "
            f"{contextuais}"
        )

        print(
            f"Evidencia insuficiente: "
            f"{insuficientes}"
        )

        print(
            f"Techniques confirmadas: "
            f"{techniques_confirmadas}"
        )

        print(
            f"Taticas candidatas: "
            f"{len(taticas)}"
        )

        print(
            f"IOCs distintos: "
            f"{len(iocs)}"
        )

        print(
            f"Schema migrado nesta execucao: "
            f"{'SIM' if adicionadas else 'NAO'}"
        )

        if adicionadas:

            print(
                "Colunas adicionadas: "
                + ", ".join(adicionadas)
            )

        print()

        if (
            quantidade_ok
            == total_validacoes
        ):

            print(
                "Status: AULA 39 CONCLUIDA"
            )

        else:

            print(
                "Status: AULA 39 REQUER ATENCAO"
            )

        # ====================================================
        # ARQUITETURA
        # ====================================================

        titulo(
            "ARQUITETURA DA AULA 39"
        )

        print(
            """
EVENTOS CORRELACIONADOS
          |
          v
        SQLite
          |
          v
VALIDACAO DO SCHEMA
          |
          +---- ip_origem
          +---- categoria
          +---- risk_score
          |
          v
   IOC RECUPERADO
          |
          v
     CATEGORIA ML
          |
          v
   CONTEXTO DE ATAQUE
          |
          v
   MITRE ATT&CK MAPPING
          |
     +----+----------------+
     |                     |
     v                     v
CONTEXTO              EVIDENCIAS
     |                     |
     v                     v
TATICA CANDIDATA     SUFICIENTES?
                           |
                    +------+------+
                    |             |
                    v             v
                   NAO           SIM
                    |             |
                    v             v
             SEM TECHNIQUE ID   TECHNIQUE
             CONFIRMADA         CONFIRMADA
                    |
                    v
              CONTEXTO SOC
                    |
                    v
          INVESTIGACAO HUMANA


SCHEMA MITRE
     |
     v
TABELA EXISTE?
     |
 +---+---+
 |       |
NAO     SIM
 |       |
 v       v
CRIA   INSPECIONA
         |
         v
   SCHEMA ANTIGO?
         |
     +---+---+
     |       |
    NAO     SIM
     |       |
     |       v
     |   MIGRACAO
     |   AUTOMATICA
     |       |
     +---+---+
         |
         v
    SCHEMA VALIDADO
         |
         v
   PERSISTE MAPPING


IMPORTANTE:
A categoria produzida pelo modelo ML nao equivale
automaticamente a uma tecnica MITRE ATT&CK.

O CyberSentinel nao atribui Technique IDs sem
evidencia suficiente.

A migracao de schema nao remove registros
historicos existentes.
"""
        )

        linha()
        print(
            "CYBERSENTINEL-ML"
        )
        linha()

        print(
            "AULA 39 - MITRE ATT&CK MAPPING"
        )

        if (
            quantidade_ok
            == total_validacoes
        ):

            print(
                "AULA 39 CONCLUIDA"
            )

        else:

            print(
                "AULA 39 REQUER ATENCAO"
            )

    except sqlite3.Error as erro:

        titulo(
            "ERRO SQLITE - AULA 39"
        )

        print(
            f"[ERRO] {erro}"
        )

        print()
        print(
            "Status: AULA 39 REQUER ATENCAO"
        )

    except Exception as erro:

        titulo(
            "ERRO INESPERADO - AULA 39"
        )

        print(
            f"[ERRO] {type(erro).__name__}: {erro}"
        )

        print()
        print(
            "Status: AULA 39 REQUER ATENCAO"
        )

    finally:

        if conexao is not None:

            conexao.close()


# ============================================================
# EXECUCAO
# ============================================================

if __name__ == "__main__":
    main()