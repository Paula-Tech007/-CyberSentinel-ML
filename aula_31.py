# ============================================================
# CyberSentinel-ML
# AULA 31 - THREAT INTELLIGENCE REAL
# Integração com AbuseIPDB
# ============================================================

import json
import os
import sys
from datetime import datetime, timezone
from ipaddress import ip_address
from pathlib import Path

import requests
from dotenv import load_dotenv


# ============================================================
# CONFIGURAÇÃO DO PROJETO
# ============================================================

PROJETO = "CyberSentinel-ML"
AULA = 31

BASE_DIR = Path(__file__).resolve().parent

ENV_FILE = BASE_DIR / ".env"

DIRETORIO_THREAT_INTEL = BASE_DIR / "threat_intel"

ARQUIVO_RESULTADO = (
    DIRETORIO_THREAT_INTEL
    / "threat_intelligence_aula_31.json"
)

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

MAX_AGE_DAYS = 90

TIMEOUT = 10


# ============================================================
# CARREGANDO VARIÁVEIS DO .ENV
# ============================================================

load_dotenv(dotenv_path=ENV_FILE)

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")


# ============================================================
# FUNÇÕES AUXILIARES
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
    return datetime.now(timezone.utc).isoformat()


def criar_diretorios():
    DIRETORIO_THREAT_INTEL.mkdir(
        parents=True,
        exist_ok=True
    )


# ============================================================
# VALIDAÇÃO DO ARQUIVO .ENV
# ============================================================

def validar_env():

    titulo("ETAPA 1 - VALIDANDO CONFIGURACAO .ENV")

    if not ENV_FILE.exists():

        print("[ERRO] Arquivo .env nao encontrado.")
        print()
        print("Local esperado:")
        print(ENV_FILE)

        return False

    print("[OK] Arquivo .env encontrado")
    print(f"Arquivo: {ENV_FILE}")

    return True


# ============================================================
# VALIDAÇÃO DA API KEY
# ============================================================

def validar_api_key():

    titulo("ETAPA 2 - VALIDANDO API KEY DO ABUSEIPDB")

    if not ABUSEIPDB_API_KEY:

        print(
            "[ERRO] Variavel ABUSEIPDB_API_KEY "
            "nao encontrada no arquivo .env."
        )

        print()
        print("O arquivo .env deve conter:")
        print()
        print("ABUSEIPDB_API_KEY=SUA_CHAVE")
        print()
        print("Nao coloque aspas.")
        print("Nao coloque espacos ao redor do sinal =.")

        return False

    if len(ABUSEIPDB_API_KEY.strip()) < 10:

        print("[ERRO] API Key parece invalida.")

        return False

    print("[OK] Variavel ABUSEIPDB_API_KEY carregada")
    print("[OK] API Key encontrada")
    print("[OK] API Key protegida - valor nao sera exibido")

    return True


# ============================================================
# VALIDAÇÃO DE IP
# ============================================================

def validar_ip(ip):

    try:

        endereco = ip_address(ip)

        if endereco.is_private:
            return False, "IP privado"

        if endereco.is_loopback:
            return False, "IP de loopback"

        if endereco.is_multicast:
            return False, "IP multicast"

        if endereco.is_unspecified:
            return False, "IP nao especificado"

        if endereco.is_reserved:
            return False, "IP reservado"

        return True, "IP publico valido"

    except ValueError:

        return False, "Formato de IP invalido"


# ============================================================
# CONSULTA AO ABUSEIPDB
# ============================================================

def consultar_abuseipdb(ip):

    headers = {
        "Accept": "application/json",
        "Key": ABUSEIPDB_API_KEY
    }

    params = {
        "ipAddress": ip,
        "maxAgeInDays": MAX_AGE_DAYS
    }

    try:

        inicio = datetime.now(timezone.utc)

        response = requests.get(
            ABUSEIPDB_URL,
            headers=headers,
            params=params,
            timeout=TIMEOUT
        )

        fim = datetime.now(timezone.utc)

        tempo_ms = (
            fim - inicio
        ).total_seconds() * 1000

        if response.status_code == 401:

            return {
                "status": "ERRO",
                "erro": "API Key invalida ou nao autorizada",
                "http_status": 401,
                "tempo_consulta_ms": round(tempo_ms, 4)
            }

        if response.status_code == 429:

            return {
                "status": "ERRO",
                "erro": "Limite de requisicoes da API atingido",
                "http_status": 429,
                "tempo_consulta_ms": round(tempo_ms, 4)
            }

        if response.status_code != 200:

            return {
                "status": "ERRO",
                "erro": (
                    "Resposta inesperada da API AbuseIPDB"
                ),
                "http_status": response.status_code,
                "tempo_consulta_ms": round(tempo_ms, 4)
            }

        resposta = response.json()

        dados = resposta.get("data", {})

        return {
            "status": "SUCESSO",
            "http_status": response.status_code,
            "tempo_consulta_ms": round(tempo_ms, 4),
            "dados": dados
        }

    except requests.exceptions.Timeout:

        return {
            "status": "ERRO",
            "erro": "Timeout na consulta ao AbuseIPDB"
        }

    except requests.exceptions.ConnectionError:

        return {
            "status": "ERRO",
            "erro": "Falha de conexao com AbuseIPDB"
        }

    except requests.exceptions.RequestException as erro:

        return {
            "status": "ERRO",
            "erro": str(erro)
        }

    except ValueError:

        return {
            "status": "ERRO",
            "erro": "Resposta JSON invalida recebida da API"
        }


# ============================================================
# CÁLCULO DE RISCO
# ============================================================

def calcular_nivel_risco(score):

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
# NORMALIZAÇÃO DOS DADOS
# ============================================================

def normalizar_threat_intelligence(ip, dados):

    score = dados.get(
        "abuseConfidenceScore",
        0
    )

    nivel_risco = calcular_nivel_risco(score)

    resultado = {

        "projeto": PROJETO,

        "aula": AULA,

        "fonte": "AbuseIPDB",

        "timestamp": agora_utc(),

        "ip": ip,

        "threat_intelligence": {

            "abuse_confidence_score": score,

            "nivel_risco": nivel_risco,

            "total_reports": dados.get(
                "totalReports",
                0
            ),

            "last_reported_at": dados.get(
                "lastReportedAt"
            ),

            "country_code": dados.get(
                "countryCode"
            ),

            "country_name": dados.get(
                "countryName"
            ),

            "isp": dados.get(
                "isp"
            ),

            "domain": dados.get(
                "domain"
            ),

            "usage_type": dados.get(
                "usageType"
            ),

            "is_public": dados.get(
                "isPublic"
            ),

            "is_whitelisted": dados.get(
                "isWhitelisted"
            )
        }
    }

    return resultado


# ============================================================
# EXIBIÇÃO DO RESULTADO
# ============================================================

def exibir_resultado(resultado):

    threat = resultado["threat_intelligence"]

    titulo("RESULTADO THREAT INTELLIGENCE")

    print(
        f"IP: "
        f"{resultado['ip']}"
    )

    print(
        f"Fonte: "
        f"{resultado['fonte']}"
    )

    print(
        f"Abuse Confidence Score: "
        f"{threat['abuse_confidence_score']}%"
    )

    print(
        f"Nivel de risco: "
        f"{threat['nivel_risco']}"
    )

    print(
        f"Total de reports: "
        f"{threat['total_reports']}"
    )

    print(
        f"Pais: "
        f"{threat['country_code']}"
    )

    print(
        f"ISP: "
        f"{threat['isp']}"
    )

    print(
        f"Dominio: "
        f"{threat['domain']}"
    )

    print(
        f"Tipo de uso: "
        f"{threat['usage_type']}"
    )

    print(
        f"Ultimo report: "
        f"{threat['last_reported_at']}"
    )


# ============================================================
# SALVAR RESULTADO
# ============================================================

def salvar_resultado(resultado):

    DIRETORIO_THREAT_INTEL.mkdir(
        parents=True,
        exist_ok=True
    )

    estrutura = {
        "projeto": PROJETO,
        "aula": AULA,
        "fonte": "AbuseIPDB",
        "timestamp": agora_utc(),
        "consultas": []
    }

    if ARQUIVO_RESULTADO.exists():

        try:

            with open(
                ARQUIVO_RESULTADO,
                "r",
                encoding="utf-8"
            ) as arquivo:

                existente = json.load(arquivo)

                if isinstance(existente, dict):

                    estrutura = existente

                    if "consultas" not in estrutura:
                        estrutura["consultas"] = []

        except (
            json.JSONDecodeError,
            OSError
        ):

            pass

    estrutura["timestamp"] = agora_utc()

    estrutura["consultas"].append(
        resultado
    )

    with open(
        ARQUIVO_RESULTADO,
        "w",
        encoding="utf-8"
    ) as arquivo:

        json.dump(
            estrutura,
            arquivo,
            indent=4,
            ensure_ascii=False
        )

    return True


# ============================================================
# TESTE DE THREAT INTELLIGENCE
# ============================================================

def executar_teste():

    titulo("ETAPA 3 - TESTE DE THREAT INTELLIGENCE REAL")

    print(
        "A aula realizara uma consulta real "
        "ao AbuseIPDB."
    )

    print()
    print(
        "O objetivo e validar:"
    )

    print("- Conectividade com a API")
    print("- Autenticacao")
    print("- Consulta de reputacao")
    print("- Normalizacao dos dados")
    print("- Classificacao de risco")
    print("- Persistencia do resultado")

    # IP público utilizado apenas para consulta
    # de reputação no laboratório.
    ip_teste = "8.8.8.8"

    print()
    print(
        f"IP utilizado no teste: "
        f"{ip_teste}"
    )

    valido, motivo = validar_ip(
        ip_teste
    )

    if not valido:

        print(
            f"[ERRO] IP rejeitado: "
            f"{motivo}"
        )

        return None

    print(
        f"[OK] {motivo}"
    )

    subtitulo(
        "CONSULTANDO ABUSEIPDB"
    )

    print(
        "Enviando consulta..."
    )

    consulta = consultar_abuseipdb(
        ip_teste
    )

    if consulta["status"] != "SUCESSO":

        print("[ERRO] Consulta falhou")

        print(
            f"Motivo: "
            f"{consulta.get('erro')}"
        )

        if consulta.get(
            "http_status"
        ):

            print(
                f"HTTP Status: "
                f"{consulta['http_status']}"
            )

        return None

    print(
        "[OK] Consulta realizada com sucesso"
    )

    print(
        f"HTTP Status: "
        f"{consulta['http_status']}"
    )

    print(
        f"Tempo de consulta: "
        f"{consulta['tempo_consulta_ms']:.2f} ms"
    )

    dados = consulta["dados"]

    resultado = normalizar_threat_intelligence(
        ip_teste,
        dados
    )

    return resultado


# ============================================================
# VALIDAÇÃO FINAL
# ============================================================

def validacao_final(resultado):

    titulo("VALIDACAO FINAL")

    validacoes = []

    validacoes.append(
        (
            "Arquivo .env encontrado",
            ENV_FILE.exists()
        )
    )

    validacoes.append(
        (
            "API Key carregada",
            bool(ABUSEIPDB_API_KEY)
        )
    )

    validacoes.append(
        (
            "Consulta AbuseIPDB executada",
            resultado is not None
        )
    )

    validacoes.append(
        (
            "Threat Intelligence normalizada",
            resultado is not None
            and "threat_intelligence" in resultado
        )
    )

    validacoes.append(
        (
            "Resultado persistido",
            ARQUIVO_RESULTADO.exists()
        )
    )

    quantidade_ok = 0

    for nome, status in validacoes:

        if status:

            print(
                f"[OK] {nome}"
            )

            quantidade_ok += 1

        else:

            print(
                f"[ERRO] {nome}"
            )

    total = len(validacoes)

    saude = (
        quantidade_ok / total
    ) * 100

    print()

    print(
        f"Validacoes: "
        f"{quantidade_ok}/{total}"
    )

    print(
        f"Saude: "
        f"{saude:.2f}%"
    )

    return quantidade_ok == total


# ============================================================
# MAIN
# ============================================================

def main():

    titulo(
        "AULA 31 - THREAT INTELLIGENCE REAL"
    )

    print(PROJETO)

    print(
        "Integracao com AbuseIPDB"
    )

    print()

    print(
        "Objetivo:"
    )

    print(
        "Enriquecer eventos de seguranca "
        "utilizando inteligencia de ameacas real."
    )

    print()

    # --------------------------------------------------------
    # Diretórios
    # --------------------------------------------------------

    criar_diretorios()

    # --------------------------------------------------------
    # .ENV
    # --------------------------------------------------------

    if not validar_env():

        print()
        print(
            "Status: AULA 31 REQUER ATENCAO"
        )

        sys.exit(1)

    # --------------------------------------------------------
    # API KEY
    # --------------------------------------------------------

    if not validar_api_key():

        print()
        print(
            "Status: AULA 31 REQUER ATENCAO"
        )

        sys.exit(1)

    # --------------------------------------------------------
    # CONSULTA REAL
    # --------------------------------------------------------

    resultado = executar_teste()

    if resultado is None:

        print()

        titulo(
            "AULA 31 NAO CONCLUIDA"
        )

        print(
            "A consulta de Threat Intelligence "
            "nao foi concluida."
        )

        print()

        print(
            "Status: AULA 31 REQUER ATENCAO"
        )

        sys.exit(1)

    # --------------------------------------------------------
    # RESULTADO
    # --------------------------------------------------------

    exibir_resultado(
        resultado
    )

    # --------------------------------------------------------
    # PERSISTÊNCIA
    # --------------------------------------------------------

    titulo(
        "ETAPA 4 - PERSISTINDO THREAT INTELLIGENCE"
    )

    salvar_resultado(
        resultado
    )

    print(
        "[OK] Resultado salvo"
    )

    print(
        f"Arquivo: "
        f"{ARQUIVO_RESULTADO.relative_to(BASE_DIR)}"
    )

    # --------------------------------------------------------
    # VALIDAÇÃO
    # --------------------------------------------------------

    sucesso = validacao_final(
        resultado
    )

    # --------------------------------------------------------
    # RESUMO
    # --------------------------------------------------------

    titulo(
        "RESUMO FINAL DA AULA 31"
    )

    threat = resultado[
        "threat_intelligence"
    ]

    print(
        "Fonte Threat Intelligence: AbuseIPDB"
    )

    print(
        f"IP consultado: "
        f"{resultado['ip']}"
    )

    print(
        f"Abuse Confidence Score: "
        f"{threat['abuse_confidence_score']}%"
    )

    print(
        f"Nivel de risco: "
        f"{threat['nivel_risco']}"
    )

    print(
        f"Reports encontrados: "
        f"{threat['total_reports']}"
    )

    print()

    if sucesso:

        print(
            "Status: AULA 31 CONCLUIDA"
        )

    else:

        print(
            "Status: AULA 31 REQUER ATENCAO"
        )

    titulo(
        "CYBERSENTINEL-ML"
    )

    print(
        "AULA 31 - THREAT INTELLIGENCE REAL"
    )

    if sucesso:

        print(
            "AULA 31 CONCLUIDA"
        )

    else:

        print(
            "AULA 31 REQUER ATENCAO"
        )


# ============================================================
# EXECUÇÃO
# ============================================================

if __name__ == "__main__":
    main()