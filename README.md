

<img src="assets/cybersentinel-banner.png" width="100%" alt="CyberSentinel-ML">

# 🛡️ CyberSentinel-ML

### Machine Learning + Threat Intelligence + SOC Engineering

![Python](https://img.shields.io/badge/Python-3.x-3776AB?logo=python&logoColor=white)
![Machine Learning](https://img.shields.io/badge/Machine%20Learning-Decision%20Tree-purple)
![FastAPI](https://img.shields.io/badge/API-FastAPI-009688?logo=fastapi&logoColor=white)
![SQLite](https://img.shields.io/badge/Database-SQLite-003B57?logo=sqlite&logoColor=white)
![SOC](https://img.shields.io/badge/SOC-Automation-red)
![Dataset](https://img.shields.io/badge/Dataset-UNSW--NB15-orange)
![MITRE](https://img.shields.io/badge/MITRE-ATT%26CK-red)
![Threat Intelligence](https://img.shields.io/badge/Threat%20Intel-AbuseIPDB-blue)
![Tests](https://img.shields.io/badge/Tests-103%2F103-success)
![Coverage](https://img.shields.io/badge/Coverage-100%25-success)
![Status](https://img.shields.io/badge/Status-Completed-success)
![Security](https://img.shields.io/badge/Mode-Simulation-blueviolet)

**Cybersecurity • Machine Learning • Threat Intelligence • Detection Engineering • SOC Automation**

`Project Health: 100%` • `103/103 Tests` • `End-to-End: 100%` • `Mode: SIMULATION`



---

# 🔎 Visão Geral

**CyberSentinel-ML** é um laboratório defensivo de Machine Learning aplicado à Segurança Cibernética, criado para demonstrar uma arquitetura SOC completa de detecção, enriquecimento, correlação, análise, tomada de decisão, gerenciamento de casos e observabilidade.

O projeto utiliza o dataset **UNSW-NB15** e modelos baseados em `DecisionTreeClassifier`.

O laboratório começou com classificação binária de tráfego:

```text
NORMAL
   ou
ATAQUE
```

e evoluiu para uma arquitetura End-to-End com:

- classificação binária;
- classificação multiclasse;
- REST API;
- JSON / JSONL;
- processamento em lote;
- persistência SQLite;
- Threat Intelligence;
- AbuseIPDB;
- IOC Enrichment;
- Risk Score V2;
- Historical IOC Correlation;
- Campaign Detection;
- Incident Timeline;
- Incident Response Playbooks;
- MITRE ATT&CK;
- Incident Evidence Correlation;
- SOC Decision Engine;
- Case Management;
- Case Lifecycle;
- Human Approval Gate em simulação;
- Metrics & Observability;
- End-to-End Validation;
- Final Test Suite;
- Project Closure.

A arquitetura segue um princípio importante:

```text
DETECÇÃO
   !=
EVIDÊNCIA
   !=
DECISÃO
   !=
APROVAÇÃO
   !=
EXECUÇÃO
```

> ⚠️ **Projeto educacional, defensivo e de laboratório**
>
> Todas as ações de resposta permanecem em modo de **SIMULAÇÃO**.
>
> O projeto não executa bloqueios automáticos, não altera firewall e não realiza contenção real.

---

# 🧠 Arquitetura End-to-End

```text
                         CYBERSENTINEL-ML
                                |
                                v
                         EVENTO DE REDE
                                |
                                v
                           API / INGESTÃO
                                |
                                v
                        MACHINE LEARNING
                          |           |
                          v           v
                       BINÁRIO     MULTICLASSE
                          |           |
                          +-----+-----+
                                |
                                v
                         CLASSIFICAÇÃO
                                |
                                v
                       THREAT INTELLIGENCE
                                |
                                v
                         IOC ENRICHMENT
                                |
                                v
                          RISK SCORE V2
                                |
                                v
                    HISTORICAL CORRELATION
                                |
                                v
                       CAMPAIGN DETECTION
                                |
                                v
                        INCIDENT TIMELINE
                                |
                                v
                       INCIDENT RESPONSE
                                |
                                v
                      MITRE ATT&CK CONTEXT
                                |
                                v
                       INCIDENT EVIDENCE
                                |
                                v
                      SOC DECISION ENGINE
                                |
                                v
                         CASE MANAGEMENT
                                |
                                v
                          CASE LIFECYCLE
                                |
                                v
                        HUMAN APPROVAL GATE
                                |
                                v
                     METRICS & OBSERVABILITY
                                |
                                v
                     END-TO-END VALIDATION
                                |
                                v
                        FINAL TEST SUITE
                                |
                                v
                         PROJECT CLOSURE
```

---

# 🤖 Machine Learning Engine

O núcleo de detecção utiliza modelos supervisionados treinados sobre dados do **UNSW-NB15**.

## Configuração do modelo binário

| Parâmetro | Valor |
|---|---|
| Dataset | UNSW-NB15 |
| Algoritmo | DecisionTreeClassifier |
| `max_depth` | 5 |
| Threshold | 0.099 |
| Features | 9 |
| Classificação | Binária |
| Classes | NORMAL / ATAQUE |

---

## 📊 Performance do modelo binário

| Métrica | Resultado |
|---|---:|
| 🎯 Accuracy | **92.42%** |
| 🔥 Recall | **99.55%** |
| 📌 Precision | **90.30%** |
| ⚡ F1-Score | **94.70%** |
| ❌ Falsos Negativos | **540** |
| ⚠️ Falsos Positivos | **12.755** |

Threshold:

```text
0.099
```

A configuração prioriza sensibilidade de detecção, buscando reduzir ataques classificados incorretamente como tráfego normal.

---

# 🧬 Classificação Multiclasse

Além da classificação binária, o projeto possui classificação multiclasse de categorias de ataque.

Artefatos versionados:

```text
modelos/configuracao_multiclasse_aula_22.joblib
modelos/configuracao_multiclasse_otimizada_aula_22.joblib
modelos/unsw_attack_multiclass_otimizado.joblib
```

O modelo multiclasse original:

```text
modelos/unsw_attack_multiclass.joblib
```

possui aproximadamente **157 MB** e não é versionado no GitHub devido ao limite padrão de tamanho por arquivo.

O modelo otimizado permanece disponível no repositório.

---

# 🔬 Features utilizadas

```text
01. spkts
02. dpkts
03. sbytes
04. dbytes
05. rate
06. sttl
07. dttl
08. sload
09. dload
```

Esses atributos são utilizados na classificação dos eventos de rede.

---

# ⚡ API de Detecção

O modelo pode ser consumido através de uma API REST construída com **FastAPI**.

## Endpoint

```http
POST /detectar
```

## Exemplo de evento

```json
{
  "spkts": 10,
  "dpkts": 2,
  "sbytes": 1500,
  "dbytes": 200,
  "rate": 120.0,
  "sttl": 254,
  "dttl": 64,
  "sload": 50000.0,
  "dload": 3000.0
}
```

## Exemplo de resposta

```json
{
  "classificacao": "ATAQUE",
  "probabilidade_ataque": 0.406258,
  "probabilidade_percentual": 40.63,
  "threshold": 0.099,
  "nivel_risco": "MEDIO",
  "modelo": "DecisionTreeClassifier"
}
```

---

# 🚨 Detection & Alert Engine

Eventos classificados como suspeitos podem gerar alertas SOC.

```text
NETWORK EVENT
      |
      v
 ML DETECTION
      |
      v
   ATTACK?
    |    |
   NÃO  SIM
    |    |
    v    v
 NORMAL ALERT
```

Os alertas preservam:

- ID do evento;
- timestamp;
- classificação;
- probabilidade;
- nível de risco;
- modelo utilizado;
- threshold;
- características originais.

---

# 📡 JSON / JSONL & Batch Processing

O CyberSentinel-ML suporta:

- JSON;
- JSONL;
- ingestão de eventos;
- processamento em lote;
- validação estrutural;
- eventos rejeitados;
- integração com o pipeline de ML.

```text
JSON / JSONL
      |
      v
  VALIDATION
      |
      v
API / BATCH PIPELINE
      |
      v
 MACHINE LEARNING
      |
      v
    SOC EVENT
```

---

# 💾 Persistência SQLite

O banco principal é:

```text
dados/cybersentinel.db
```

Durante a Aula 48 foram inventariadas **18 tabelas antes da criação do registro de Project Closure**.

Entre as principais estruturas estão:

```text
alertas
alertas_operacionais
baselines_operacionais
campanhas_ioc
correlacao_ioc_eventos
eventos
incident_evidence
incident_response_playbooks
incident_timelines
metricas
mitre_attack_mapping
soc_case_transitions
soc_end_to_end_runs
soc_final_validation_runs
soc_human_approvals
soc_incident_cases
soc_incident_decisions
soc_observability_snapshots
```

Na etapa final também é criada:

```text
soc_project_closure
```

---

# 📉 Operational Baseline

O projeto implementa uma camada de baseline para acompanhar comportamento operacional e apoiar observabilidade.

Essa etapa permite comparar o estado atual com referências anteriores e identificar mudanças relevantes no pipeline.

---

# 🌐 Threat Intelligence

O CyberSentinel-ML integra Threat Intelligence externo utilizando **AbuseIPDB**.

O enriquecimento pode considerar:

```text
IOC
Abuse Confidence Score
Reports
Reputação
Histórico
Recorrência
Contexto
```

Credenciais são carregadas através de variável de ambiente.

> Nunca publique chaves de API no repositório.

---

# 🔎 IOC Enrichment

Fluxo simplificado:

```text
IOC
 |
 v
THREAT INTELLIGENCE
 |
 v
REPUTATION
 |
 v
CONTEXT ENRICHMENT
 |
 v
RISK ENGINE
```

O objetivo é adicionar contexto externo sem substituir os sinais produzidos pelas demais camadas.

---

# 🎯 Risk Score V2

O Risk Score V2 combina informações como:

```text
Machine Learning
Threat Intelligence
Reputação
Recorrência
Contexto
Correlação histórica
Categoria
```

Invariante:

```text
0 <= Risk Score <= 100
```

---

# 🔗 Historical IOC Correlation

O pipeline mantém histórico de eventos relacionados a IOCs.

```text
IOC
 |
 +--> EVENTO 1
 |
 +--> EVENTO 2
 |
 +--> EVENTO 3
 |
 v
HISTORICAL CORRELATION
```

A correlação acrescenta contexto sobre recorrência e evolução do risco.

---

# 🕸️ Campaign Detection

Eventos recorrentes de um mesmo IOC podem ser agrupados para identificar possível atividade de campanha.

Cenário validado:

```text
IOC: 8.8.8.8

Eventos: 3
Categorias: 3
Campaign Score: 85/100
Nível: CRÍTICO
Status: CAMPANHA_DETECTADA
```

---

# 🕒 Incident Timeline

O projeto cria timelines para representar evolução temporal.

```text
PRIMEIRO EVENTO
      |
      v
EVENTOS INTERMEDIÁRIOS
      |
      v
EVENTO DE MAIOR RISCO
      |
      v
INCIDENT TIMELINE
```

São avaliados:

- primeiro score;
- score final;
- score máximo;
- variação;
- tendência;
- evolução temporal.

---

# 📕 Incident Response Playbooks

O CyberSentinel-ML possui playbooks defensivos simulados.

Exemplos:

```text
✓ Abrir incidente
✓ Validar IOC
✓ Investigar timeline
✓ Correlacionar campanha
✓ Preservar evidências
✓ Escalar para analista
✓ Preparar contenção
✓ Notificar responsável
```

Importante:

```text
PREPARAR CONTENÇÃO
       !=
EXECUTAR CONTENÇÃO
```

Modo:

```text
SIMULAÇÃO
```

---

# 🧬 MITRE ATT&CK

O pipeline contextualiza eventos utilizando **MITRE ATT&CK**.

O mapeamento é conservador.

Exemplos:

```text
DoS

Contexto: IMPACTO
Tática: Impact
Confiança: CONTEXTUAL
```

```text
Shellcode

Contexto: EXECUCAO_POTENCIAL
Tática: Execution
Confiança: CONTEXTUAL
```

O projeto não inventa Technique IDs quando a evidência é insuficiente.

---

# 🧾 Incident Evidence Correlation

Diversas fontes são consolidadas em uma camada de evidência:

```text
Historical Correlation
Campaign Detection
Incident Timeline
Incident Response
MITRE Context
        |
        v
INCIDENT EVIDENCE
```

O **Evidence Score** representa força de contexto correlacionado.

Ele não representa diretamente probabilidade de ataque.

## Cenários validados

### IOC de menor risco

```text
IOC: 1.1.1.1
Evidence Score: 18
Nível: BAIXO
```

### IOC crítico

```text
IOC: 8.8.8.8
Evidence Score: 92
Nível: CRÍTICO
```

---

# 🔗 Lineage e Rastreabilidade

Uma das regras mais importantes do projeto:

```text
Decision.evidence_id
        ==
Evidence.evidence_id
```

Cadeia:

```text
Decision
   |
   +-- evidence_id
           |
           v
       Evidence
           |
           +-- evidence_score
           +-- mitre_contexto
           +-- mitre_tatica
           +-- mitre_confianca
```

Isso permite rastrear uma decisão até a evidência correspondente.

---

# ⚙️ SOC Decision Engine

O Decision Engine combina:

- Evidence Score;
- Risk Score;
- Campaign Detection;
- Timeline;
- MITRE Context;
- prioridade;
- SLA;
- necessidade de analista;
- escalonamento;
- preparação de contenção.

## Cenário crítico

```text
IOC: 8.8.8.8

Evidence Score: 92
Decision Score: 92.15
Prioridade SOC: CRÍTICO
Classificação: INCIDENTE_PRIORITARIO
Ação: ESCALAR_E_PREPARAR_CONTENCAO
SLA: IMEDIATO
```

## Cenário de menor risco

```text
IOC: 1.1.1.1

Evidence Score: 18
Decision Score: 25.50
Prioridade SOC: BAIXO
Classificação: MONITORAMENTO
Ação: MONITORAR_E_REGISTRAR
```

Regra:

```text
AUTO BLOCK: NÃO
```

---

# 📂 SOC Case Management

Decisões SOC podem originar casos para acompanhamento.

Cada caso pode incluir:

```text
Case ID
IOC
Evidence
Decision
Risk Score
Priority
Status
Phase
Owner
SLA
History
```

---

# 🔄 Case Lifecycle

As mudanças de estado são persistidas.

```text
CASE
 |
 v
TRIAGEM
 |
 v
ESCALONAMENTO
 |
 v
APROVAÇÃO
 |
 v
ACOMPANHAMENTO
```

Tabela:

```text
soc_case_transitions
```

---

# 👤 Human Approval Gate

O projeto registra uma camada de aprovação simulada antes de ações sensíveis.

Princípio:

```text
DECISÃO
   |
   v
APROVAÇÃO
   |
   v
AÇÃO AUTORIZADA

AÇÃO AUTORIZADA
   !=
EXECUÇÃO REAL
```

No laboratório:

```text
Aprovações registradas ..... 1
Execuções reais ............ 0
Bloqueios automáticos ...... 0
Modo ....................... SIMULAÇÃO
```

---

# 📈 Metrics & Observability

A camada de observabilidade acompanha:

```text
IOC Correlation
Campaign Detection
Timeline
Incident Response
MITRE
Evidence
Decision Engine
Case Management
Lifecycle
Human Approval
Security Invariants
```

Resultado:

```text
Observability Health ....... 100%
IOCs ativos ................ 2
```

Arquivos:

```text
metricas/soc_metrics_aula_45.json
metricas/soc_metrics_aula_45.prom
```

---

# 🔁 End-to-End Validation

A validação End-to-End verifica integridade entre as camadas.

```text
Artefatos ML ............... 4/4
Componentes ................ 11/11
IOCs ativos ................ 2
Lineages completos ......... 2/2

Decision -> Evidence ....... SIM
MITRE consistente .......... SIM

End-to-End Health .......... 100%
```

Arquivo:

```text
pipeline/end_to_end_aula_46.json
```

---

# 🧪 Final Test Suite

A bateria final valida:

```text
✓ Ambiente
✓ Machine Learning
✓ SQLite
✓ Schemas
✓ IOCs
✓ Scores
✓ Decision -> Evidence
✓ MITRE
✓ Case Management
✓ Lifecycle
✓ Human Approval
✓ Observability
✓ End-to-End
✓ Arquivos
✓ JSON
✓ Segurança
```

Resultado:

```text
Testes executados .......... 103
Testes aprovados ........... 103
Falhas ..................... 0
Cobertura .................. 100.00%
```

Arquivo:

```text
testes/final_validation_aula_47.json
```

---

# 🏁 Project Closure

Resultados consolidados:

```text
Artefatos ML ............... 4/4
IOCs ativos ................ 2

Observability Health ....... 100%
End-to-End Health .......... 100%
Lineages completos ......... 2

Decision -> Evidence ....... SIM
MITRE consistente .......... SIM

Testes finais .............. 103/103
Falhas ..................... 0
Cobertura .................. 100%

Execuções reais ............ 0
Bloqueios automáticos ...... 0
Modo operacional ........... SIMULAÇÃO
```

Validações da Aula 48:

```text
28/28
```

Project Health:

```text
100.00%
```

Status:

```text
PROJETO CONCLUÍDO
```

---

# 🛠️ Stack

| Tecnologia | Aplicação |
|---|---|
| 🐍 Python | Core do projeto |
| 🤖 Scikit-learn | Machine Learning |
| 🌳 Decision Tree | Classificação |
| ⚡ FastAPI | API REST |
| 🚀 Uvicorn | Servidor ASGI |
| 🐼 Pandas | Processamento de dados |
| 💾 Joblib | Persistência dos modelos |
| 🗄️ SQLite | Persistência operacional |
| 📄 JSON | Eventos e artefatos |
| 📜 JSONL | Ingestão contínua |
| 📊 CSV | Resultados |
| 🌐 AbuseIPDB | Threat Intelligence |
| 🧬 MITRE ATT&CK | Contextualização |
| 📈 Prometheus-style Metrics | Observabilidade |

---

# 📁 Estrutura do projeto

```text
CyberSentinel-ML/
│
├── assets/
├── alertas/
├── aprovacoes/
├── campanhas/
├── casos/
├── correlacao/
├── dados/
├── decisoes/
├── docs/
├── eventos/
├── evidencias/
├── iocs/
├── metricas/
├── mitre/
├── modelos/
├── pipeline/
├── playbooks/
├── risk_scores/
├── testes/
├── threat_intel/
├── timelines/
│
├── aula_03.py
├── aula_04.py
├── ...
├── aula_21.py
├── ...
├── aula_46.py
├── aula_47.py
├── aula_48.py
│
├── evento.json
├── .gitignore
├── README.md
└── README_FINAL.md
```

---

# 📚 Documentação Técnica

Documentação final:

```text
README_FINAL.md
docs/ARQUITETURA_FINAL.md
docs/RESUMO_EXECUTIVO.md
docs/inventario_tecnico.json
alertas/relatorio_aula_48.json
```

Validações:

```text
metricas/soc_metrics_aula_45.json
metricas/soc_metrics_aula_45.prom
pipeline/end_to_end_aula_46.json
testes/final_validation_aula_47.json
```

---

# 🚀 Como executar

## 1. Clone o repositório

```bash
git clone https://github.com/Paula-Tech007/CyberSentinel-ML.git
```

Entre na pasta:

```bash
cd CyberSentinel-ML
```

---

## 2. Crie o ambiente virtual

```bash
python -m venv .venv
```

### Windows / PowerShell

```powershell
.\.venv\Scripts\Activate.ps1
```

---

## 3. Instale as dependências principais

```bash
pip install pandas scikit-learn fastapi uvicorn joblib requests python-dotenv
```

---

## 4. Configure variáveis de ambiente

Crie localmente:

```text
.env
```

Exemplo:

```text
ABUSEIPDB_API_KEY=SUA_CHAVE_LOCAL
```

> Nunca publique o valor real da chave.

---

## 5. Execute a API

```bash
uvicorn aula_08:app --reload
```

Swagger:

```text
http://127.0.0.1:8000/docs
```

Health check:

```text
http://127.0.0.1:8000/health
```

---

# 🛡️ Segurança do repositório

O `.gitignore` protege arquivos locais e sensíveis.

Exemplo:

```gitignore
.venv/
venv/
__pycache__/
*.pyc

.env
.env.*
!.env.example

*.pem
*.key
*.p12
*.pfx

*.credentials
*.secret
*.secrets

.vscode/
.idea/

modelos/unsw_attack_multiclass.joblib
```

O modelo de aproximadamente 157 MB permanece local e fora do GitHub.

---

# 🔐 Security by Design

```text
NO REAL BLOCKING

NO DESTRUCTIVE RESPONSE

NO PRODUCTION CREDENTIALS

NO AUTOMATIC FIREWALL CHANGES

NO REAL CONTAINMENT

RESPONSE MODE:

SIMULATION
```

Pipeline conceitual:

```text
DETECT
   |
   v
ENRICH
   |
   v
CORRELATE
   |
   v
EVIDENCE
   |
   v
DECIDE
   |
   v
APPROVE
   |
   v
OBSERVE
```

---

# 🗺️ Roadmap

## ✅ Capacidades concluídas

- [x] Machine Learning
- [x] Detecção binária
- [x] Detecção multiclasse
- [x] Comparação entre modelos ML
- [x] Threshold customizado
- [x] Persistência dos modelos
- [x] API REST
- [x] JSON / JSONL
- [x] Batch Processing
- [x] Alert Engine
- [x] Persistência SQLite
- [x] Operational Metrics
- [x] Operational Baseline
- [x] Threat Intelligence externo
- [x] AbuseIPDB
- [x] Machine Learning + Threat Intelligence
- [x] IOC Enrichment
- [x] Risk Score V2
- [x] Historical IOC Correlation
- [x] Campaign Detection
- [x] Incident Timeline
- [x] Incident Response
- [x] MITRE ATT&CK Mapping
- [x] Incident Evidence Correlation
- [x] SOC Decision Engine
- [x] Case Management
- [x] Case Lifecycle
- [x] Human Approval Gate em simulação
- [x] Metrics & Observability
- [x] End-to-End Validation
- [x] Testes automatizados
- [x] Final Test Suite — 103/103
- [x] Documentação final
- [x] Project Closure

## 🔭 Possíveis evoluções futuras

- [ ] Elasticsearch Integration
- [ ] Grafana Dashboards
- [ ] Dashboard SOC Web
- [ ] Dockerização completa
- [ ] SIEM Integration
- [ ] SOAR Integration
- [ ] CI/CD com GitHub Actions

---

# 📈 System Status

```text
╔══════════════════════════════════════════════════╗
║              CYBERSENTINEL-ML                    ║
╠══════════════════════════════════════════════════╣
║                                                  ║
║ ML BINARY ...................... READY            ║
║ ML MULTICLASS .................. READY            ║
║ REST API ....................... READY            ║
║ JSON / JSONL ................... READY            ║
║ SQLITE ......................... READY            ║
║ THREAT INTELLIGENCE ............ READY            ║
║ IOC ENRICHMENT ................. READY            ║
║ RISK SCORE ..................... READY            ║
║ CORRELATION .................... READY            ║
║ CAMPAIGN DETECTION ............. READY            ║
║ INCIDENT TIMELINE .............. READY            ║
║ INCIDENT RESPONSE .............. READY            ║
║ MITRE ATT&CK ................... READY            ║
║ EVIDENCE CORRELATION ........... READY            ║
║ SOC DECISION ENGINE ............ READY            ║
║ CASE MANAGEMENT ................ READY            ║
║ CASE LIFECYCLE ................. READY            ║
║ HUMAN APPROVAL ................. SIMULATED        ║
║ OBSERVABILITY .................. READY            ║
║ END-TO-END ..................... 100%             ║
║ FINAL TEST SUITE ............... 103/103          ║
║                                                  ║
║ PROJECT HEALTH ................. 100%             ║
║                                                  ║
║ SYSTEM STATUS .................. COMPLETED        ║
║                                                  ║
╚══════════════════════════════════════════════════╝
```

---

# 🏆 Resultados Finais

| Indicador | Resultado |
|---|---:|
| Artefatos ML finais | **4/4** |
| IOCs ativos | **2** |
| Tabelas inventariadas antes do closure | **18** |
| Observability Health | **100%** |
| End-to-End Health | **100%** |
| Lineages completos | **2/2** |
| Decision → Evidence | **SIM** |
| MITRE consistente | **SIM** |
| Testes finais | **103/103** |
| Falhas | **0** |
| Cobertura | **100%** |
| Validações de fechamento | **28/28** |
| Project Health | **100%** |
| Execuções reais | **0** |
| Bloqueios automáticos | **0** |
| Modo operacional | **SIMULAÇÃO** |

---

# 🎯 Objetivo Educacional

O CyberSentinel-ML foi desenvolvido como laboratório de estudo e portfólio para demonstrar conhecimentos em:

- Machine Learning aplicado à Cybersecurity;
- Detection Engineering;
- SOC Engineering;
- Threat Intelligence;
- Incident Response;
- Security Automation;
- IOC Analysis;
- Risk Scoring;
- MITRE ATT&CK;
- Evidence Correlation;
- Case Management;
- Observability;
- End-to-End Validation;
- Security by Design.

---

# ⚠️ Uso Responsável

Este projeto possui finalidade **educacional, defensiva e de pesquisa**.

Não deve ser utilizado para:

- atacar sistemas de terceiros;
- explorar ambientes sem autorização;
- comprometer serviços;
- realizar contenção ou bloqueios fora de ambiente autorizado.

Todas as etapas de resposta foram desenvolvidas e validadas em ambiente controlado.

---

<div align="center">

# 👩‍💻 Paula Sabino

### Cybersecurity • Machine Learning • Security Automation • SOC

Projeto desenvolvido como laboratório prático de aplicação de **Machine Learning em operações defensivas de Segurança Cibernética**.

<br>

## 🛡️ CyberSentinel-ML

### From Network Events to SOC Decisions

`DETECT` → `ENRICH` → `CORRELATE` → `EVIDENCE` → `DECIDE` → `APPROVE` → `OBSERVE`

<br>

### ✅ PROJECT COMPLETED

**103/103 Tests • 100% Coverage • 100% End-to-End Health**

**Defensive Security • Machine Learning • SOC Engineering**

