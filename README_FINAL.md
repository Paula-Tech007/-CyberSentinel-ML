# CyberSentinel-ML

Laboratório educacional de Machine Learning aplicado à Cybersecurity e operações SOC.

> Projeto executado em ambiente controlado e mantido em modo **SIMULAÇÃO**.

## Visão geral

O CyberSentinel-ML integra Machine Learning, Threat Intelligence,
correlação histórica, gerenciamento de incidentes, contexto MITRE ATT&CK,
Evidence Correlation, Decision Engine, Case Management e observabilidade.

O laboratório foi projetado para demonstrar uma arquitetura defensiva,
auditável e segura, sem executar ações destrutivas na infraestrutura.

## Pipeline

```text
Machine Learning
       |
       v
Threat Intelligence
       |
       v
IOC Enrichment
       |
       v
Risk Score V2
       |
       v
Historical Correlation
       |
       v
Campaign Detection
       |
       v
Incident Timeline
       |
       v
Incident Response
       |
       v
MITRE ATT&CK Context
       |
       v
Incident Evidence
       |
       v
SOC Decision Engine
       |
       v
Case Management
       |
       v
Case Lifecycle
       |
       v
Human Approval Gate
       |
       v
Metrics & Observability
       |
       v
End-to-End Validation
       |
       v
Final Test Suite
```

## Principais componentes

- Machine Learning - Binary Classification
- Machine Learning - Multiclass Classification
- JSON / JSONL Ingestion
- REST API
- Batch Processing
- SQLite Persistence
- Operational Observability
- Operational Alerts
- Threat Intelligence
- AbuseIPDB Integration
- IOC Enrichment
- Risk Score V2
- Historical IOC Correlation
- Campaign Detection
- Incident Timeline
- Incident Response Playbooks
- MITRE ATT&CK Context
- Incident Evidence Correlation
- SOC Incident Decision Engine
- SOC Case Management
- SOC Case Lifecycle
- Human Approval Gate
- SOC Metrics & Observability
- Pipeline End-to-End
- Final Validation Test Suite

## Machine Learning

Modelos binário e multiclasse persistidos com Joblib.

Features utilizadas:

- spkts
- dpkts
- sbytes
- dbytes
- rate
- sttl
- dttl
- sload
- dload

## Threat Intelligence

O laboratório inclui enriquecimento de IOC e integração com AbuseIPDB.

Credenciais e chaves devem permanecer em variáveis de ambiente e nunca
devem ser publicadas no repositório.

## Lineage

O vínculo principal validado é:

```text
Decision.evidence_id
        ==
Evidence.evidence_id
```

## MITRE ATT&CK

O mapeamento MITRE é contextual e conservador.
Technique IDs não são atribuídos quando não há evidência suficiente.

O contexto MITRE canônico do End-to-End é obtido do Evidence
referenciado pela Decision.

## Resultados finais

- Testes executados: 103
- Testes aprovados: 103
- Falhas: 0
- Cobertura: 100.00%
- End-to-End Health: 100.00%
- Observability Health: 100.00%
- IOCs ativos: 2

## Segurança operacional

- Execuções reais: 0
- Bloqueios automáticos: 0
- Contenção real: não executada
- Firewall: não alterado
- Modo operacional: SIMULACAO

## Arquivos principais de validação

- `metricas/soc_metrics_aula_45.json`
- `metricas/soc_metrics_aula_45.prom`
- `pipeline/end_to_end_aula_46.json`
- `testes/final_validation_aula_47.json`
- `docs/inventario_tecnico.json`
- `docs/ARQUITETURA_FINAL.md`
- `docs/RESUMO_EXECUTIVO.md`

## Uso responsável

Projeto desenvolvido para treinamento e pesquisa defensiva.

Não realiza bloqueio automático de IP, alteração de firewall
ou contenção operacional real.

## Status

**PROJETO CONCLUÍDO**

Modo final: **SIMULACAO**
