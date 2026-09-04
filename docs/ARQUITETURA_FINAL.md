# Arquitetura Final - CyberSentinel-ML

## Visão geral

O CyberSentinel-ML é um laboratório SOC defensivo que integra
Machine Learning, Threat Intelligence, correlação, evidência,
decisão, gestão de casos, aprovação e observabilidade.

## Arquitetura

```text
                   CYBERSENTINEL-ML
                          |
                          v
                 MACHINE LEARNING
                    |         |
                    v         v
                 BINARIO   MULTICLASSE
                    |         |
                    +----+----+
                         |
                         v
                EVENT CLASSIFICATION
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

## Lineage principal

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

Regra validada:

```text
Decision.evidence_id == Evidence.evidence_id
```

## Persistência

Banco:

```text
dados/cybersentinel.db
```

Total de tabelas no fechamento:

18

## Machine Learning

Artefatos ML: 4/4

## Observability

Pipeline Health: 100.00%

## End-to-End

Health: 100.00%

Lineages completos: 2

## Testes finais

Executados: 103
Aprovados: 103
Falhas: 0
Cobertura: 100.00%

## Segurança

```text
Execuções reais ............... 0
Bloqueios automáticos ......... 0
Contenção real ................ NAO
Firewall ...................... NAO ALTERADO
Modo operacional .............. SIMULACAO
```

## Princípio arquitetural

```text
DETECCAO
   !=
EVIDENCIA
   !=
DECISAO
   !=
APROVACAO
   !=
EXECUCAO
```

Nenhuma decisão crítica resulta automaticamente
em alteração real de infraestrutura.

## Status

**CYBERSENTINEL-ML CONCLUÍDO**
