---
proyecto: SIEM-IA
relacionadas:
  - "[[SIEM-IA - Arquitectura y flujo]]"
tags:
  - siem
---

## Estructura de microservicios (Docker Compose)

```yaml
# docker-compose.yml — estructura objetivo
services:
  suricata:          # detección de red
  auditd-filebeat:   # logs de sistema
  logstash:          # normalización
  elasticsearch:     # almacenamiento
  kibana:            # visualización SIEM
  redis:             # cola de mensajes
  agente-clasificador:   # Agente 1 — reglas Sigma
  agente-llm:            # Agente 2 — Ollama + modelos
  ollama:                # servidor LLM local
  appwrite:              # orquestador / APIs
  dashboard-frontend:    # React app
  owasp-juice-shop:      # entorno de testing
```
