---
proyecto: SIEM-IA
tags:
  - siem
relacionadas:
  - "[[SIEM-IA - Contexto y problema]]"
  - "[[SIEM-IA - Stack tecnológico]]"
  - "[[SIEM-IA - Dashboard de supervisión]]"
ultima_actualizacion: 2026-06-11
---
# Arquitectura y flujo

Dos capas conectadas por archivos de intercambio.

## Capa SIEM (Elastic Stack, en Docker)

```
Fuentes de log ─▶ Filebeat ─▶ Logstash ─▶ Elasticsearch ─▶ Kibana
(SSH container,   (shipper)   (grok, date,  (almacén +       (reglas,
 /var/log,                     geoip, tags)  reglas de         alertas,
 network_logs/*.json)                        detección)        dashboards)
```

## Capa IA (Python)

```
prepare-for-ia.py ─▶ classifier.py ─▶ siem_agent.py ─▶ dashboard.py
(ES → siem_clean    (Agente 1:        (Agente 2:        (supervisión
 .json)              reglas/umbral)    LLM + fallback)    humana)
                                                              │
                                                              ▼
                                                     decisions.jsonl
                                                     (append-only)
```

## Recorrido de un evento (resumen)

1. El ataque genera logs (auth SSH, o eventos NDJSON de red/web en `network_logs/`).
2. Filebeat los recolecta; Logstash los normaliza (extrae IP/usuario, fija `@timestamp` real,
   GeoIP solo para IPs públicas); Elasticsearch los almacena.
3. Una regla de Kibana dispara una alerta (para el brute force) cuando se supera el umbral.
4. `prepare-for-ia.py` extrae alertas + logs (ventana de 24h + agregación por IP) → `siem_clean.json`.
5. **Agente 1** clasifica el incidente (tipo, severidad, falso positivo) y asigna un playbook de
   acciones con comandos fijos. **Agente 2** lo explica en lenguaje claro (o fallback sin nube).
6. El analista aprueba/descarta cada acción en el dashboard; cada decisión queda registrada de forma
   inmutable.

## Decisiones de diseño

- **Agente 1 determinístico antes del LLM:** etapa rápida, barata y auditable.
- **Comandos del playbook, no del LLM:** un log envenenado por el atacante no puede sugerirle un
  comando malicioso al operador (mitigación de inyección de prompt).
- **Fallback local:** el sistema funciona completo sin enviar datos a la nube (privacidad).
- **La IA sugiere, el humano decide:** nunca hay contención automática.

> Detalle técnico completo y diagramas: `docs/01-arquitectura.md` y `docs/06-flujo-de-datos.md`.
