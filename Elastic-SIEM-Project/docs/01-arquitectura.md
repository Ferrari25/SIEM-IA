# 01 · Arquitectura

El sistema tiene **dos capas** que se conectan por un archivo de intercambio:

1. **Capa SIEM (Elastic Stack)** — recolecta, normaliza, almacena y detecta.
2. **Capa IA (Python)** — clasifica, analiza y presenta para supervisión humana.

```
┌──────────────────────────── CAPA SIEM (Docker) ─────────────────────────────┐
│                                                                              │
│   Fuentes de logs          Filebeat ──▶ Logstash ──▶ Elasticsearch ──▶ Kibana│
│   • contenedores (SSH)     (shipper)    (parseo,      (almacén +      (SIEM, │
│   • /var/log host                        GeoIP,        reglas de       reglas,│
│   • network_logs/*.json                  tags, date)   detección)      alertas)│
│                                                            │                 │
└────────────────────────────────────────────────────────────┼────────────────┘
                                                              │ alertas + logs
                                  prepare-for-ia.py  ◀────────┘ (REST API :9200)
                                          │  siem_clean.json
┌──────────────────────────── CAPA IA (Python) ──────────────▼─────────────────┐
│                                                                              │
│   classifier.py  ──▶  siem_agent.py  ──▶  siem_incidents.json                │
│   (Agente 1:          (Agente 2:                                             │
│    reglas/umbral)      LLM + fallback)         dashboard.py (Flask)          │
│                                                  │   el analista aprueba/     │
│                                                  ▼   descarta cada acción     │
│                                            decisions.jsonl (append-only)      │
└──────────────────────────────────────────────────────────────────────────────┘
```

## Componentes de la capa SIEM

| Servicio | Imagen | Rol |
|----------|--------|-----|
| **elasticsearch** | `elasticsearch:8.12.2` | Almacén de eventos + motor de detección. Seguridad y TLS de transporte activados. |
| **kibana** | `kibana:8.12.2` | UI del SIEM (Security Solution): reglas de detección, alertas, dashboards. |
| **logstash** | `logstash:8.12.2` | Pipeline de normalización: grok de auth SSH, filtro `date`, GeoIP (solo IPs públicas), tags. |
| **filebeat** | `filebeat:8.12.2` | Shipper: logs de contenedores, `/var/log` acotado y `network_logs/*.json`. |
| **setup** | `elasticsearch:8.12.2` | One-shot: fija el password del usuario `kibana_system` para que Kibana autentique. |

### Componentes de simulación (perfil `simulation`)

| Servicio | Imagen | Rol |
|----------|--------|-----|
| **ssh-target** | `linuxserver/openssh-server` | Servidor SSH víctima del brute force. |
| **hydra-attacker** | `ubuntu:22.04` | Contenedor con Hydra (y nmap) para los ataques. |

> No arrancan por defecto. Se levantan con `docker compose --profile simulation up -d`.

## Componentes de la capa IA

| Archivo | Rol |
|---------|-----|
| `siem_lib.py` | Módulo común: config, acceso a ES (queries con ventana temporal + agregación por IP), saneamiento anti-inyección, utilidades JSON/JSONL. |
| `prepare-for-ia.py` | Extrae y limpia alertas + logs de auth desde Elasticsearch → `siem_clean.json`. |
| `classifier.py` | **Agente 1 determinístico.** Reglas/umbral; detecta `ssh_brute_force`, `port_scan`, `credential_harvesting`. Asigna playbook de acciones con comandos fijos. |
| `siem_agent.py` | **Agente 2.** Análisis en lenguaje claro vía LLM (Gemini) con **fallback** determinístico si no hay API/red. |
| `siem_pipeline.py` | Orquestador: encadena prepare → classifier → agent. |
| `dashboard.py` + `templates/index.html` | GUI de supervisión humana (Flask). |

## Decisiones de diseño clave

- **Agente 1 determinístico antes del LLM:** una etapa rápida, barata y auditable
  filtra y clasifica antes de gastar el LLM. "O cumple el patrón o no."
- **Comandos del playbook, no del LLM:** los comandos que ve el operador salen de
  un playbook fijo en `classifier.py`, nunca del LLM. Así un log envenenado por un
  atacante no puede sugerirle al operador un comando malicioso.
- **Fallback sin nube:** si no hay `GEMINI_API_KEY` o falla la red, el análisis se
  genera de forma determinística. El sistema **siempre** produce salida.
- **Supervisión humana con registro inmutable:** las decisiones van a un log
  append-only (`decisions.jsonl`); el estado se reconstruye por *replay*.

## Red y exposición

Todos los servicios viven en la red Docker `elastic-net`. Los puertos publicados
al host están **bindeados a `127.0.0.1`** (no a toda la LAN): `9200` (ES),
`5601` (Kibana), `5044`/`9600` (Logstash), `2222` (ssh-target en simulación).
El dashboard Flask corre en `127.0.0.1:5000`.

Ver el recorrido detallado de un evento en [06 · Flujo de datos](06-flujo-de-datos.md).
