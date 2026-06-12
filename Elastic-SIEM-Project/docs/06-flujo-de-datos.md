# 06 · Flujo de datos

Este documento sigue **un evento** desde que el ataque ocurre hasta que un humano
toma una decisión, nombrando en cada paso el archivo/servicio responsable y la
forma de los datos.

## Vista general

```
 [1] ATAQUE        [2] RECOLECCIÓN     [3] NORMALIZACIÓN   [4] ALMACÉN+DETECCIÓN
 Hydra / nmap  ─▶  Filebeat        ─▶  Logstash        ─▶  Elasticsearch ─▶ alerta
 curl phishing     (filebeat.yml)      (beats.conf)        (regla Kibana)
                                                                  │
                                                                  ▼
 [8] DECISIÓN      [7] SUPERVISIÓN    [6] ANÁLISIS        [5] EXTRACCIÓN
 decisions.jsonl ◀─ dashboard.py  ◀─  classifier.py   ◀─  prepare-for-ia.py
 (append-only)      (Flask GUI)        + siem_agent.py     (siem_clean.json)
```

---

## Paso 1 — El ataque genera logs

- **SSH brute force:** cada intento fallido escribe `Failed password for testuser
  from 172.18.0.7 ...` en el log del contenedor `ssh-target`.
- **Port scan / phishing:** el script de simulación escribe eventos NDJSON en
  `network_logs/*.json` (rol equivalente al de un IDS escribiendo eventos de red).

## Paso 2 — Filebeat recolecta (`filebeat/filebeat.yml`)

Tres inputs:
- `container` → logs de los contenedores Docker (incluye el SSH).
- `filestream` → `/var/log/auth.log`, `syslog`, `messages` (acotado, sin firehose).
- `filestream` (ndjson) → `network_logs/*.json`, marcados `source_type:
  network_traffic`.

Un `drop_event` descarta ruido (GPU/Xorg) **en ingesta**, no después. Filebeat
envía todo a Logstash por el puerto 5044.

## Paso 3 — Logstash normaliza (`logstash/pipeline/beats.conf`)

Para eventos de auth SSH:
1. **grok** extrae `timestamp`, `program`, y reparsea `message` con
   `overwrite => ["message"]` (evita que `message` se vuelva un array).
2. Según el contenido, agrega tag `authentication_failure` /
   `authentication_success` / `invalid_user` y extrae `user` y `source_ip`.
3. **`date`** asigna el timestamp del evento a `@timestamp` (no la hora de
   ingesta) → las ventanas de correlación quedan correctas.
4. **`cidr` + `geoip`**: GeoIP solo para IPs públicas; las privadas
   (Docker/LAN) se saltan para no generar `_geoip_lookup_failure`.

Salida: índice diario `filebeat-<versión>-YYYY.MM.dd` en Elasticsearch.

## Paso 4 — Elasticsearch almacena y la regla detecta

Una **regla de detección** de Kibana (tipo *Threshold*) corre periódicamente: si
una `host.ip` acumula ≥ 3 `authentication_failure` en 5 minutos, crea una alerta
en `.alerts-security.alerts-default` con severidad, risk score y mapeo MITRE
(T1110). (Los ataques de red/web no pasan por una regla de Kibana en este setup;
se detectan en el Paso 6 por el clasificador.)

## Paso 5 — Extracción (`prepare-for-ia.py`)

Consulta la API REST de ES (`:9200`) con **ventana temporal** (`now-24h`):
- alertas de seguridad (`.alerts-security.alerts-default`),
- logs de auth fallida (`filebeat-*`),
- una **agregación por IP** (el "historial de la IP en 24h").

Produce `siem_clean.json` (resumen + alertas + logs). **Si ES no responde, no
sobreescribe** el archivo, para preservar la última captura buena.

```json
{ "summary": { "total_alerts": 3, "top_source_ips": {"172.18.0.5": 722133} },
  "alerts": [ ... ], "auth_failure_logs": [ ... ] }
```

## Paso 6 — Análisis en dos agentes

**Agente 1 — `classifier.py` (determinístico):** arma incidentes desde
`siem_clean.json` (auth/alertas) y desde `network_logs/` (red/web). Aplica reglas
de umbral y asigna tipo (`ssh_brute_force` / `port_scan` /
`credential_harvesting` / `suspicious_auth`), severidad, probabilidad de falso
positivo y un **playbook de acciones con comandos fijos**. Salida:
`siem_incidents.json` (con `analysis: null`).

**Agente 2 — `siem_agent.py` (LLM con fallback):** por cada incidente genera el
análisis en lenguaje claro (explicación, metodología, riesgo, severidad
ajustada, referencias). Usa Gemini con salida estructurada; si no hay key o la
API falla, usa el **fallback determinístico**. Rellena `analysis` en
`siem_incidents.json` y registra la corrida en `analysis_history.jsonl`
(append-only).

```json
{ "incidents": [ {
    "incident_id": "INC-AUTH-172.18.0.5-c42ca785",
    "classification": { "attack_type": "ssh_brute_force", "severity": "critica" },
    "analysis": { "explicacion": "...", "severidad_ajustada": "CRITICAL",
                  "_source": "fallback" },
    "recommended_actions": [
      { "action_id": "...-a1", "accion": "Bloquear la IP ...",
        "comando_sugerido": "sudo ufw deny from 172.18.0.7", "status": "pending" }
    ] } ] }
```

> **Frontera de confianza:** el campo `message` lo controla el atacante. Por eso
> se sanea antes de mandarlo al LLM, el LLM lo trata como dato (no instrucción), y
> **los comandos no los inventa el LLM** sino el playbook del Agente 1.

## Paso 7 — Supervisión humana (`dashboard.py`)

El dashboard lee `siem_incidents.json` y superpone el estado de cada acción
haciendo *replay* de `decisions.jsonl`. Renderiza una card por incidente con
botones **Aprobar / Descartar** por acción.

## Paso 8 — La decisión queda registrada (`decisions.jsonl`)

Cada decisión es una línea **append-only e inmutable**:

```json
{"ts":"2026-06-11T23:41:51Z","incident_id":"INC-AUTH-...","action_id":"...-a1",
 "decision":"approved","analyst":"analista-soc","note":""}
```

Nunca se sobreescribe. El estado actual = la última decisión por `action_id`. Esto
da trazabilidad completa (quién decidió qué y cuándo) — base para auditoría
ISO 27001 y para calibrar el sistema con el tiempo.

---

## Resumen de artefactos

| Archivo | Lo produce | Lo consume | Naturaleza |
|---------|------------|------------|------------|
| `network_logs/*.json` | simulaciones / IDS | Filebeat, classifier | runtime |
| índices `filebeat-*` | Logstash | prepare-for-ia.py | persistente (ES) |
| `.alerts-security.*` | regla Kibana | prepare-for-ia.py | persistente (ES) |
| `siem_clean.json` | prepare-for-ia.py | classifier.py | intercambio |
| `siem_incidents.json` | classifier + agent | dashboard.py | intercambio |
| `decisions.jsonl` | dashboard.py | dashboard.py | append-only (auditoría) |
| `analysis_history.jsonl` | siem_agent.py | — | append-only (auditoría) |
