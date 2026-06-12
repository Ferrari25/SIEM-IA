# 04 · Uso y ejecución

Cómo correr la capa IA y supervisar incidentes. Dos modos:

- **Online:** con el stack Elastic levantado; los datos salen de Elasticsearch.
- **Offline (demo):** sin el stack; se usa la última captura `siem_clean.json` y
  los logs que generan las simulaciones en `network_logs/`. El Agente 2 usa el
  fallback determinístico.

## Opción A — Pipeline completo (un comando)

```bash
python3 siem_pipeline.py
```

Encadena las tres etapas:

1. `prepare-for-ia.py` — extrae de Elasticsearch → `siem_clean.json`.
   Si ES no está disponible, **no pisa** el archivo y el pipeline continúa con la
   última captura (modo demo).
2. `classifier.py` — Agente 1: clasifica en incidentes → `siem_incidents.json`.
3. `siem_agent.py` — Agente 2: agrega el análisis en lenguaje claro.

Al terminar imprime los incidentes y te invita a abrir el dashboard.

## Opción B — Etapa por etapa

```bash
python3 prepare-for-ia.py     # ES → siem_clean.json   (requiere stack arriba)
python3 classifier.py         # Agente 1 → siem_incidents.json
python3 siem_agent.py         # Agente 2 → análisis + análisis_history.jsonl
python3 get-logs.py           # (opcional) inspección ad-hoc de ES
```

## El dashboard de supervisión

```bash
python3 dashboard.py
# abrir http://127.0.0.1:5000
```

En el panel, por cada incidente vas a ver:

- **Cabecera:** tipo de ataque, severidad ajustada, IP de origen y atacante, ID.
- **Ficha técnica:** regla SIEM, cantidad de eventos, técnica MITRE, probabilidad
  de falso positivo, ventana temporal.
- **Análisis en lenguaje claro:** qué pasó, metodología del ataque, riesgo en este
  entorno, referencias. Una etiqueta indica si lo generó `gemini` o el `fallback`.
- **Acciones sugeridas:** cada una con responsable, plazo y comando. Botones
  **Aprobar** / **Descartar**.

### Qué pasa cuando decidís

Cada click registra una línea en `decisions.jsonl` (append-only e inmutable) con:
timestamp, incidente, acción, decisión, analista y nota opcional. El estado de
cada acción se reconstruye haciendo *replay* de ese log, así que **reiniciar el
server no pierde las decisiones**. El dashboard se refresca solo cada 15 s.

### Endpoints (por si querés integrarlo)

| Método | Ruta | Qué hace |
|--------|------|----------|
| GET | `/api/incidents` | Incidentes con el estado actual de cada acción. |
| POST | `/api/decision` | Registra una decisión `{incident_id, action_id, decision, note}`. |
| GET | `/api/decisions` | Historial completo de decisiones (auditoría). |

## Modo offline de punta a punta (sin Docker)

```bash
# 1. Generar ataques de red/web como logs detectables
bash simulation/run-port-scan.sh --offline
bash simulation/run-phishing.sh  --offline

# 2. Clasificar + analizar (usa siem_clean.json + network_logs/)
python3 classifier.py && python3 siem_agent.py

# 3. Supervisar
python3 dashboard.py
```

## El LLM (Agente 2)

- Modelo por defecto: `gemini-2.0-flash`. Salida estructurada (JSON) directa, sin
  parsear bloques markdown.
- Si **no hay** `GEMINI_API_KEY`, o la API falla (cuota/red), cada incidente cae al
  **análisis determinístico**. El campo `analyst_mode` y la etiqueta en cada card
  indican qué se usó.
- Mitigación de inyección de prompt: los datos del log se marcan como **no
  confiables** por system instruction y se entregan delimitados; el LLM nunca
  genera comandos (esos vienen del playbook del Agente 1).
