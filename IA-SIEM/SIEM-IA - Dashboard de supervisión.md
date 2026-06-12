---
proyecto: SIEM-IA
tipo: componente
estado: 🟢 implementado
area: ia
tags:
  - siem
  - dashboard
  - supervision
  - "#human-in-the-loop"
relacionadas:
  - "[[SIEM-IA - Arquitectura y flujo]]"
  - "[[SIEM-IA - Contexto y problema]]"
ultima_actualizacion: 2026-06-11
---
# Dashboard de supervisión humana

Es la pieza que materializa la idea central del proyecto: **la IA sugiere, el humano decide**. Sin
esto, el sistema sería un análisis automático más; con esto, el analista pasa de *construir* el
análisis a *aprobar o descartar* una recomendación ya elaborada.

## Qué es

Una app **Flask** (`dashboard.py` + `templates/index.html`) que corre en `http://127.0.0.1:5000`.
Lee `siem_incidents.json` (los incidentes ya analizados) y muestra una **card por incidente**.

Por cada incidente: tipo de ataque, severidad ajustada, IP origen/atacante, regla SIEM, técnica
MITRE, probabilidad de falso positivo, y el **análisis en lenguaje claro** (qué pasó, metodología,
riesgo). Una etiqueta indica si lo generó el LLM (`gemini`) o el `fallback`.

Debajo, las **acciones sugeridas**, cada una con responsable, plazo, comando y botones
**Aprobar / Descartar**.

## El registro de decisiones (lo que pedía el contexto)

La nota de contexto decía: *"cada decisión queda registrada... ese historial alimenta al sistema"*.
Acá está: cada click escribe una línea en `decisions.jsonl`, **append-only e inmutable**:

```json
{"ts":"2026-06-11T23:41:51Z","incident_id":"INC-AUTH-...","action_id":"...-a1",
 "decision":"approved","analyst":"analista-soc","note":""}
```

Nunca se sobreescribe. El estado actual de cada acción = la última decisión registrada (replay del
log). Reiniciar el server no pierde nada. Esto da trazabilidad completa (quién, qué, cuándo) — base
para auditoría ISO 27001 y para calibrar el sistema con el tiempo.

## Cómo se usa

```bash
python3 siem_pipeline.py     # genera/actualiza los incidentes
python3 dashboard.py         # abrir http://127.0.0.1:5000
```

Capturas de evidencia en el repo: `screenshots/dashboard-multiataque.png`.
