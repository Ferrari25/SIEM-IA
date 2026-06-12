---
proyecto: SIEM-IA
tipo: proyecto
estado: 🟢 implementado
area: area1
tags:
  - siem
relacionadas:
  - "[[SIEM-IA - Port Scan]]"
  - "[[SIEM-IA - Phishing]]"
  - "[[SIEM-IA - SSH]]"
  - "[[SIEM-IA - Contexto y problema]]"
ultima_actualizacion: 2026-06-11
---
# Tipos de ataque contemplados

El sistema detecta y responde a **tres tipos de ataque**, cada uno con su simulación, su ruta de
detección y su mapeo MITRE. Los tres se ven como incidentes en el dashboard de supervisión.

| Ataque | Nota | MITRE | Detección | Simulación |
|--------|------|-------|-----------|------------|
| Fuerza bruta SSH | [[SIEM-IA - SSH]] | T1110 (Credential Access) | Regla *Threshold* en Kibana + `classifier.py` | `simulation/run-brute-force.sh` |
| Escaneo de puertos | [[SIEM-IA - Port Scan]] | T1046 (Discovery) | `classifier.py` (umbral de puertos distintos) | `simulation/run-port-scan.sh` |
| Phishing / captura de credenciales | [[SIEM-IA - Phishing]] | T1566 (Initial Access) | `classifier.py` (envío de credenciales) | `simulation/run-phishing.sh` |

## Patrón común de detección → respuesta

1. **El ataque genera logs** (auth SSH en contenedor, o eventos NDJSON en `network_logs/`).
2. **Agente 1 (`classifier.py`)** clasifica por reglas/umbral y asigna un playbook de acciones fijas.
3. **Agente 2 (`siem_agent.py`)** explica el incidente en lenguaje claro (LLM o fallback).
4. **El analista** aprueba/descarta cada acción en el dashboard → `decisions.jsonl` (inmutable).

## Cómo agregar un tipo de ataque nuevo

- Generar el log representativo (en `network_logs/` o uno que Filebeat ya recolecte).
- Agregar `detect_<tipo>()` + umbral + playbook en `classifier.py`.
- Agregar la rama del fallback en `siem_agent.py`.
- Documentar acá y crear la nota correspondiente.

Detalle técnico completo: `docs/05-simulaciones-de-ataque.md` y `docs/06-flujo-de-datos.md` del repo.
