# CLAUDE.md — Orientación del proyecto (se carga automáticamente cada sesión)

> Este archivo lo lee Claude Code solo al iniciar. Es el punto de entrada: explica
> qué es el proyecto y **dónde está el contexto completo**, sin duplicarlo.

## Qué es

**SIEM-IA:** un Elastic Stack SIEM + una capa de IA con dashboard de supervisión
humana. Un ataque genera logs → Elastic detecta → un Agente 1 determinístico
clasifica → un Agente 2 (LLM con fallback) explica en lenguaje claro → un analista
**aprueba/descarta** cada acción sugerida desde un dashboard, y cada decisión queda
registrada de forma inmutable. Principio rector: **la IA sugiere, el humano decide.**

Ataques contemplados: SSH brute force (T1110), port scan (T1046), phishing/captura
de credenciales (T1566).

## Dónde está el contexto completo (leer según haga falta)

- **`docs/`** — documentación del sistema (la fuente de verdad técnica):
  - `01-arquitectura.md`, `02-requerimientos.md`, `03-instalacion-y-montaje.md`,
    `04-uso-y-ejecucion.md`, `05-simulaciones-de-ataque.md`, `06-flujo-de-datos.md`,
    `07-reglas-de-deteccion.md`, `08-puesta-en-marcha-paso-a-paso.md`.
- **`.claude/claude-context/outputs/auditoria-y-mejoras-2026-06-11.md`** — auditoría
  del Council y changelog completo de todo lo aplicado.
- **`.claude/claude-context/`** — flujo del Council (`CLAUDE.md`), agentes, skills y
  contexto reutilizable. Los entregables del Council van a su carpeta `outputs/`.

## Mapa rápido del código (capa IA)

| Archivo | Rol |
|---------|-----|
| `siem_lib.py` | Módulo común (ES, queries, saneamiento, utils JSON/JSONL). |
| `prepare-for-ia.py` | Extrae alertas + logs de ES → `siem_clean.json`. |
| `classifier.py` | Agente 1 determinístico (reglas/umbral + playbook). |
| `siem_agent.py` | Agente 2 (LLM Gemini con fallback determinístico). |
| `siem_pipeline.py` | Orquestador prepare→classify→analyze. |
| `dashboard.py` + `templates/` | GUI de supervisión (Flask, :5000). |

## Cómo correrlo (resumen — detalle en `docs/08`)

```bash
docker compose up -d                              # stack Elastic (setup automatiza kibana_system)
docker compose --profile simulation up -d         # contenedores de ataque (no arrancan por defecto)
bash simulation/run-brute-force.sh                 # generar ataque
python3 siem_pipeline.py                            # detección → análisis
python3 dashboard.py                                # http://127.0.0.1:5000 → supervisión
# Demo sin Docker:
bash simulation/run-port-scan.sh --offline && python3 siem_pipeline.py && python3 dashboard.py
```

## Notas que ahorran tiempo

- **El LLM (Gemini) está en cuota 0** → el **fallback determinístico** es el camino
  real hoy. El sistema funciona completo offline.
- **Los comandos de respuesta salen del playbook de `classifier.py`, no del LLM**
  (mitigación de inyección de prompt vía logs).
- **`network_logs/*.json`** es la fuente de port scan/phishing (no hay Suricata);
  es a la vez input de Filebeat y fuente offline del clasificador.
- **Secretos:** todo en `.env` (gitignored). Pendiente: rotar `ELASTIC_PASSWORD`,
  `KIBANA_SYSTEM_PASSWORD`, `GEMINI_API_KEY`.

## Flujo del Council

Si el usuario escribe `/council [tarea]` o pide "activar el council", seguir el
flujo de `.claude/claude-context/CLAUDE.md` (leer los 4 agentes, simular el debate,
entregar consenso). Los entregables se guardan en `.claude/claude-context/outputs/`.
