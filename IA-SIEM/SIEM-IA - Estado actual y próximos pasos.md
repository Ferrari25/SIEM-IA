---
proyecto: SIEM-IA
tags:
  - "#proyecto"
  - siem
relacionadas:
  - "[[SIEM-IA - Contexto y problema]]"
  - "[[SIEM-IA - Arquitectura y flujo]]"
  - "[[SIEM-IA - Dashboard de supervisión]]"
ultima_actualizacion: 2026-06-11
---

### ✅ Hecho

- [x] Diseño de arquitectura (capa SIEM + capa IA)
- [x] Stack tecnológico definido
- [x] Setup Docker Compose base (con servicio `setup` que automatiza el password de kibana_system)
- [x] Pipeline Logstash → Elasticsearch (grok auth, filtro `date`, geoip solo IPs públicas)
- [x] Agente 1 — clasificador **determinístico** (`classifier.py`, reglas/umbral + playbook)
- [x] Agente 2 — análisis LLM (Gemini) con **fallback** determinístico sin nube (`siem_agent.py`)
- [x] Dashboard de supervisión humana (Flask) con registro de decisiones append-only
- [x] Tres tipos de ataque detectados y simulados: SSH brute force, port scan, phishing
- [x] Documentación completa del sistema (`docs/`) + auditoría del Council (`outputs/`)

### 🔄 En progreso / decidido

- [x] **LLM:** se usó Gemini, pero la key está en cuota 0 → el **fallback** es hoy el camino real.
- [x] **Frontend:** Flask (MVP), no React — suficiente para la supervisión.
- [ ] Reglas de detección como código (exportar las de Kibana al repo; ya hay un ejemplo en `outputs/`)

### ⏳ Pendiente

- [ ] **Privacidad:** evaluar **Ollama local** vs. Gemini con datos reales y documentar (Ley 25.326)
- [ ] **Orquestación automática:** watcher que dispare el pipeline al aparecer alertas nuevas
- [ ] Suricata para detección de red real (hoy se usa `network_logs/` sintético)
- [ ] Integración Appwrite como orquestador
- [ ] Testing con OWASP Juice Shop (XSS, SQLi, auth bypass)
- [ ] Despliegue en entorno de producción real
- [ ] Entrenamiento ML con datasets de ataques (scikit-learn/TF)

### ❓ Decisiones pendientes

- **Rotación de secretos:** rotar `ELASTIC_PASSWORD`, `KIBANA_SYSTEM_PASSWORD` y `GEMINI_API_KEY`
  (estuvieron expuestas). Considerar limpiar el historial de Git.
- **Appwrite:** definir qué endpoints expone el fork (si se sigue por ese camino).
