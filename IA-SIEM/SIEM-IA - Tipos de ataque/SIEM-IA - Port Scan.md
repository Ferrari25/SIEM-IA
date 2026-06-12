---
proyecto: SIEM-IA
tags:
  - nmap
  - ataques
relacionadas:
  - "[[SIEM-IA - Tipos de ataque]]"
  - "[[SIEM-IA - SSH]]"
ultima_actualizacion: 2026-06-11
---
# Port Scan (escaneo de puertos)

## ¿Qué es?

Un **escaneo de puertos** es la fase de **reconocimiento** de un ataque: el atacante sondea muchos
puertos de un host para descubrir qué servicios están abiertos y son potencialmente atacables.
Herramienta típica: **nmap** (`nmap -sT host`). Es lo que un atacante hace *antes* de intentar
entrar — por eso detectarlo temprano da ventaja.

MITRE ATT&CK: **T1046 – Network Service Discovery** (táctica *Discovery*).

## Cómo se detecta en este proyecto

El SIEM no tiene Suricata desplegado, así que el escaneo se materializa como eventos NDJSON en
`network_logs/port-scan.json` (entrada `network-traffic` de Filebeat → Elasticsearch, y también
fuente offline del clasificador).

Regla del **Agente 1** (`classifier.py`, `detect_port_scans`): agrupa los eventos `network_flow`
por IP origen y cuenta **puertos distintos**; si supera el umbral (`PORT_SCAN_DISTINCT_PORTS = 10`)
→ incidente `port_scan` [severidad ALTA].

## Playbook de respuesta (acciones supervisadas)

1. Bloquear la IP escaneadora en el firewall — `sudo ufw deny from <ip>` (SOC, inmediata)
2. Revisar qué puertos quedaron expuestos — `sudo ss -tulnp` (sysadmin, inmediata)
3. Cerrar puertos innecesarios / segmentar (sysadmin, 24h)
4. Desplegar IDS de red (Suricata) para visibilidad futura (SOC, 48h)

## Simulación

Implementada en `simulation/run-port-scan.sh`:

```bash
bash simulation/run-port-scan.sh            # genera logs + nmap real si hay contenedor
bash simulation/run-port-scan.sh --offline  # solo logs (sin Docker)
```

Genera un evento por puerto sondeado:

```json
{"@timestamp":"...","event_type":"network_flow","source_ip":"172.18.0.7",
 "dest_ip":"172.18.0.5","dest_port":22,"protocol":"tcp","action":"probe",
 "tags":["network_traffic","port_scan"],"source_type":"network_traffic"}
```

Ver el flujo completo en `docs/05-simulaciones-de-ataque.md` del repo.
