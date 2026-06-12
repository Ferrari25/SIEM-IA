#!/usr/bin/env python3
"""
Agente 1 — Clasificador determinístico (sin LLM).

Construye incidentes a partir de dos fuentes y aplica reglas fijas (umbrales,
técnica MITRE) para decidir tipo de ataque, severidad y probabilidad de falso
positivo. "O cumple el patrón o no": etapa rápida, barata y auditable, ANTES de
gastar el LLM.

Fuentes:
  - siem_clean.json        → alertas + logs de auth fallida  (ataques SSH/auth)
  - network_logs/*.json    → eventos de red/web (NDJSON)      (port scan, phishing)
    (es el mismo directorio que Filebeat envía a Elasticsearch; leerlo localmente
     permite detectar sin el stack levantado, en modo demo offline.)

Tipos de ataque soportados: ssh_brute_force, port_scan, credential_harvesting
(phishing), suspicious_auth (sub-umbral), generic.

Cada incidente trae un playbook de acciones con COMANDOS FIJOS (de acá, no del
LLM) para que el operador nunca reciba un comando alucinado o inyectado vía logs.

Salida: `siem_incidents.json` (analysis = null; lo completa el Agente 2).
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

from siem_lib import (
    load_json, write_json, now_iso, sanitize_for_prompt, read_network_logs,
)

SIEM_FILE      = "siem_clean.json"
INCIDENTS_FILE = "siem_incidents.json"

# Umbrales de detección (dentro de la ventana analizada).
BRUTE_FORCE_THRESHOLD   = 20      # fallos de auth → fuerza bruta
CRITICAL_FAILURE_COUNT  = 5000    # por encima → severidad crítica
PORT_SCAN_DISTINCT_PORTS = 10     # puertos distintos sondeados → port scan

_FROM_IP_RE = re.compile(r"from (\d{1,3}(?:\.\d{1,3}){3})")
_USER_RE    = re.compile(r"for (?:invalid user )?(\w+)")


def _incident_id(prefix: str, ip: str, first_seen: str) -> str:
    h = hashlib.sha1(f"{prefix}|{ip}|{first_seen}".encode()).hexdigest()[:8]
    return f"INC-{prefix}-{ip}-{h}"


# ─── Playbooks (acciones con comandos fijos) ─────────────────────────────────

def _playbook(attack_type: str, ip: str | None, user: str | None) -> list[dict]:
    ip = ip or "<IP_ATACANTE>"
    usr = user or "<USUARIO>"

    if attack_type == "ssh_brute_force":
        return [
            {"orden": 1, "accion": "Bloquear la IP atacante en el firewall perimetral",
             "comando_sugerido": f"sudo ufw deny from {ip}",
             "responsable": "SOC", "plazo": "inmediata", "impacto": "alto"},
            {"orden": 2, "accion": "Verificar si hubo algún login EXITOSO desde la IP atacante",
             "comando_sugerido": f"grep 'Accepted password' /var/log/auth.log | grep {ip}",
             "responsable": "sysadmin", "plazo": "inmediata", "impacto": "alto"},
            {"orden": 3, "accion": f"Forzar rotación de credenciales del usuario objetivo ({usr})",
             "comando_sugerido": f"sudo passwd {usr}",
             "responsable": "sysadmin", "plazo": "24h", "impacto": "medio"},
            {"orden": 4, "accion": "Habilitar rate-limiting / fail2ban en el servicio SSH",
             "comando_sugerido": "sudo apt-get install -y fail2ban && sudo systemctl enable --now fail2ban",
             "responsable": "sysadmin", "plazo": "48h", "impacto": "medio"},
        ]

    if attack_type == "port_scan":
        return [
            {"orden": 1, "accion": "Bloquear la IP que realiza el escaneo en el firewall",
             "comando_sugerido": f"sudo ufw deny from {ip}",
             "responsable": "SOC", "plazo": "inmediata", "impacto": "alto"},
            {"orden": 2, "accion": "Revisar qué servicios/puertos quedaron expuestos en el host objetivo",
             "comando_sugerido": "sudo ss -tulnp",
             "responsable": "sysadmin", "plazo": "inmediata", "impacto": "medio"},
            {"orden": 3, "accion": "Cerrar puertos innecesarios y segmentar el host afectado",
             "comando_sugerido": None,
             "responsable": "sysadmin", "plazo": "24h", "impacto": "medio"},
            {"orden": 4, "accion": "Desplegar IDS de red (Suricata) para visibilidad de futuros escaneos",
             "comando_sugerido": None,
             "responsable": "SOC", "plazo": "48h", "impacto": "bajo"},
        ]

    if attack_type == "credential_harvesting":
        return [
            {"orden": 1, "accion": "Dar de baja / bloquear el servidor de phishing (página falsa)",
             "comando_sugerido": f"sudo ufw deny from {ip}",
             "responsable": "SOC", "plazo": "inmediata", "impacto": "alto"},
            {"orden": 2, "accion": f"Forzar reset de credenciales del usuario que envió datos ({usr})",
             "comando_sugerido": f"sudo passwd {usr}",
             "responsable": "sysadmin", "plazo": "inmediata", "impacto": "alto"},
            {"orden": 3, "accion": "Alertar a los usuarios afectados y reforzar concientización",
             "comando_sugerido": None,
             "responsable": "SOC", "plazo": "inmediata", "impacto": "medio"},
            {"orden": 4, "accion": "Agregar el indicador (IP/dominio) a la blocklist / threat intel",
             "comando_sugerido": None,
             "responsable": "SOC", "plazo": "24h", "impacto": "medio"},
        ]

    return [
        {"orden": 1, "accion": "Escalar a analista L2 para revisión manual del evento",
         "comando_sugerido": None, "responsable": "SOC", "plazo": "alta", "impacto": "medio"},
    ]


def _classification(attack_type: str, magnitude: int, detail: str) -> dict:
    table = {
        "ssh_brute_force": {
            "severity": "critica" if magnitude >= CRITICAL_FAILURE_COUNT else "alta",
            "confidence": "alta", "fp": "baja", "mitre": "T1110",
        },
        "port_scan": {
            "severity": "alta", "confidence": "alta", "fp": "baja", "mitre": "T1046",
        },
        "credential_harvesting": {
            "severity": "alta", "confidence": "media", "fp": "media", "mitre": "T1566",
        },
        "suspicious_auth": {
            "severity": "media", "confidence": "media", "fp": "media", "mitre": None,
        },
    }
    t = table.get(attack_type, table["suspicious_auth"])
    return {
        "attack_type": attack_type,
        "confidence": t["confidence"],
        "severity": t["severity"],
        "false_positive_likelihood": t["fp"],
        "rationale": detail,
        "mitre_technique": t["mitre"],
    }


def _finalize(incident_id: str, actions: list[dict]) -> list[dict]:
    for i, act in enumerate(actions, 1):
        act["action_id"] = f"{incident_id}-a{i}"
        act["status"] = "pending"
    return actions


# ─── Detección: SSH / auth ───────────────────────────────────────────────────

def detect_auth_incidents(siem_data: dict) -> list[dict]:
    alerts = siem_data.get("alerts", [])
    logs   = siem_data.get("auth_failure_logs", [])
    incidents: dict[str, dict] = {}

    def ensure(ip: str, ts: str) -> dict:
        if ip not in incidents:
            incidents[ip] = {
                "source_ip": ip, "first_seen": ts, "last_seen": ts,
                "rule_name": None, "severity_siem": None, "risk_score": None,
                "event_count": 0, "mitre": {}, "attacker_ips": set(),
                "target_users": set(), "sample_messages": [], "evidence": [],
            }
        inc = incidents[ip]
        if ts and ts < inc["first_seen"]:
            inc["first_seen"] = ts
        if ts and ts > inc["last_seen"]:
            inc["last_seen"] = ts
        return inc

    for a in alerts:
        ip = a.get("source_ip") or "desconocida"
        inc = ensure(ip, a.get("timestamp", now_iso()))
        inc["rule_name"]     = a.get("rule_name") or inc["rule_name"]
        inc["severity_siem"] = a.get("severity") or inc["severity_siem"]
        inc["risk_score"]    = a.get("risk_score") or inc["risk_score"]
        inc["event_count"]  += a.get("event_count") or 0
        if a.get("mitre"):
            inc["mitre"] = a["mitre"]

    for lg in logs:
        msg = lg.get("message", "") or ""
        host_ip = lg.get("host_ip") or "desconocida"
        inc = ensure(host_ip, lg.get("timestamp", now_iso()))
        m_ip = _FROM_IP_RE.search(msg)
        if m_ip:
            inc["attacker_ips"].add(m_ip.group(1))
        m_user = _USER_RE.search(msg)
        if m_user:
            inc["target_users"].add(m_user.group(1))
        if len(inc["sample_messages"]) < 8:
            inc["sample_messages"].append(sanitize_for_prompt(msg))
        ts = lg.get("timestamp")
        if ts and len(inc["evidence"]) < 12:
            inc["evidence"].append({"ts": ts, "detail": sanitize_for_prompt(msg)})
        if not inc["event_count"]:
            inc["event_count"] += 1

    out: list[dict] = []
    for ip, inc in incidents.items():
        technique = (inc["mitre"] or {}).get("technique_id")
        rule_name = (inc["rule_name"] or "").lower()
        total = inc["event_count"]
        has_failed_pw = bool(inc["attacker_ips"]) or any(
            "failed password" in (e.get("detail", "").lower()) for e in inc["evidence"])
        rule_hint = any(k in rule_name for k in
                        ("brute", "fuerza bruta", "ssh", "auth", "password", "login"))
        # Si el SIEM ya disparó una alerta sobre fallos de auth, es un ataque confirmado:
        # el clasificador no debe degradarlo solo porque el conteo sea menor a su umbral.
        siem_confirmed = bool(inc["rule_name"]) and has_failed_pw
        is_brute = (technique == "T1110" or rule_hint or siem_confirmed
                    or total >= BRUTE_FORCE_THRESHOLD)
        attack_type = "ssh_brute_force" if is_brute else "suspicious_auth"
        if not is_brute:
            detail = (f"{total} fallos de autenticación: por debajo del umbral de "
                      f"{BRUTE_FORCE_THRESHOLD} y sin alerta del SIEM; requiere revisión manual.")
        elif total >= BRUTE_FORCE_THRESHOLD:
            detail = (f"{total} fallos de autenticación desde una misma IP superan el umbral "
                      f"de {BRUTE_FORCE_THRESHOLD}; patrón de fuerza bruta automatizada (T1110).")
        else:
            ip = next(iter(inc["attacker_ips"]), "la misma IP")
            usr = next(iter(inc["target_users"]), "un usuario")
            detail = (f"El SIEM disparó la regla '{inc['rule_name']}': {total} fallos de "
                      f"autenticación desde {ip} contra {usr}; patrón consistente con "
                      f"fuerza bruta SSH (MITRE T1110), confirmado por el SIEM.")
        classification = _classification(attack_type, total, detail)

        attacker_ip = next(iter(inc["attacker_ips"]), None)
        user = next(iter(inc["target_users"]), None)
        incident_id = _incident_id("AUTH", ip, inc["first_seen"])
        actions = _finalize(incident_id, _playbook(attack_type, attacker_ip, user))

        if not inc["mitre"] and classification["mitre_technique"]:
            inc["mitre"] = {"tactic": "Credential Access", "technique": "Brute Force",
                            "technique_id": classification["mitre_technique"]}

        out.append({
            "incident_id": incident_id, "source_ip": ip,
            "attacker_ips": sorted(inc["attacker_ips"]),
            "target_users": sorted(inc["target_users"]),
            "first_seen": inc["first_seen"], "last_seen": inc["last_seen"],
            "rule_name": inc["rule_name"], "severity_siem": inc["severity_siem"],
            "risk_score": inc["risk_score"], "event_count": total,
            "mitre": inc["mitre"], "sample_messages": inc["sample_messages"],
            "evidence": inc["evidence"],
            "classification": classification, "analysis": None,
            "recommended_actions": actions,
        })
    return out


# ─── Detección: port scan (eventos de red) ───────────────────────────────────

def detect_port_scans(events: list[dict]) -> list[dict]:
    flows = [e for e in events if e.get("event_type") in ("network_flow", "port_scan")
             and e.get("source_ip") and e.get("dest_port") is not None]
    by_ip: dict[str, dict] = {}
    for e in flows:
        ip = e["source_ip"]
        b = by_ip.setdefault(ip, {"ports": set(), "dests": set(), "ts": [], "count": 0, "evidence": []})
        b["ports"].add(e.get("dest_port"))
        if e.get("dest_ip"):
            b["dests"].add(e["dest_ip"])
        if e.get("@timestamp"):
            b["ts"].append(e["@timestamp"])
            if len(b["evidence"]) < 12:
                b["evidence"].append({"ts": e["@timestamp"],
                    "detail": f"probe → {e.get('dest_ip','?')}:{e.get('dest_port')}/{e.get('protocol','tcp')}"})
        b["count"] += 1

    out: list[dict] = []
    for ip, b in by_ip.items():
        if len(b["ports"]) < PORT_SCAN_DISTINCT_PORTS:
            continue
        ts_sorted = sorted(b["ts"]) or [now_iso()]
        detail = (f"{len(b['ports'])} puertos distintos sondeados desde {ip} "
                  f"(umbral {PORT_SCAN_DISTINCT_PORTS}); patrón de reconocimiento de red.")
        classification = _classification("port_scan", len(b["ports"]), detail)
        incident_id = _incident_id("SCAN", ip, ts_sorted[0])
        actions = _finalize(incident_id, _playbook("port_scan", ip, None))
        out.append({
            "incident_id": incident_id, "source_ip": ip,
            "attacker_ips": [ip], "target_users": [],
            "first_seen": ts_sorted[0], "last_seen": ts_sorted[-1],
            "rule_name": "Network port scan detection",
            "severity_siem": "high", "risk_score": 47,
            "event_count": b["count"],
            "mitre": {"tactic": "Discovery", "technique": "Network Service Discovery",
                      "technique_id": "T1046"},
            "scanned_ports": sorted(p for p in b["ports"] if p is not None),
            "target_hosts": sorted(b["dests"]),
            "sample_messages": [sanitize_for_prompt(
                f"scan {ip} -> {', '.join(sorted(b['dests']))} puertos {sorted(b['ports'])[:12]}")],
            "evidence": b["evidence"],
            "classification": classification, "analysis": None,
            "recommended_actions": actions,
        })
    return out


# ─── Detección: phishing / credential harvesting (eventos web) ───────────────

def detect_phishing(events: list[dict]) -> list[dict]:
    subs = [e for e in events if e.get("event_type") == "http_request"
            and (e.get("credential_submission") or e.get("password_submitted"))]
    by_ip: dict[str, dict] = {}
    for e in subs:
        ip = e.get("source_ip") or "desconocida"
        b = by_ip.setdefault(ip, {"users": set(), "urls": set(), "dests": set(),
                                   "ts": [], "count": 0, "evidence": []})
        if e.get("username"):
            b["users"].add(e["username"])
        if e.get("url"):
            b["urls"].add(e["url"])
        if e.get("dest_ip"):
            b["dests"].add(e["dest_ip"])
        if e.get("@timestamp"):
            b["ts"].append(e["@timestamp"])
            if len(b["evidence"]) < 12:
                b["evidence"].append({"ts": e["@timestamp"],
                    "detail": f"{e.get('http_method','POST')} {e.get('url','/login')} "
                              f"(user={e.get('username','?')}, creds={'sí' if e.get('credential_submission') or e.get('password_submitted') else 'no'})"})
        b["count"] += 1

    out: list[dict] = []
    for ip, b in by_ip.items():
        ts_sorted = sorted(b["ts"]) or [now_iso()]
        users = ", ".join(sorted(b["users"])) or "usuario(s) desconocido(s)"
        detail = (f"{b['count']} envío(s) de credenciales hacia una página de login "
                  f"sospechosa ({', '.join(sorted(b['urls'])) or '/login'}); posible "
                  f"captura de credenciales (phishing).")
        classification = _classification("credential_harvesting", b["count"], detail)
        incident_id = _incident_id("PHISH", ip, ts_sorted[0])
        user = next(iter(b["users"]), None)
        actions = _finalize(incident_id, _playbook("credential_harvesting", ip, user))
        out.append({
            "incident_id": incident_id, "source_ip": ip,
            "attacker_ips": sorted(b["dests"]) or [ip],
            "target_users": sorted(b["users"]),
            "first_seen": ts_sorted[0], "last_seen": ts_sorted[-1],
            "rule_name": "Credential submission to suspicious login page",
            "severity_siem": "high", "risk_score": 68,
            "event_count": b["count"],
            "mitre": {"tactic": "Initial Access", "technique": "Phishing",
                      "technique_id": "T1566"},
            "phishing_urls": sorted(b["urls"]),
            "sample_messages": [sanitize_for_prompt(
                f"POST {', '.join(sorted(b['urls']))} usuario={users} desde {ip}")],
            "evidence": b["evidence"],
            "classification": classification, "analysis": None,
            "recommended_actions": actions,
        })
    return out


# ─── Orquestación ────────────────────────────────────────────────────────────

def classify(siem_data: dict, network_events: list[dict] | None = None) -> list[dict]:
    network_events = network_events or []
    incidents = (
        detect_auth_incidents(siem_data)
        + detect_port_scans(network_events)
        + detect_phishing(network_events)
    )
    incidents.sort(key=lambda x: x["event_count"], reverse=True)
    return incidents


def main() -> None:
    print("[Agente 1 - Clasificador] Aplicando reglas determinísticas...")
    siem_data = load_json(SIEM_FILE)
    # Eventos de red/web: del propio siem_clean.json (vía ES) o de network_logs/ (offline).
    network_events = siem_data.get("network_events", []) + siem_data.get("web_events", [])
    network_events += read_network_logs("network_logs")

    incidents = classify(siem_data, network_events)

    report = {
        "generated_at": now_iso(),
        "source": SIEM_FILE,
        "incident_count": len(incidents),
        "incidents": incidents,
    }
    write_json(INCIDENTS_FILE, report)

    print(f"  Incidentes detectados: {len(incidents)}")
    for inc in incidents:
        c = inc["classification"]
        print(f"   • {inc['incident_id']}: {c['attack_type']} "
              f"[{c['severity'].upper()}] — {inc['event_count']} eventos")
    print(f"[OK] Clasificación guardada en '{INCIDENTS_FILE}'")


if __name__ == "__main__":
    main()
