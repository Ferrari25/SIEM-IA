#!/usr/bin/env python3
"""
Extrae y limpia datos del SIEM (alertas + logs de auth fallida) dentro de una
ventana temporal, agrega por IP, y genera `siem_clean.json` para el Agente 1.

Si Elasticsearch no está accesible, NO sobreescribe el archivo existente: así no
se pierde la última captura buena (útil para demos con el stack apagado).
"""

from __future__ import annotations

import sys

from siem_lib import (
    ALERTS_INDEX, LOGS_INDEX, ES_HOST, ESUnavailable,
    es_search, es_aggregate, alerts_query, auth_failure_query,
    source_ip_aggregation, write_json, now_iso,
)

OUTPUT_FILE = "siem_clean.json"
WINDOW = "24h"   # ventana temporal de análisis


def parse_alerts(hits: list[dict]) -> list[dict]:
    alerts = []
    for h in hits:
        s = h["_source"]
        threshold = s.get("kibana.alert.threshold_result", {})
        terms = threshold.get("terms") or []
        # threat/technique pueden venir vacíos si la regla no tiene mapeo MITRE.
        threat_list = s.get("kibana.alert.rule.threat") or []
        threat0 = threat_list[0] if threat_list else {}
        tech_list = threat0.get("technique") or []
        tech0 = tech_list[0] if tech_list else {}
        alerts.append({
            "type":        "security_alert",
            "timestamp":   s.get("@timestamp"),
            "alert_id":    (s.get("kibana.alert.uuid", "") or "")[:16] + "...",
            "rule_name":   s.get("kibana.alert.rule.name"),
            "severity":    s.get("kibana.alert.severity"),
            "risk_score":  s.get("kibana.alert.risk_score"),
            "status":      s.get("kibana.alert.status"),
            "reason":      s.get("kibana.alert.reason"),
            "source_ip":   terms[0].get("value") if terms else None,
            "event_count": threshold.get("count"),
            "time_window": {"from": threshold.get("from"), "to": s.get("@timestamp")},
            "mitre": {
                "tactic":       threat0.get("tactic", {}).get("name"),
                "technique":    tech0.get("name"),
                "technique_id": tech0.get("id"),
            },
            "false_positives": s.get("kibana.alert.rule.false_positives", []),
            "rule_query":      s.get("kibana.alert.rule.parameters", {}).get("query"),
        })
    return alerts


def parse_logs(hits: list[dict]) -> list[dict]:
    logs = []
    for h in hits:
        s = h["_source"]
        logs.append({
            "type":        "auth_failure_log",
            "timestamp":   s.get("@timestamp"),
            "message":     s.get("message"),
            "host_ip":     (s.get("host", {}).get("ip") or [None])[0]
                            if isinstance(s.get("host", {}).get("ip"), list)
                            else s.get("host", {}).get("ip"),
            "host_name":   s.get("host", {}).get("name"),
            "log_file":    s.get("log", {}).get("file", {}).get("path"),
            "tags":        s.get("tags", []),
            "source_type": s.get("fields", {}).get("source_type"),
        })
    return logs


def build_summary(alerts: list[dict], logs: list[dict], ip_buckets: list[dict]) -> dict:
    return {
        "total_alerts":        len(alerts),
        "total_auth_failures": len(logs),
        "active_alerts":       sum(1 for a in alerts if a.get("status") == "active"),
        "high_severity":       sum(1 for a in alerts if a.get("severity") == "high"),
        "window":              WINDOW,
        # Historial por IP (agregación de ES) — base del contexto "IP en 24h".
        "top_source_ips":      {b["key"]: b["doc_count"] for b in ip_buckets},
        "mitre_techniques":    sorted({a["mitre"]["technique_id"] for a in alerts
                                       if a.get("mitre", {}).get("technique_id")}),
    }


def main() -> None:
    print(f"Extrayendo datos del SIEM (ventana: {WINDOW}) desde {ES_HOST} ...")
    try:
        alerts     = parse_alerts(es_search(ALERTS_INDEX, alerts_query(size=10, window=WINDOW)))
        logs       = parse_logs(es_search(LOGS_INDEX, auth_failure_query(size=20, window=WINDOW)))
        ip_buckets = es_aggregate(LOGS_INDEX, source_ip_aggregation(WINDOW), "by_source_ip")
    except ESUnavailable as e:
        print(f"[ERROR] {e}")
        print(f"[INFO] No se sobreescribe '{OUTPUT_FILE}' para preservar la última captura.")
        sys.exit(1)

    summary = build_summary(alerts, logs, ip_buckets)
    output = {
        "generated_at": now_iso(),
        "context": "Elastic SIEM - Análisis de seguridad automatizado",
        "summary": summary,
        "alerts": alerts,
        "auth_failure_logs": logs,
    }
    write_json(OUTPUT_FILE, output)

    print(f"\n{'='*50}\n  RESUMEN\n{'='*50}")
    print(f"  Alertas de seguridad : {summary['total_alerts']}")
    print(f"  Alertas activas      : {summary['active_alerts']}")
    print(f"  Severidad alta       : {summary['high_severity']}")
    print(f"  Logs auth fallida    : {summary['total_auth_failures']}")
    print(f"  IPs origen (top)     : {list(summary['top_source_ips'].keys())}")
    print(f"  Técnicas MITRE       : {summary['mitre_techniques']}")
    print(f"\n[OK] JSON limpio guardado en '{OUTPUT_FILE}'.")


if __name__ == "__main__":
    main()
