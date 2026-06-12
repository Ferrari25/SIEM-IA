#!/usr/bin/env python3
"""
Dashboard de supervisión humana (Flask).

Toma como entrada los incidentes ya analizados por el pipeline
(`siem_incidents.json`) y los muestra como cards al analista. Cada acción
recomendada tiene botones Aprobar / Descartar. La decisión se registra en un
log append-only (`decisions.jsonl`) — la IA sugiere, el humano decide, y todo
queda auditado e inmutable.

Estado de cada acción = última decisión registrada para su action_id (replay
del log append-only). Reiniciar el server no pierde el estado.

Uso:
    python3 dashboard.py
    # luego abrir http://127.0.0.1:5000
"""

from __future__ import annotations

import os
from pathlib import Path

from flask import Flask, jsonify, render_template, request

from siem_lib import load_json, append_jsonl, read_jsonl, now_iso

INCIDENTS_FILE = "siem_incidents.json"
DECISIONS_FILE = "decisions.jsonl"
ANALYST = os.getenv("ANALYST_NAME", "analista-soc")

app = Flask(__name__)


def _decision_state() -> dict[str, dict]:
    """Replay del log append-only: última decisión por action_id gana."""
    state: dict[str, dict] = {}
    for rec in read_jsonl(DECISIONS_FILE):
        aid = rec.get("action_id")
        if aid:
            state[aid] = rec
    return state


def _load_incidents() -> dict:
    if not Path(INCIDENTS_FILE).exists():
        return {"incidents": [], "analyst_mode": None, "missing": True}
    report = load_json(INCIDENTS_FILE)
    state = _decision_state()
    for inc in report.get("incidents", []):
        for act in inc.get("recommended_actions", []):
            rec = state.get(act["action_id"])
            act["status"] = rec["decision"] if rec else "pending"
            act["decided_by"] = rec.get("analyst") if rec else None
            act["decided_at"] = rec.get("ts") if rec else None
            act["note"] = rec.get("note") if rec else None
    return report


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/incidents")
def api_incidents():
    return jsonify(_load_incidents())


@app.route("/api/decision", methods=["POST"])
def api_decision():
    data = request.get_json(force=True)
    decision = data.get("decision")
    if decision not in ("approved", "dismissed"):
        return jsonify({"error": "decision inválida (approved|dismissed)"}), 400
    if not data.get("action_id") or not data.get("incident_id"):
        return jsonify({"error": "faltan incident_id / action_id"}), 400

    record = {
        "ts": now_iso(),
        "incident_id": data["incident_id"],
        "action_id": data["action_id"],
        "decision": decision,
        "analyst": ANALYST,
        "note": (data.get("note") or "").strip(),
    }
    append_jsonl(DECISIONS_FILE, record)
    return jsonify({"ok": True, "record": record})


@app.route("/api/decisions")
def api_decisions():
    """Historial completo de decisiones (auditoría)."""
    return jsonify(read_jsonl(DECISIONS_FILE))


if __name__ == "__main__":
    print("🛡️  Dashboard de supervisión SIEM-IA  →  http://127.0.0.1:5000")
    print(f"    Analista: {ANALYST}  |  decisiones → {DECISIONS_FILE}")
    app.run(host="127.0.0.1", port=5000, debug=False)
