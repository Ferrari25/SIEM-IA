#!/usr/bin/env python3
"""
Librería común del SIEM-IA.

Centraliza lo que antes estaba duplicado entre get-logs.py y prepare-for-ia.py:
conexión a Elasticsearch, queries con rango temporal, agregación por IP, y
utilidades de archivos (carga JSON, append-only JSONL). También expone helpers
de saneamiento usados antes de mandar datos de logs (no confiables) a un LLM.
"""

from __future__ import annotations

import ipaddress
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests
from requests.auth import HTTPBasicAuth
from dotenv import load_dotenv

load_dotenv()

# Windows: las consolas cp1252 lanzan UnicodeEncodeError al imprimir emojis.
# Forzamos UTF-8 en la salida estandar una sola vez, para todos los scripts que
# importan este modulo (Agente 1, Agente 2, dashboard). No-op en Linux/Mac.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8")
    except Exception:
        pass

# ─── Configuración (desde .env) ──────────────────────────────────────────────

ES_HOST = os.getenv("ES_HOST", "http://localhost:9200")
ES_USER = os.getenv("ES_USER", "elastic")
ES_PASS = os.getenv("ELASTIC_PASSWORD", "elastic123")

LOGS_INDEX   = "filebeat-*"
ALERTS_INDEX = ".alerts-security.alerts-default"

_AUTH    = HTTPBasicAuth(ES_USER, ES_PASS)
_HEADERS = {"Content-Type": "application/json"}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ─── Acceso a Elasticsearch ──────────────────────────────────────────────────

class ESUnavailable(RuntimeError):
    """Elasticsearch no está accesible (stack apagado o credenciales inválidas)."""


def es_search(index: str, query: dict, timeout: int = 10) -> list[dict]:
    """Ejecuta un _search y devuelve la lista de hits (_source ya desempaquetado).

    Lanza ESUnavailable si no se puede conectar, para que el caller decida si
    abortar sin pisar datos previos.
    """
    url = f"{ES_HOST}/{index}/_search"
    try:
        r = requests.post(url, auth=_AUTH, headers=_HEADERS, json=query, timeout=timeout)
        r.raise_for_status()
        return r.json().get("hits", {}).get("hits", [])
    except requests.exceptions.ConnectionError as e:
        raise ESUnavailable(f"No se pudo conectar a Elasticsearch en {ES_HOST}") from e
    except requests.exceptions.HTTPError as e:
        if r.status_code == 404:
            # Índice inexistente todavía: no es un error fatal, no hay datos aún.
            return []
        raise ESUnavailable(f"HTTP {r.status_code} desde Elasticsearch: {e}") from e


def _time_range(window: str) -> dict:
    return {"range": {"@timestamp": {"gte": f"now-{window}", "lte": "now"}}}


def auth_failure_query(size: int, window: str = "24h") -> dict:
    """Logs de autenticación fallida dentro de una ventana temporal."""
    return {
        "size": size,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "_source": ["@timestamp", "message", "host.ip", "host.name",
                    "log.file.path", "tags", "fields", "source_ip", "user"],
        "query": {
            "bool": {
                "filter": [_time_range(window)],
                "must": [{
                    "bool": {
                        "should": [
                            {"match_phrase": {"message": "Failed password"}},
                            {"match_phrase": {"message": "authentication failure"}},
                            {"match_phrase": {"message": "Invalid user"}},
                            {"term": {"tags": "authentication_failure"}},
                        ],
                        "minimum_should_match": 1,
                    }
                }],
                "must_not": [
                    {"match_phrase": {"log.file.path": "Xorg"}},
                    {"match_phrase": {"message": "AMDGPU"}},
                ],
            }
        },
    }


def alerts_query(size: int, window: str = "24h") -> dict:
    return {
        "size": size,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {"bool": {"filter": [_time_range(window)], "must": [{"match_all": {}}]}},
    }


def source_ip_aggregation(window: str = "24h") -> dict:
    """Agrega fallos de auth por IP origen — base del 'historial de la IP en 24h'."""
    return {
        "size": 0,
        "query": {
            "bool": {
                "filter": [_time_range(window)],
                "must": [{"term": {"tags": "authentication_failure"}}],
            }
        },
        "aggs": {
            "by_source_ip": {
                "terms": {"field": "source_ip", "size": 10, "order": {"_count": "desc"}}
            }
        },
    }


def es_aggregate(index: str, query: dict, agg_name: str, timeout: int = 10) -> list[dict]:
    """Devuelve los buckets de una agregación terms."""
    url = f"{ES_HOST}/{index}/_search"
    try:
        r = requests.post(url, auth=_AUTH, headers=_HEADERS, json=query, timeout=timeout)
        r.raise_for_status()
        return r.json().get("aggregations", {}).get(agg_name, {}).get("buckets", [])
    except requests.exceptions.ConnectionError as e:
        raise ESUnavailable(f"No se pudo conectar a Elasticsearch en {ES_HOST}") from e
    except requests.exceptions.HTTPError:
        return []


# ─── Saneamiento (datos de log = contenido NO confiable) ─────────────────────

def is_private_ip(ip: str | None) -> bool:
    if not ip:
        return False
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def sanitize_for_prompt(text: str | None, max_len: int = 300) -> str:
    """Neutraliza contenido de logs antes de incrustarlo en un prompt de LLM.

    El campo `message` de un log SSH lo controla el atacante (ej: el username que
    tipea). Aplastamos saltos de línea y recortamos para reducir la superficie de
    inyección de prompt. La defensa principal sigue siendo la system instruction
    y el esquema estructurado; esto es defensa en profundidad.
    """
    if not text:
        return ""
    flat = " ".join(str(text).split())
    if len(flat) > max_len:
        flat = flat[:max_len] + "…"
    return flat


# ─── Utilidades de archivos ──────────────────────────────────────────────────

def load_json(path: str | Path) -> Any:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"No se encontró '{p}'.")
    with open(p, "r", encoding="utf-8") as f:
        return json.load(f)


def write_json(path: str | Path, data: Any) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def append_jsonl(path: str | Path, record: dict) -> None:
    """Append-only: registro inmutable de eventos/decisiones (nunca se sobreescribe)."""
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def read_jsonl(path: str | Path) -> list[dict]:
    p = Path(path)
    if not p.exists():
        return []
    out = []
    with open(p, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def read_network_logs(dir_path: str | Path = "network_logs") -> list[dict]:
    """Lee todos los eventos NDJSON de network_logs/*.json.

    Es el mismo directorio que Filebeat envía a Elasticsearch (input
    network-traffic). Leerlo localmente permite que el clasificador detecte
    ataques de red/web sin depender del stack levantado (modo demo offline).
    Tolera líneas malformadas para no romper la cadena por un log sucio.
    """
    events: list[dict] = []
    d = Path(dir_path)
    if not d.exists():
        return events
    for f in sorted(d.glob("*.json")):
        with open(f, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return events
