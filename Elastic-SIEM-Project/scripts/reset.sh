#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# reset.sh — Apaga TODO y borra los datos (reset total a cero).
#
# Detiene y elimina todos los contenedores del proyecto (incluida la simulación),
# borra el volumen de datos de Elasticsearch (se pierden índices y alertas) y
# limpia los artefactos locales del pipeline para que el dashboard arranque vacío.
#
# Uso:  ./scripts/reset.sh            (pide confirmación)
#       ./scripts/reset.sh --yes      (sin confirmar)
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail
cd "$(dirname "$0")/.."

if [[ "${1:-}" != "--yes" ]]; then
  echo "⚠️  Esto BORRA el volumen de datos de Elasticsearch (índices + alertas)."
  read -r -p "¿Seguro? [y/N] " ans
  [[ "$ans" =~ ^[yY]$ ]] || { echo "Cancelado."; exit 0; }
fi

echo "🧹 Apagando contenedores y borrando volúmenes..."
docker compose --profile simulation down -v --remove-orphans

echo "🧹 Limpiando artefactos locales del pipeline..."
rm -f siem_clean.json siem_incidents.json decisions.jsonl analysis_history.jsonl ai_report.json
rm -f network_logs/*.json

echo "✅ Reset completo. Todo apagado, datos en cero."
echo "   Levantá de nuevo con:  ./scripts/start.sh"
