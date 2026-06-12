---
proyecto: SIEM-IA
tags:
  - phising
  - ataques
relacionadas:
  - "[[SIEM-IA - Tipos de ataque]]"
ultima_actualizacion: 2026-06-11
---
# Phishing / captura de credenciales

## ¿Qué es?

El **phishing** presenta a la víctima una página falsa que imita un login legítimo. Cuando la
víctima ingresa usuario y contraseña, el atacante los **captura**. A diferencia de la fuerza bruta
(que adivina), acá la víctima *entrega* la credencial creyendo que es real.

MITRE ATT&CK: **T1566 – Phishing** (táctica *Initial Access*). El peligro: la credencial capturada
da acceso con identidad válida, evadiendo controles que asumen que el usuario es legítimo.

## Cómo se detecta en este proyecto

Los envíos de credenciales se registran como eventos web NDJSON en `network_logs/phishing.json`.

Regla del **Agente 1** (`classifier.py`, `detect_phishing`): busca eventos `http_request` con
`credential_submission: true` (o `password_submitted`) y los agrupa por IP → incidente
`credential_harvesting` [severidad ALTA].

## Playbook de respuesta (acciones supervisadas)

1. Dar de baja / bloquear el servidor de phishing — `sudo ufw deny from <ip>` (SOC, inmediata)
2. Forzar reset de credenciales del usuario que envió datos — `sudo passwd <user>` (sysadmin, inmediata)
3. Alertar a los usuarios afectados / concientización (SOC, inmediata)
4. Agregar el indicador (IP/dominio) a la blocklist / threat intel (SOC, 24h)

## Simulación

Implementada en `simulation/run-phishing.sh` (genera la visita GET + el POST con credenciales):

```bash
bash simulation/run-phishing.sh             # genera logs + POST real si hay contenedor
bash simulation/run-phishing.sh --offline   # solo logs (sin Docker)
```

```json
{"@timestamp":"...","event_type":"http_request","source_ip":"172.18.0.9",
 "dest_ip":"172.18.0.8","http_method":"POST","url":"/login","username":"testuser",
 "credential_submission":true,"tags":["web","credential_submission"],
 "source_type":"network_traffic"}
```

## Script original de diseño (contenedores fake-login / simulated-user)

> Diseño original de la nota. La versión implementada usa `network_logs/` para no depender de
> contenedores extra; este script queda como referencia de la idea (servidor de login falso + usuario
> simulado que envía credenciales).

```bash
#!/bin/bash
# Limpiar logs anteriores
docker exec fake-login sh -c "rm -f /var/log/phishing.log && touch /var/log/phishing.log"
echo "Starting phishing simulation..."
PHISH_SERVER_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' fake-login)
echo "Fake login server IP: $PHISH_SERVER_IP"
docker exec simulated-user curl -s "http://$PHISH_SERVER_IP/login" > /dev/null
docker exec simulated-user curl -s -X POST "http://$PHISH_SERVER_IP/login" \
  -d "username=testuser&password=fakepassword123" > /dev/null
echo "Credential submission simulated."
sleep 10
docker exec fake-login cat /var/log/phishing.log || echo "No phishing log found"
echo "Check Elastic SIEM for alerts."
```
