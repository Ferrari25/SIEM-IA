---
proyecto: SIEM-IA
tipo: proyecto
estado: 🟢 En progreso
area: area1
tags:
  - siem
relacionadas:
  - "[[SIEM-IA - Contexto y problema]]"
ultima_actualizacion: 2026-06-11
---
# SIEM-IA — Índice

Mapa de las notas del proyecto.

## Fundamentos
- [[SIEM-IA - Contexto y problema]] — el problema real (alert fatigue, tiempo de respuesta) y qué resuelve el sistema.
- [[SIEM-IA - Arquitectura y flujo]] — componentes y recorrido de un evento de punta a punta.
- [[SIEM-IA - Stack tecnológico]] — tecnologías por capa.

## Implementación
- [[SIEM-IA - Docker y Microservicios]] — estructura de servicios.
- [[SIEM-IA - Prompts de IA]] — prompts del Agente 2 (análisis, reglas Sigma, reportes).
- [[SIEM-IA - Dashboard de supervisión]] — la GUI donde el humano aprueba/descarta acciones.
- [[SIEM-IA - Estado actual y próximos pasos]] — qué está hecho y qué falta.

## Tipos de ataque
- [[SIEM-IA - Tipos de ataque]] — overview de los tres tipos.
- [[SIEM-IA - SSH]] — fuerza bruta SSH (T1110).
- [[SIEM-IA - Port Scan]] — escaneo de puertos (T1046).
- [[SIEM-IA - Phishing]] — captura de credenciales (T1566).

## Documentación técnica (en el repo)
La guía completa de arquitectura, requisitos, montaje, uso, simulaciones y flujo de datos está en
`docs/` del repositorio Elastic-SIEM-Project. Las auditorías y entregables del Council, en
`.claude/claude-context/outputs/`.
