# Documentación del sistema SIEM-IA

Esta carpeta documenta la arquitectura, los requerimientos y la operación del
proyecto: cómo se monta, cómo se usa, cómo se ejecuta y cómo se corren las
simulaciones de ataque. Está pensada para que cualquiera pueda **reconstruir el
sistema desde cero** y entender el **flujo de datos** de punta a punta.

## Índice

| # | Documento | Qué responde |
|---|-----------|--------------|
| 01 | [Arquitectura](01-arquitectura.md) | Qué componentes hay y cómo se conectan |
| 02 | [Requerimientos](02-requerimientos.md) | Qué hace falta (hardware, software, red) |
| 03 | [Instalación y montaje](03-instalacion-y-montaje.md) | Cómo se despliega el stack paso a paso |
| 04 | [Uso y ejecución](04-uso-y-ejecucion.md) | Cómo se corre el pipeline y el dashboard |
| 05 | [Simulaciones de ataque](05-simulaciones-de-ataque.md) | Cómo se generan SSH brute force, port scan y phishing |
| 06 | [Flujo de datos](06-flujo-de-datos.md) | Recorrido completo de un evento: del ataque a la acción |
| 07 | [Reglas de detección](07-reglas-de-deteccion.md) | Cómo configurar la regla en Elastic para que capte la alerta |
| 08 | [Puesta en marcha paso a paso](08-puesta-en-marcha-paso-a-paso.md) | Runbook completo para levantar todo desde cero |

## Resumen en una frase

> Un ataque genera logs → Elastic los ingiere y dispara alertas → un Agente 1
> determinístico clasifica → un Agente 2 (LLM con fallback) explica en lenguaje
> claro → un analista humano aprueba o descarta cada acción sugerida desde un
> dashboard, y cada decisión queda registrada de forma inmutable.

## El principio rector

**La IA sugiere, el humano decide.** El sistema nunca ejecuta una acción de
contención por su cuenta: siempre hay un analista que aprueba. Los falsos
positivos en seguridad tienen consecuencias reales (cortar un servicio legítimo),
así que la supervisión humana es una *feature*, no una limitación.
