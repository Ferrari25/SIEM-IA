---
proyecto: SIEM-IA
tags:
  - siem
  - ollama
  - LLM
  - ia
relacionadas:
  - "[[SIEM-IA - Arquitectura y flujo]]"
---
----


| Capa                | Tecnología          | Función                    |
| ------------------- | ------------------- | -------------------------- |
| ***Detección red*** | Suricata            | Port scan, HTTP malicioso  |
| Detección sistema   | Auditd + Filebeat   | Logs SSH, usuarios, correo |
| Pipeline            | Logstash            | Normaliza → JSON           |
| Almacenamiento      | Elasticsearch       | Índices de alertas         |
| Cola de mensajes    | Redis               | Desacopla agentes          |
| Agentes IA          | Python + Ollama     | Reglas + LLM local         |
| Orquestación base   | Appwrite (fork)     | Microservicios + APIs REST |
| ML adicional        | scikit-learn + TF   | Clasificación supervisada  |
| Testing ataques     | OWASP Juice Shop    | XSS, SQLi, auth bypass     |
| Frontend            | React + TailwindCSS | Dashboard supervisor       |
| Infraestructura     | Docker Compose      | Un contenedor por servicio |
|                     |                     |                            |
