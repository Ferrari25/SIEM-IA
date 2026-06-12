# 07 · Configurar las reglas de detección en Elastic

Para que el SIEM **genere una alerta** a partir de los logs, hace falta una **regla de detección**
en Kibana (Elastic Security). Esta guía explica cómo crearla paso a paso para el ataque de fuerza
bruta SSH, y cómo se manejan los otros dos ataques.

> Sin regla no hay alerta: Logstash ingiere los logs a Elasticsearch, pero es la regla la que
> evalúa el umbral y escribe en `.alerts-security.alerts-default` (el índice que después lee
> `prepare-for-ia.py`).

## Requisitos previos

1. El stack está levantado y Kibana abre en `http://127.0.0.1:5601` (ver [03 · Instalación](03-instalacion-y-montaje.md)).
2. **Ya hay datos en `filebeat-*`.** La regla solo dispara si existen logs. Corré al menos una vez
   la simulación de fuerza bruta para tener `authentication_failure` en el índice (ver
   [05 · Simulaciones](05-simulaciones-de-ataque.md)).
3. Kibana tiene la clave de cifrado de saved objects configurada (`KIBANA_SAVEDOBJECTS_KEY` →
   `xpack.encryptedSavedObjects.encryptionKey`). Ya está en `kibana.yml`; es lo que permite habilitar
   el motor de detección.

## Paso 1 — Crear el data view (si no existe)

1. Kibana → menú **☰ → Stack Management → Data Views → Create data view**.
2. Name: `filebeat-*` · Index pattern: `filebeat-*` · Timestamp field: `@timestamp`.
3. Guardar.

## Paso 2 — Habilitar el motor de detección

1. Kibana → **☰ → Security → Alerts**.
2. La primera vez, Kibana pide habilitar las detecciones (crea los índices de alertas).
   Aceptar. Si pide permisos, iniciá sesión como `elastic`.

## Paso 3 — Crear la regla *Threshold* (fuerza bruta SSH, T1110)

1. **Security → Rules → Detection rules (SIEM) → Create new rule**.
2. Tipo de regla: **Threshold**.
3. **Definir la fuente y la condición:**
   - **Source / Index patterns:** `filebeat-*`
   - **Custom query (KQL):**
     ```
     tags:authentication_failure OR message:*Failed password* OR message:*authentication failure*
     ```
   - **Group by field:** `host.ip`
   - **Threshold:** `3`
4. **About rule:**
   - **Name:** `Detección de ataques de fuerza bruta`
   - **Description:** `Detecta múltiples fallos de autenticación desde una misma IP (fuerza bruta SSH).`
   - **Severity:** `High` · **Risk score:** `73`
   - **Tags:** `brute-force`, `authentication`, `credential-access`
   - **MITRE ATT&CK:** táctica *Credential Access* → técnica *Brute Force (T1110)*
   - **False positives:** `Usuarios que olvidaron su contraseña y reintentaron`
5. **Schedule:**
   - **Runs every:** `5m`
   - **Additional look-back time:** `1m`
6. **Create & enable rule.**

> Capturas paso a paso de esta misma regla en [`../brute_force.md`](../brute_force.md).

## Paso 4 — Disparar y verificar

```bash
# generar la fuerza bruta (con el stack y la simulación arriba)
docker compose --profile simulation up -d ssh-target hydra-attacker
bash simulation/run-brute-force.sh
```

1. Esperá 5–10 minutos (la regla corre cada 5m).
2. Kibana → **Security → Alerts** → debería aparecer la alerta *Detección de ataques de fuerza bruta*.
3. Confirmá por API que el índice de alertas tiene documentos:
   ```bash
   curl -s -u elastic:$ELASTIC_PASSWORD \
     "http://127.0.0.1:9200/.alerts-security.alerts-default/_count"
   ```

A partir de acá, `python3 prepare-for-ia.py` ya puede extraer la alerta hacia la capa IA.

## Los otros dos ataques (port scan y phishing)

En este proyecto **no** se crean reglas de Kibana para port scan ni phishing: esos ataques se
detectan directamente en la **capa IA** (`classifier.py`), a partir de los eventos NDJSON que las
simulaciones dejan en `network_logs/`. Razón: el SIEM no tiene Suricata desplegado, así que no hay
una fuente de eventos de red sobre la que escribir una regla en Kibana.

Si más adelante se despliega Suricata, se pueden crear reglas equivalentes:

| Ataque | Tipo de regla | Query / condición sugerida | MITRE |
|--------|---------------|----------------------------|-------|
| Port scan | Threshold | agrupar por `source.ip`, contar `destination.port` distintos > 10 | T1046 |
| Phishing | Custom query | `http.request.method:POST AND url.path:"/login" AND <marca de credenciales>` | T1566 |

## Detection-as-code (versionar la regla)

Tener la regla solo en la UI no es reproducible. Dos opciones:

- **Exportar desde Kibana:** Security → Rules → seleccionar la regla → **Export** → genera un
  `.ndjson` que se commitea y se puede **Import** en otro Kibana.
- **Ejemplo de referencia:** `.claude/claude-context/outputs/detection-rules/brute-force.example.json`
  muestra los campos de la regla en JSON (ilustrativo; para importar de verdad usá el `.ndjson`
  exportado por Kibana).

> Recomendación: una vez que la regla funciona, exportala y guardala en el repo para tenerla
> versionada y poder recrearla en cualquier despliegue.
