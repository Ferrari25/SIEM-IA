---
proyecto: SIEM-IA
tags:
  - "#ssh"
  - ataques
relacionadas:
  - "[[SIEM-IA - Port Scan]]"
  - "[[SIEM-IA - Phishing]]"
---
## ¿ Qué es SSH ?

**SSH (Secure Shell)** es un protocolo de red que permite conectarse de forma segura a una máquina remota.

Antes de SSH se usaba Telnet, que enviaba todo en texto plano. SSH cifra la comunicación.

Con SSH podés:

- Administrar servidores remotamente.
- Ejecutar comandos.
- Transferir archivos (SCP/SFTP).
- Crear túneles cifrados.
- Automatizar tareas.

Ejemplo:

```
ssh usuario@192.168.1.100
```

Cuando te conectás:

1. El cliente inicia conexión.
2. El servidor responde.
3. Intercambian claves criptográficas.
4. Se autentica el usuario.
5. Se abre una sesión remota.

---

# Autenticación en SSH

## Mediante contraseña

```
ssh testuser@192.168.1.100
```

El servidor pide:

```
Password:
```

Si coincide:

```
Login successful
```

---

## Mediante claves SSH

Se genera un par:

```
ssh-keygen
```

Obtiene:

```
id_rsaid_rsa.pub
```

- privada → se queda en tu PC
- pública → se copia al servidor

Luego:

```
ssh usuario@servidor
```

sin ingresar contraseña.

Es mucho más seguro.

---

# ¿Qué es un ataque de fuerza bruta SSH?

Es cuando alguien intenta autenticarse repetidamente probando muchas contraseñas.

Conceptualmente:

```
testuser : admintestuser : 123456testuser : passwordtestuser : qwerty...
```

Cada intento genera un evento de autenticación fallida en el servidor.

Para un SIEM esto es ideal porque deja muchos registros detectables.

---
### Resumen del script

1. **Borra los logs anteriores**

```
docker exec ssh-target rm -f /var/log/auth.log
```

Para que solo aparezcan los eventos generados por la prueba.

---

2. **Crea un diccionario de contraseñas**

```
password123
admin
123456
testpassword <---- Contraseña Correcta
```

Guardado en:

```
/tmp/passwords.txt
```

---

3. **Obtiene la IP del servidor SSH**

```
SSH_TARGET_IP=$(docker inspect ...)
```

Para saber contra qué contenedor atacar.

---

4. **Ejecuta Hydra**

```
hydra -l testuser -P /tmp/passwords.txt IP ssh
```

Donde:

- `-l testuser` → usuario objetivo.
- `-P passwords.txt` → lista de contraseñas.
- `-s 2222` → puerto SSH.
- `-V` → muestra cada intento.
- `-t 1` → un intento a la vez.

---

5. **Genera eventos de autenticación**

El servidor registra:

```
Failed password for testuserFailed password for testuserFailed password for testuserAccepted password for testuser
```

---

6. **Espera que Elastic procese los logs**

```
sleep 10
```

---

7. **Muestra los logs generados**

```
cat /var/log/auth.log
```

Para verificar que los eventos fueron registrados.

# Script
```bash
#!/bin/bash

# Clear old logs
docker exec ssh-target rm -f /var/log/auth.log

# Create password list for the brute-force attack
docker exec hydra-attacker bash -c "echo 'password123' > /tmp/passwords.txt"
docker exec hydra-attacker bash -c "echo 'admin' >> /tmp/passwords.txt"
docker exec hydra-attacker bash -c "echo '123456' >> /tmp/passwords.txt" 
docker exec hydra-attacker bash -c "echo 'testpassword' >> /tmp/passwords.txt" # The correct password

echo "Starting brute-force attack with Hydra..."
echo "This will generate failed login attempts that should be visible in Elastic SIEM"

# Find the IP address of the ssh-target container
SSH_TARGET_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' ssh-target)

echo "Target SSH Server IP: $SSH_TARGET_IP"

# Run Hydra attack with verbose logging
docker exec hydra-attacker hydra -l testuser -P /tmp/passwords.txt $SSH_TARGET_IP -s 2222 ssh -V -t 1

echo "Attack simulation completed."
echo "Verifying logs made it to Elasticsearch..."

# Wait 10 seconds for log processing
sleep 10

# Check logs directly in SSH container
echo "SSH Container Log Contents:"
docker exec ssh-target cat /var/log/auth.log || echo "No auth.log found"
docker logs ssh-target | grep -i password

echo "Check Elastic SIEM for alerts."
```

