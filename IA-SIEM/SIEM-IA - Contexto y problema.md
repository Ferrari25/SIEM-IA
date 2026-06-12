---
proyecto: SIEM-IA
tipo: contexto
estado: 🟢 listo
área: seguridad
tags:
  - contexto
  - siem
  - problema
relacionadas:
  - "[[SIEM-IA - Índice]]"
  - "[[SIEM-IA - Arquitectura y flujo]]"
última_actualización: 2025-06-09
---
# Contexto y problema

## El problema real que queremos resolver

Un analista de seguridad que trabaja en el SOC (Security Operations Center) de cualquier organización mediana empieza su turno y tiene frente a él entre 500 y 2000 alertas acumuladas. No es exageración: es el número promedio real que generan los sistemas de seguridad modernos por día. Ese analista tiene que decidir cuáles son reales, cuáles son ruido, y cuáles requieren acción inmediata. Lo hace solo, o con un equipo pequeño, bajo presión de tiempo, con el conocimiento de que si se equivoca o tarda demasiado, un atacante puede estar moviéndose dentro de la red en ese momento.

El problema no es que falten herramientas. Los SIEM existen hace décadas. El problema es que las herramientas actuales generan información pero no generan comprensión. Le dicen al analista que hubo 47 intentos de login fallidos desde la IP 185.220.101.43 en los últimos 10 minutos. Pero no le dicen qué significa eso en el contexto de su red, qué debería hacer exactamente, ni si esa misma IP estuvo activa hace dos horas intentando otra cosa. El analista tiene que construir ese razonamiento él solo, para cada alerta, todo el día.

Eso genera tres consecuencias graves:

**Alert fatigue.** Cuando un analista ve mil alertas por turno, el cerebro humano empieza a normalizar. Las alertas dejan de sentirse urgentes. Se desarrolla un hábito inconsciente de descartar lo que parece repetitivo, y ahí es exactamente donde los atacantes más sofisticados se esconden: en el ruido, con ataques lentos y graduales que individualmente no parecen alarma pero en conjunto son una intrusión activa.

**Tiempo de respuesta alto.** El tiempo promedio entre que un atacante entra a una red y que el equipo de seguridad lo detecta es, según múltiples estudios de la industria, de semanas o meses. No horas. Eso no es porque los analistas sean malos en su trabajo: es porque el volumen de información hace imposible que un humano correlacione eventos distribuidos en el tiempo de manera eficiente.

**Decisiones bajo presión sin contexto suficiente.** Cuando finalmente una alerta escala y el analista tiene que actuar, muchas veces lo hace sin poder ver el cuadro completo. ¿Esta IP es un atacante real o un scanner legítimo de un proveedor? ¿Bloquearla va a cortar algún servicio crítico? ¿Qué técnica específica está usando? Sin respuestas rápidas a esas preguntas, la decisión se toma con información incompleta.

---

## Qué hace este sistema que no hacen los SIEM tradicionales

Un SIEM tradicional como Elastic, Splunk o QRadar es esencialmente una base de datos muy rápida con capacidad de búsqueda y algunas reglas de correlación. Cuando una regla dispara, crea una alerta. Esa alerta llega al dashboard del analista con datos técnicos crudos: timestamp, IP, puerto, tipo de evento, cantidad de ocurrencias. El analista lee eso y tiene que construir el análisis desde cero.

Lo que este sistema agrega encima de eso es una capa de razonamiento automático. No reemplaza al analista: le da un primer análisis ya hecho para cada alerta o para un bloque de alertas, en lenguaje que se puede leer y entender rápido, con una recomendación concreta de qué hacer. El analista pasa de ser el que tiene que construir el análisis a ser el que aprueba o descarta una recomendación ya elaborada.

La diferencia en la carga cognitiva es enorme. En lugar de leer datos crudos y razonar, el analista lee una conclusión y decide si la valida. Es la diferencia entre que alguien te diga "47 failed SSH logins from 185.220.101.43 in 10 minutes" y que te digan "Esta IP está ejecutando un ataque de fuerza bruta automatizado contra SSH. El patrón de temporización sugiere uso de Hydra o Medusa. No aparece en ningún listado de IPs legítimas de tu red. Recomendación: bloquear en firewall perimetral. Comando: `ufw deny from 185.220.101.43`. Probabilidad de falso positivo: baja."

---

## El flujo concreto de cómo ayuda

Cuando el sistema detecta una amenaza, en lugar de tirar una alerta cruda al dashboard, pasa por dos etapas antes de llegar al analista.

Primero, un agente clasificador revisa la alerta contra reglas de detección conocidas y determina de qué tipo de ataque se trata y qué tan severo es. Esto es rápido y determinístico: o cumple el patrón o no lo cumple.

Segundo, ese resultado va a un agente de lenguaje (un LLM) que tiene como función específica explicar qué está pasando, por qué es peligroso en ese contexto, y qué acción concreta tomar. No de forma genérica: con los datos específicos de esa alerta, esa IP, ese momento.

Lo que llega al analista es una card en el dashboard, la cual se debera construir en base a la salidad que nos proporciona el SIEM para poder hacer un tratamiendo y crear tal dashboard que indique la informacion que queremos mostrar, por ejemplo que dice: qué IP está involucrada, qué nivel de riesgo tiene, qué hizo exactamente, qué significa eso en términos de ataque, y un botón para aprobar la acción sugerida o descartarla. El analista no tiene que escribir comandos, no tiene que buscar documentación, no tiene que correlacionar eventos manualmente. Puede procesar esa alerta en segundos en lugar de minutos.

Y cada decisión queda registrada. Si el analista ignoró una alerta que después resultó ser un ataque real, eso está en el log. Si aprobó un bloqueo que cortó un servicio legítimo, también. Con el tiempo, ese historial alimenta al sistema para mejorar la calibración de las recomendaciones.

---

## Por qué esto importa más allá del proyecto académico

La realidad de la ciberseguridad en Argentina y en la región es que la mayoría de las organizaciones no tienen un SOC con 20 analistas. Tienen una persona, o dos, encargadas de seguridad como parte de un rol más amplio. Esas personas no pueden revisar miles de alertas por día. No tienen tiempo, y probablemente tampoco tienen la experiencia especializada para interpretar cada tipo de ataque.

Un sistema como este democratiza la capacidad de respuesta. Una organización pequeña con un solo administrador de sistemas puede tener el mismo nivel de análisis automatizado que una empresa grande con un equipo dedicado, porque la inteligencia está en el software, no en la cantidad de personas.

Además, el diseño con supervisión humana es una decisión deliberada e importante. El sistema nunca bloquea nada sin que un humano apruebe la acción. Eso no es una limitación: es una feature. Los falsos positivos en seguridad tienen consecuencias reales. Bloquear una IP automáticamente puede cortar el acceso de un proveedor legítimo, interrumpir un servicio crítico, o generar un incidente peor que el que intentaba prevenir. La IA sugiere, el humano decide. Ese equilibrio es lo que hace al sistema confiable en un entorno real.

---

## Las preguntas que este proyecto viene a responder

¿Es posible reducir el tiempo que tarda un analista en procesar una alerta de minutos a segundos, sin perder la precisión del análisis?

¿Puede un LLM generar recomendaciones de respuesta que sean lo suficientemente específicas y correctas como para que un analista las apruebe con confianza, sin necesitar verificar cada detalle?

¿Se puede construir este sistema con tecnología open source (Elastic Stack, Ollama, Python, Docker) de manera que sea desplegable en organizaciones sin presupuesto para soluciones comerciales?

¿Cómo se integra el componente de IA con la infraestructura SIEM existente sin romper lo que ya funciona?