# REALLY REALLY SAFE PROTOCOL(RRSP)
This is a security protocol for comunication between players on videogames. Its aim is to protect user data shared between conections
Handshake with RSA , but always sharing secret tickets between. 

## Arquitectura y Diseño de una App de Mensajería
-Arquitectura híbrida Cliente-Servidor y Cliente-Cliente.
-Se ha usado sockets con TCP
-Todos los clientes se conectan al servidor en su conversación inicial.
-Servidor actúa como KDC
-Servidor guarda las claves públicas y los tickets de los clientes
-Los clientes se autentican con el KDC (login).
-El usuario ingresa la clave de la aplicación, el servidor valida y permite la comunicación.
-Los mensajes se cifran por RSA

## Diseño y descripción del Protocolo

-El diseño está dividido en cuatro partes:
-Autenticación mutua entre cliente y KDC.
-Validación de clave del cliente con el KDC.
-KDC entrega ticket y clave Kab.
-Intercambio de claves públicas por medio de Kab entre los clientes
-El tamaño de las claves será de 512 bits

Cabe mencionar que las claves , tanto simetricas como asimetricas serán actualizadas por el servidor cada cierto tiempo, para tener perfect forward secrecy.
E
El KDC enviará un mensje a los clientes para cambiar su claves.






