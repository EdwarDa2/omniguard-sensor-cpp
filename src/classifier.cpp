#include "classifier.h"

#include <string>

namespace {

enum Risk { LOW = 0, MEDIUM = 1, HIGH = 2 };

const char* risk_name(Risk r) {
    switch (r) {
        case HIGH: return "HIGH";
        case MEDIUM: return "MEDIUM";
        default: return "LOW";
    }
}

constexpr uint8_t T = 1, U = 2, TU = 3;  
struct Rule {
    uint16_t port;
    uint8_t transport;
    const char* app;
    const char* category;
    Risk risk;
    const char* reason;  // "" = sin nota especial
};

// Catálogo de servicios por puerto. LOW = tráfico esperado; MEDIUM = a vigilar
// (sin cifrar, administración remota, servicios expuestos); HIGH = indicador de amenaza.
const Rule kRules[] = {
    // Web
    {80, T, "HTTP", "web", LOW, "HTTP sin cifrar: el contenido viaja en texto plano"},
    {8080, T, "HTTP-alt", "web", LOW, "HTTP alterno sin cifrar"},
    {443, T, "HTTPS", "web", LOW, ""},
    {443, U, "QUIC/HTTP3", "web", LOW, ""},
    {8443, T, "HTTPS-alt", "web", LOW, ""},
    // Nombres y configuración de red
    {53, TU, "DNS", "resolucion_dns", LOW, ""},
    {853, T, "DNS sobre TLS", "resolucion_dns", LOW, ""},
    {67, U, "DHCP", "configuracion_red", LOW, ""},
    {68, U, "DHCP", "configuracion_red", LOW, ""},
    {123, U, "NTP", "sincronizacion_hora", LOW, ""},
    {514, U, "Syslog", "registro", LOW, ""},
    {88, TU, "Kerberos", "autenticacion", LOW, ""},
    {636, T, "LDAPS", "directorio", LOW, ""},
    {389, TU, "LDAP", "directorio", MEDIUM, "LDAP sin cifrar: consultas y credenciales visibles"},
    {161, U, "SNMP", "gestion_red", MEDIUM, "SNMP v1/v2c usa 'community strings' en texto plano"},
    // Acceso remoto
    {22, T, "SSH", "acceso_remoto", MEDIUM, "Administración remota: objetivo habitual de fuerza bruta"},
    {23, T, "Telnet", "acceso_remoto", HIGH, "Telnet envía credenciales en texto plano y es objetivo común de botnets"},
    {3389, T, "RDP", "acceso_remoto", MEDIUM, "Escritorio remoto expuesto: objetivo frecuente de ransomware"},
    {5900, T, "VNC", "acceso_remoto", MEDIUM, "Control remoto VNC, a menudo con autenticación débil"},
    {5985, T, "WinRM", "acceso_remoto", MEDIUM, "Administración remota de Windows"},
    // Archivos
    {21, T, "FTP", "transferencia_archivos", MEDIUM, "FTP sin cifrar: credenciales en texto plano"},
    {20, T, "FTP-data", "transferencia_archivos", MEDIUM, "Datos FTP sin cifrar"},
    {69, U, "TFTP", "transferencia_archivos", MEDIUM, "TFTP sin autenticación ni cifrado"},
    {445, T, "SMB", "compartir_archivos", MEDIUM, "SMB: vector común de movimiento lateral y ransomware"},
    {139, T, "NetBIOS Session", "compartir_archivos", MEDIUM, "Servicio heredado de Windows, expuesto a enumeración"},
    {2049, TU, "NFS", "compartir_archivos", MEDIUM, "Compartición NFS expuesta"},
    {135, T, "MS-RPC", "servicios_windows", MEDIUM, "RPC de Windows: usado en enumeración y explotación"},
    // Correo
    {25, T, "SMTP", "correo", MEDIUM, "SMTP puede transportar correo sin cifrar"},
    {110, T, "POP3", "correo", MEDIUM, "POP3 sin cifrar: credenciales en texto plano"},
    {143, T, "IMAP", "correo", MEDIUM, "IMAP sin cifrar: credenciales en texto plano"},
    {465, T, "SMTPS", "correo", LOW, ""},
    {587, T, "SMTP (submission)", "correo", LOW, ""},
    {993, T, "IMAPS", "correo", LOW, ""},
    {995, T, "POP3S", "correo", LOW, ""},
    // Bases de datos
    {3306, T, "MySQL", "base_de_datos", MEDIUM, "Base de datos accesible por red: no debería exponerse fuera de la red interna"},
    {5432, T, "PostgreSQL", "base_de_datos", MEDIUM, "Base de datos accesible por red: no debería exponerse fuera de la red interna"},
    {1433, T, "MS SQL Server", "base_de_datos", MEDIUM, "Base de datos accesible por red: no debería exponerse fuera de la red interna"},
    {1521, T, "Oracle DB", "base_de_datos", MEDIUM, "Base de datos accesible por red: no debería exponerse fuera de la red interna"},
    {27017, T, "MongoDB", "base_de_datos", MEDIUM, "Base de datos accesible por red: no debería exponerse fuera de la red interna"},
    {6379, T, "Redis", "base_de_datos", MEDIUM, "Redis accesible por red: no debería exponerse fuera de la red interna"},
    {9200, T, "Elasticsearch", "base_de_datos", MEDIUM, "Servicio de datos accesible por red"},
    {11211, TU, "Memcached", "base_de_datos", MEDIUM, "Memcached expuesto: usado en ataques de amplificación"},
    // Descubrimiento local
    {137, U, "NetBIOS Name", "descubrimiento", LOW, ""},
    {138, U, "NetBIOS Datagram", "descubrimiento", LOW, ""},
    {1900, U, "SSDP/UPnP", "descubrimiento", LOW, ""},
    {5353, U, "mDNS", "descubrimiento", LOW, ""},
    {3702, U, "WS-Discovery", "descubrimiento", LOW, ""},
    {57621, TU, "Spotify (descubrimiento local)", "descubrimiento", LOW, ""},
    {5355, TU, "LLMNR", "descubrimiento", MEDIUM, "LLMNR es susceptible a envenenamiento de nombres (suplantación)"},
    // VPN, VoIP, IoT
    {51820, U, "WireGuard", "vpn_tunel", LOW, ""},
    {500, U, "IPsec IKE", "vpn_tunel", LOW, ""},
    {4500, U, "IPsec NAT-T", "vpn_tunel", LOW, ""},
    {1194, TU, "OpenVPN", "vpn_tunel", LOW, ""},
    {1723, T, "PPTP", "vpn_tunel", MEDIUM, "PPTP es un protocolo VPN obsoleto e inseguro"},
    {3478, U, "STUN", "voip_streaming", LOW, ""},
    {8883, T, "MQTT (TLS)", "iot", LOW, ""},
    {1883, T, "MQTT", "iot", MEDIUM, "MQTT sin cifrar"},
    {2375, T, "Docker API", "administracion_contenedores", HIGH, "API de Docker sin TLS: control total del host si se expone"},
    // Puertos asociados a malware, botnets o anonimización
    {4444, TU, "Puerto de malware (Metasploit/backdoor)", "sospechoso", HIGH, "Puerto por defecto de Metasploit y de múltiples backdoors"},
    {31337, TU, "Back Orifice (backdoor)", "sospechoso", HIGH, "Puerto clásico de backdoors"},
    {12345, T, "NetBus (backdoor)", "sospechoso", HIGH, "Puerto clásico de troyanos de acceso remoto"},
    {6667, T, "IRC", "sospechoso", MEDIUM, "IRC: canal de control habitual de botnets"},
    {5555, T, "ADB / backdoor", "sospechoso", MEDIUM, "Android Debug Bridge o backdoors"},
    {9001, T, "Tor (relay)", "anonimizacion", MEDIUM, "Posible tráfico de la red Tor"},
    {9050, T, "Tor (SOCKS)", "anonimizacion", MEDIUM, "Posible tráfico de la red Tor"},
    {1080, T, "SOCKS proxy", "anonimizacion", MEDIUM, "Proxy SOCKS: posible túnel o evasión"},
};

const Rule* lookup(uint16_t port, uint8_t transport) {
    if (port == 0) return nullptr;
    for (const auto& r : kRules)
        if (r.port == port && (r.transport & transport)) return &r;
    return nullptr;
}

struct Verdict {
    std::string app = "Desconocido";
    std::string category = "desconocido";
    Risk risk = LOW;
    std::string reason;
};

void classify_icmp(const PacketInfo& p, Verdict& v) {
    v.app = "ICMP";
    v.category = "diagnostico_red";
    switch (p.icmp_type) {
        case 0: v.app = "Echo Reply (ping)"; break;
        case 8:
            v.app = "Echo Request (ping)";
            if (p.length > 200) {
                v.risk = MEDIUM;
                v.category = "sospechoso";
                v.reason = "Ping de tamaño anómalo: posible túnel ICMP o sondeo";
            }
            break;
        case 3: v.app = "Destination Unreachable"; break;
        case 11: v.app = "Time Exceeded (traceroute)"; break;
        case 5:
            v.app = "Redirect";
            v.risk = MEDIUM;
            v.category = "sospechoso";
            v.reason = "ICMP Redirect puede usarse para alterar rutas (intercepción de tráfico)";
            break;
        case 13: case 15: case 17:
            v.app = "Timestamp/Info/Mask Request";
            v.risk = MEDIUM;
            v.category = "reconocimiento";
            v.reason = "Solicitud típica de reconocimiento de red";
            break;
        default:
            v.app = "ICMP tipo " + std::to_string(p.icmp_type);
    }
}

void classify_other(const PacketInfo& p, Verdict& v) {
    switch (p.ip_proto) {
        case 2: v.app = "IGMP"; v.category = "multicast"; break;
        case 4:
            v.app = "IP-in-IP"; v.category = "tunel"; v.risk = MEDIUM;
            v.reason = "Encapsulamiento IP-in-IP: puede ocultar tráfico a la inspección";
            break;
        case 41:
            v.app = "IPv6 encapsulado"; v.category = "tunel"; v.risk = MEDIUM;
            v.reason = "Túnel IPv6 sobre IPv4: puede eludir controles";
            break;
        case 47:
            v.app = "Túnel GRE"; v.category = "tunel"; v.risk = MEDIUM;
            v.reason = "Túnel GRE: puede encapsular tráfico no inspeccionado";
            break;
        case 50: v.app = "IPsec ESP"; v.category = "vpn_tunel"; break;
        case 51: v.app = "IPsec AH"; v.category = "vpn_tunel"; break;
        case 89: v.app = "OSPF"; v.category = "enrutamiento"; break;
        case 112: v.app = "VRRP"; v.category = "enrutamiento"; break;
        case 132: v.app = "SCTP"; v.category = "transporte_alternativo"; break;
        default:
            v.app = "Protocolo IP " + std::to_string(p.ip_proto);
            v.risk = MEDIUM;
            v.reason = "Protocolo IP poco común: verificar su origen";
    }
}


void check_tcp_flags(const PacketInfo& p, Verdict& v) {
    constexpr int FIN = 0x01, SYN = 0x02, RST = 0x04, PSH = 0x08, URG = 0x20;
    const int f = p.tcp_flag_bits & 0x3F;
    Risk r = LOW;
    const char* why = nullptr;
    if (f == 0) { r = HIGH; why = "Paquete TCP sin flags (técnica de escaneo NULL)"; }
    else if ((f & (FIN | PSH | URG)) == (FIN | PSH | URG)) { r = HIGH; why = "Flags FIN+PSH+URG (técnica de escaneo XMAS)"; }
    else if ((f & (SYN | FIN)) == (SYN | FIN)) { r = HIGH; why = "SYN+FIN: combinación inválida (escaneo o evasión)"; }
    else if ((f & (SYN | RST)) == (SYN | RST)) { r = HIGH; why = "SYN+RST: combinación inválida (escaneo o evasión)"; }
    else if (f == FIN) { r = MEDIUM; why = "FIN sin ACK: posible escaneo FIN"; }
    if (why && r >= v.risk) {
        v.risk = r;
        v.reason = why;
        v.category = "reconocimiento";
    }
}

}   

void classify(PacketInfo& p) {
    Verdict v;
    if (p.ip_proto == 6 || p.ip_proto == 17) {
        const uint8_t t = (p.ip_proto == 6) ? T : U;
          
        const Rule* r = lookup(p.dst_port, t);
        if (!r) r = lookup(p.src_port, t);
        if (r) {
            v.app = r->app;
            v.category = r->category;
            v.risk = r->risk;
            v.reason = r->reason;
        }
        if (p.ip_proto == 6 && p.tcp_flag_bits >= 0) check_tcp_flags(p, v);
    } else if (p.ip_proto == 1) {
        classify_icmp(p, v);
    } else {
        classify_other(p, v);
    }

    if (v.reason.empty())
        v.reason = (v.risk == LOW) ? "Tráfico habitual, sin indicios de amenaza"
                                   : "Tráfico a vigilar";
    p.app_protocol = v.app;
    p.category = v.category;
    p.risk = risk_name(v.risk);
    p.risk_reason = v.reason;
}