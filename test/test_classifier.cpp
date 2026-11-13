#include <arpa/inet.h>

#include <cstdio>
#include <vector>

#include "capture.h"
#include "classifier.h"

static int failures = 0;
#define CHECK(cond)                                                      \
    do {                                                                 \
        if (!(cond)) {                                                   \
            std::printf("FALLO (línea %d): %s\n", __LINE__, #cond);      \
            ++failures;                                                  \
        }                                                                \
    } while (0)

using Bytes = std::vector<uint8_t>;

static Bytes make_packet(uint8_t proto, const char* src, const char* dst, const Bytes& l4) {
    Bytes p(14, 0);
    p[12] = 0x08;
    p[13] = 0x00;  // IPv4
    Bytes ip(20, 0);
    ip[0] = 0x45;
    const uint16_t total = static_cast<uint16_t>(20 + l4.size());
    ip[2] = total >> 8;
    ip[3] = total & 0xFF;
    ip[8] = 64;
    ip[9] = proto;
    inet_pton(AF_INET, src, &ip[12]);
    inet_pton(AF_INET, dst, &ip[16]);
    p.insert(p.end(), ip.begin(), ip.end());
    p.insert(p.end(), l4.begin(), l4.end());
    return p;
}

static Bytes tcp(uint16_t sport, uint16_t dport, uint8_t flags) {
    Bytes t(20, 0);
    t[0] = sport >> 8; t[1] = sport & 0xFF;
    t[2] = dport >> 8; t[3] = dport & 0xFF;
    t[12] = 0x50;
    t[13] = flags;
    return t;
}

static Bytes udp(uint16_t sport, uint16_t dport) {
    Bytes u(8, 0);
    u[0] = sport >> 8; u[1] = sport & 0xFF;
    u[2] = dport >> 8; u[3] = dport & 0xFF;
    u[5] = 8;
    return u;
}

static PacketInfo run(const Bytes& pkt) {
    PacketInfo info;
    const bool ok = parse_ethernet_ipv4(pkt.data(), pkt.size(), static_cast<uint32_t>(pkt.size()), 1700000000, info);
    CHECK(ok);
    classify(info);
    return info;
}

int main() {
    {  // SSH (SYN)
        auto p = run(make_packet(6, "10.0.0.5", "10.0.0.9", tcp(50000, 22, 0x02)));
        CHECK(p.protocol == "TCP" && p.dst_port == 22 && p.src_ip == "10.0.0.5");
        CHECK(p.app_protocol == "SSH" && p.category == "acceso_remoto" && p.risk == "MEDIUM");
        CHECK(p.tcp_flags == "SYN");
    }
    {  // HTTPS y respuesta del servidor (puerto origen 443)
        auto p = run(make_packet(6, "10.0.0.5", "93.184.216.34", tcp(50000, 443, 0x10)));
        CHECK(p.app_protocol == "HTTPS" && p.risk == "LOW");
        auto r = run(make_packet(6, "93.184.216.34", "10.0.0.5", tcp(443, 50000, 0x18)));
        CHECK(r.app_protocol == "HTTPS" && r.risk == "LOW");
    }
    {  // Telnet
        auto p = run(make_packet(6, "10.0.0.5", "10.0.0.9", tcp(50000, 23, 0x02)));
        CHECK(p.app_protocol == "Telnet" && p.risk == "HIGH");
    }
    {  // Escaneo XMAS (FIN+PSH+URG) hacia un puerto cualquiera
        auto p = run(make_packet(6, "10.0.0.5", "10.0.0.9", tcp(50000, 80, 0x29)));
        CHECK(p.risk == "HIGH" && p.category == "reconocimiento");
        CHECK(p.tcp_flags.find("FIN") != std::string::npos);
    }
    {  // Escaneo NULL
        auto p = run(make_packet(6, "10.0.0.5", "10.0.0.9", tcp(50000, 8081, 0x00)));
        CHECK(p.risk == "HIGH" && p.tcp_flags == "NONE");
    }
    {  // SYN+FIN
        auto p = run(make_packet(6, "10.0.0.5", "10.0.0.9", tcp(50000, 443, 0x03)));
        CHECK(p.risk == "HIGH");
    }
    {  // SSDP (UDP multicast)
        auto p = run(make_packet(17, "172.24.208.1", "239.255.255.250", udp(59271, 1900)));
        CHECK(p.protocol == "UDP" && p.app_protocol == "SSDP/UPnP");
        CHECK(p.category == "descubrimiento" && p.risk == "LOW");
    }
    {  // NTP
        auto p = run(make_packet(17, "172.24.208.167", "185.125.190.121", udp(55419, 123)));
        CHECK(p.app_protocol == "NTP" && p.category == "sincronizacion_hora");
    }
    {  // Puerto desconocido
        auto p = run(make_packet(6, "10.0.0.5", "10.0.0.9", tcp(50000, 51234, 0x02)));
        CHECK(p.app_protocol == "Desconocido" && p.risk == "LOW");
    }
    {  // Backdoor conocido
        auto p = run(make_packet(6, "10.0.0.5", "10.0.0.9", tcp(50000, 4444, 0x02)));
        CHECK(p.risk == "HIGH" && p.category == "sospechoso");
    }
    {  // ICMP echo request (antes aparecía como OTHER)
        auto p = run(make_packet(1, "10.0.0.5", "8.8.8.8", Bytes{8, 0, 0, 0, 0, 0, 0, 0}));
        CHECK(p.protocol == "ICMP" && p.icmp_type == 8);
        CHECK(p.app_protocol == "Echo Request (ping)" && p.risk == "LOW");
    }
    {  // GRE
        auto p = run(make_packet(47, "10.0.0.5", "10.0.0.9", Bytes(8, 0)));
        CHECK(p.protocol == "GRE" && p.risk == "MEDIUM" && p.category == "tunel");
    }
    {  // Protocolo IP desconocido
        auto p = run(make_packet(200, "10.0.0.5", "10.0.0.9", Bytes(8, 0)));
        CHECK(p.protocol == "IP-200" && p.risk == "MEDIUM");
    }
    {  // IGMP
        auto p = run(make_packet(2, "10.0.0.5", "224.0.0.22", Bytes(8, 0)));
        CHECK(p.protocol == "IGMP" && p.category == "multicast");
    }
    {  // Tramas inválidas
        PacketInfo info;
        Bytes tiny(10, 0);
        CHECK(!parse_ethernet_ipv4(tiny.data(), tiny.size(), 10, 0, info));
        Bytes v6(60, 0);
        v6[12] = 0x86; v6[13] = 0xDD;
        CHECK(!parse_ethernet_ipv4(v6.data(), v6.size(), 60, 0, info));
        auto trunc = make_packet(6, "10.0.0.5", "10.0.0.9", tcp(1, 2, 2));
        CHECK(!parse_ethernet_ipv4(trunc.data(), 20, 54, 0, info));
    }

    if (failures == 0) std::printf("OK: todas las pruebas pasaron\n");
    return failures ? 1 : 0;
}