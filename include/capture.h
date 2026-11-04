#pragma once

#include <string>
#include <functional>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <arpa/inet.h>

// Datos extraídos de cada paquete capturado
struct PacketInfo {
    std::string src_ip;
    std::string dst_ip;
    int         src_port  = 0;
    int         dst_port  = 0;
    std::string protocol;       // "TCP" | "UDP" | "OTHER"
    int         packet_len = 0;
    long long   timestamp  = 0; // epoch en segundos
};

// Callback que se invoca por cada paquete procesado
using PacketCallback = std::function<void(const PacketInfo&)>;

class NetworkCapture {
public:
    // Abre la interfaz de red (p.ej. "eth0", "wlan0").
    // Pasa "" para que libpcap elija la primera activa.
    explicit NetworkCapture(const std::string& interface = "");
    ~NetworkCapture();

    // Inicia la captura: procesa 'count' paquetes y llama a 'cb' por cada uno.
    // count = -1 → captura indefinida hasta llamar a stop().
    void start(int count, PacketCallback cb);
    void stop();

    // Devuelve la interfaz que se está usando
    const std::string& active_interface() const { return iface_; }

private:
    static void pcap_handler(u_char* user,
                             const struct pcap_pkthdr* header,
                             const u_char* packet);

    pcap_t*       handle_ = nullptr;
    std::string   iface_;
    PacketCallback callback_;
};