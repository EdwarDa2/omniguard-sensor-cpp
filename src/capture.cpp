#include "capture.h"
#include <iostream>
#include <stdexcept>
#include <cstring>
#include <ctime>

// ── Constructor ───────────────────────────────────────────────────────────────
NetworkCapture::NetworkCapture(const std::string& interface)
{
    char errbuf[PCAP_ERRBUF_SIZE] = {};

    // Si no se especifica interfaz, libpcap elige la primera activa
    if (interface.empty()) {
        pcap_if_t* devs = nullptr;
        if (pcap_findalldevs(&devs, errbuf) == -1 || devs == nullptr) {
            throw std::runtime_error(
                std::string("No se encontró interfaz de red: ") + errbuf);
        }
        iface_ = devs->name;
        pcap_freealldevs(devs);
    } else {
        iface_ = interface;
    }

    // Abre la interfaz en modo promiscuo, timeout 1000 ms
    handle_ = pcap_open_live(iface_.c_str(), 65535, 1, 1000, errbuf);
    if (!handle_) {
        throw std::runtime_error(
            std::string("pcap_open_live falló en '") + iface_ + "': " + errbuf);
    }

    // Solo capturamos paquetes IPv4
    struct bpf_program fp{};
    const char* filter = "ip";
    if (pcap_compile(handle_, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) == -1 ||
        pcap_setfilter(handle_, &fp) == -1)
    {
        std::cerr << "[WARN] No se pudo aplicar filtro BPF: "
                  << pcap_geterr(handle_) << "\n";
    }
    pcap_freecode(&fp);

    std::cout << "[SENSOR] Interfaz activa: " << iface_ << "\n";
}

// ── Destructor ────────────────────────────────────────────────────────────────
NetworkCapture::~NetworkCapture()
{
    if (handle_) {
        pcap_close(handle_);
        handle_ = nullptr;
    }
}

// ── start ─────────────────────────────────────────────────────────────────────
void NetworkCapture::start(int count, PacketCallback cb)
{
    callback_ = std::move(cb);
    // Pasamos 'this' como user data al handler estático
    pcap_loop(handle_, count,
              NetworkCapture::pcap_handler,
              reinterpret_cast<u_char*>(this));
}

void NetworkCapture::stop()
{
    if (handle_) pcap_breakloop(handle_);
}

// ── Handler estático (invocado por libpcap) ───────────────────────────────────
void NetworkCapture::pcap_handler(u_char*                  user,
                                   const struct pcap_pkthdr* header,
                                   const u_char*             packet)
{
    auto* self = reinterpret_cast<NetworkCapture*>(user);
    PacketInfo info;
    info.packet_len = static_cast<int>(header->len);
    info.timestamp  = static_cast<long long>(header->ts.tv_sec);

    // ── Cabecera Ethernet (14 bytes) ──────────────────────────────────────────
    if (header->len < sizeof(struct ether_header)) return;
    const auto* eth = reinterpret_cast<const struct ether_header*>(packet);

    // Solo IPv4 (0x0800)
    if (ntohs(eth->ether_type) != ETHERTYPE_IP) return;

    // ── Cabecera IP ───────────────────────────────────────────────────────────
    const u_char* ip_ptr = packet + sizeof(struct ether_header);
    if (header->len < sizeof(struct ether_header) + sizeof(struct ip)) return;

    const auto* ip_hdr = reinterpret_cast<const struct ip*>(ip_ptr);
    info.src_ip = inet_ntoa(ip_hdr->ip_src);
    info.dst_ip = inet_ntoa(ip_hdr->ip_dst);

    int ip_hdr_len = ip_hdr->ip_hl * 4; // en bytes

    // ── Protocolo de transporte ───────────────────────────────────────────────
    const u_char* transport_ptr = ip_ptr + ip_hdr_len;

    switch (ip_hdr->ip_p) {
        case IPPROTO_TCP: {
            info.protocol = "TCP";
            if (header->len >= sizeof(struct ether_header) +
                               static_cast<size_t>(ip_hdr_len) +
                               sizeof(struct tcphdr))
            {
                const auto* tcp =
                    reinterpret_cast<const struct tcphdr*>(transport_ptr);
                info.src_port = ntohs(tcp->th_sport);
                info.dst_port = ntohs(tcp->th_dport);
            }
            break;
        }
        case IPPROTO_UDP: {
            info.protocol = "UDP";
            if (header->len >= sizeof(struct ether_header) +
                               static_cast<size_t>(ip_hdr_len) +
                               sizeof(struct udphdr))
            {
                const auto* udp =
                    reinterpret_cast<const struct udphdr*>(transport_ptr);
                info.src_port = ntohs(udp->uh_sport);
                info.dst_port = ntohs(udp->uh_dport);
            }
            break;
        }
        default:
            info.protocol = "OTHER";
            break;
    }

    // Invoca el callback registrado
    if (self->callback_) self->callback_(info);
}