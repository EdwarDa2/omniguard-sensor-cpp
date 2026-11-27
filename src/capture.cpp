#include "capture.h"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#endif

#include <cstdlib>
#include <cstring>
#include <iostream>
#include <vector>

#include "classifier.h"

namespace {

constexpr uint8_t kFin = 0x01, kSyn = 0x02, kRst = 0x04, kPsh = 0x08, kAck = 0x10, kUrg = 0x20;

std::string flags_to_string(uint8_t bits) {
    std::string s;
    auto add = [&](uint8_t mask, const char* name) {
        if (bits & mask) {
            if (!s.empty()) s += ",";
            s += name;
        }
    };
    add(kSyn, "SYN");
    add(kAck, "ACK");
    add(kFin, "FIN");
    add(kRst, "RST");
    add(kPsh, "PSH");
    add(kUrg, "URG");
    return s.empty() ? "NONE" : s;
}

std::string protocol_name(uint8_t p) {
    switch (p) {
        case 1: return "ICMP";
        case 2: return "IGMP";
        case 4: return "IPIP";
        case 6: return "TCP";
        case 17: return "UDP";
        case 41: return "IPV6";
        case 47: return "GRE";
        case 50: return "ESP";
        case 51: return "AH";
        case 89: return "OSPF";
        case 112: return "VRRP";
        case 132: return "SCTP";
        default: return "IP-" + std::to_string(p);
    }
}

std::string ip_to_string(const uint8_t* b) {
    char buf[INET_ADDRSTRLEN];
    in_addr a;
    std::memcpy(&a, b, 4);
    inet_ntop(AF_INET, &a, buf, sizeof(buf));
    return buf;
}

uint16_t be16(const uint8_t* p) { return static_cast<uint16_t>((p[0] << 8) | p[1]); }

bool find_ipv4_addresses(std::string& interface_name, std::vector<std::string>& addresses,
                         std::string& err) {
    pcap_if_t* devices = nullptr;
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    if (pcap_findalldevs(&devices, errbuf) != 0) {
        err = errbuf;
        return false;
    }

    pcap_if_t* matched_dev = nullptr;
    int idx = 1;
    for (pcap_if_t* device = devices; device; device = device->next, ++idx) {
        bool match = (interface_name == device->name);
        if (!match && interface_name == std::to_string(idx)) match = true;
        if (!match && device->description && std::string(device->description).find(interface_name) != std::string::npos) match = true;

        if (match) {
            matched_dev = device;
            interface_name = device->name; // Usar el nombre de dispositivo real para pcap_open_live
            for (pcap_addr_t* address = device->addresses; address; address = address->next) {
                if (!address->addr || address->addr->sa_family != AF_INET) continue;
                const auto* ipv4 = reinterpret_cast<const sockaddr_in*>(address->addr);
                char text[INET_ADDRSTRLEN] = {0};
                if (inet_ntop(AF_INET, &ipv4->sin_addr, text, sizeof(text))) {
                    addresses.emplace_back(text);
                }
            }
            break;
        }
    }

    pcap_freealldevs(devices);
    if (!matched_dev) {
        err = "No se encontró el dispositivo de red '" + interface_name + "'";
        return false;
    }
    return true;
}

}   

bool parse_ethernet_ipv4(const uint8_t* d, size_t caplen, uint32_t origlen, int64_t ts,
                         PacketInfo& out) {
    size_t off = 14;
    if (caplen < off) return false;
    uint16_t ethertype = be16(d + 12);
    if (ethertype == 0x8100 || ethertype == 0x88A8) {   
        if (caplen < off + 4) return false;
        ethertype = be16(d + 16);
        off += 4;
    }
    if (ethertype != 0x0800) return false;   
    if (caplen < off + 20) return false;

    const uint8_t* ip = d + off;
    if ((ip[0] >> 4) != 4) return false;
    const size_t ihl = static_cast<size_t>(ip[0] & 0x0F) * 4;
    if (ihl < 20 || caplen < off + ihl) return false;

    out = PacketInfo{};
    out.ip_proto = ip[9];
    out.protocol = protocol_name(out.ip_proto);
    out.src_ip = ip_to_string(ip + 12);
    out.dst_ip = ip_to_string(ip + 16);
    out.length = origlen;
    out.timestamp = ts;

    const uint16_t frag_offset = static_cast<uint16_t>(((ip[6] & 0x1F) << 8) | ip[7]);
    const uint8_t* l4 = ip + ihl;
    const size_t l4len = caplen - off - ihl;

    if (frag_offset != 0) return true;   

    switch (out.ip_proto) {
        case 6:  // TCP
            if (l4len >= 4) {
                out.src_port = be16(l4);
                out.dst_port = be16(l4 + 2);
            }
            if (l4len >= 14) {
                out.tcp_flag_bits = l4[13];
                out.tcp_flags = flags_to_string(l4[13]);
                const size_t tcp_header_len = static_cast<size_t>((l4[12] >> 4) * 4);
                if (tcp_header_len >= 20 && l4len > tcp_header_len) {
                    const size_t payload_len = l4len - tcp_header_len;
                    const size_t copied = payload_len > 128 ? 128 : payload_len;
                    out.service_banner.assign(
                        reinterpret_cast<const char*>(l4 + tcp_header_len),
                        copied);
                }
            }
            break;
        case 17:  // UDP
            if (l4len >= 4) {
                out.src_port = be16(l4);
                out.dst_port = be16(l4 + 2);
            }
            break;
        case 1:  // ICMP
            if (l4len >= 2) {
                out.icmp_type = l4[0];
                out.icmp_code = l4[1];
            }
            break;
        default:
            break;
    }
    return true;
}

NetworkCapture::NetworkCapture(std::string interface_name) : iface_(std::move(interface_name)) {}

NetworkCapture::~NetworkCapture() {
    if (handle_) pcap_close(handle_);
#ifdef _WIN32
    WSACleanup();
#endif
}

std::string NetworkCapture::pick_interface(std::string& err) {
    pcap_if_t* devs = nullptr;
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    if (pcap_findalldevs(&devs, errbuf) != 0) {
        err = errbuf;
        return "";
    }
    std::string chosen;
    std::cout << "[SENSOR] Interfaces de red disponibles:" << std::endl;
    int idx = 1;
    for (pcap_if_t* d = devs; d; d = d->next, ++idx) {
        if (d->flags & PCAP_IF_LOOPBACK) continue;
        if (std::strcmp(d->name, "any") == 0) continue;
        std::string ip_found = "";
        for (pcap_addr_t* a = d->addresses; a; a = a->next) {
            if (a->addr && a->addr->sa_family == AF_INET) {
                const auto* ipv4 = reinterpret_cast<const sockaddr_in*>(a->addr);
                char text[INET_ADDRSTRLEN] = {0};
                if (inet_ntop(AF_INET, &ipv4->sin_addr, text, sizeof(text))) {
                    ip_found = text;
                    break;
                }
            }
        }
        std::string desc = d->description ? d->description : d->name;
        std::cout << "  [" << idx << "] " << desc;
        if (!ip_found.empty()) std::cout << " (IPv4: " << ip_found << ")";
        std::cout << std::endl;

        if (chosen.empty() && !ip_found.empty()) {
            chosen = d->name;
        }
    }
    pcap_freealldevs(devs);
    if (chosen.empty())
        err = "No se encontró una interfaz activa con IPv4. Indica una: ./omniguard-sensor <interfaz>";
    return chosen;
}

bool NetworkCapture::open() {
    std::string err;
#ifdef _WIN32
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif

    if (iface_.empty()) {
        iface_ = pick_interface(err);
        if (iface_.empty()) {
            std::cerr << "[SENSOR] " << err << "\n";
            return false;
        }
    }

    if (!find_ipv4_addresses(iface_, local_ipv4_addresses_, err)) {
        std::cerr << "[SENSOR] " << err << "; captura cancelada por seguridad.\n";
        return false;
    }

    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    handle_ = pcap_open_live(iface_.c_str(), 128, 0, 1000, errbuf);
    if (!handle_) {
        std::cerr << "[SENSOR] No se pudo abrir '" << iface_ << "': " << errbuf
                  << " (¿ejecutaste con sudo?)\n";
        return false;
    }
    if (pcap_datalink(handle_) != DLT_EN10MB) {
        std::cerr << "[SENSOR] La interfaz '" << iface_
                  << "' no usa enlace Ethernet (DLT_EN10MB); no soportada.\n";
        pcap_close(handle_);
        handle_ = nullptr;
        return false;
    }

    const char* env = std::getenv("BPF_FILTER");
    const std::string filter = (env && *env) ? env : "ip";
    bpf_program fp;
    if (pcap_compile(handle_, &fp, filter.c_str(), 1, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "[SENSOR] Filtro BPF inválido '" << filter << "': " << pcap_geterr(handle_) << "\n";
        pcap_close(handle_);
        handle_ = nullptr;
        return false;
    }
    const int rc = pcap_setfilter(handle_, &fp);
    pcap_freecode(&fp);
    if (rc == -1) {
        std::cerr << "[SENSOR] No se pudo aplicar el filtro: " << pcap_geterr(handle_) << "\n";
        pcap_close(handle_);
        handle_ = nullptr;
        return false;
    }
    std::cout << "[SENSOR] Filtro BPF: " << filter << "\n";
    return true;
}

void NetworkCapture::run(PacketHandler handler, TickHandler tick_handler) {
    handler_ = std::move(handler);
    while (handle_) {
        const int result = pcap_dispatch(
            handle_,
            64,
            &NetworkCapture::trampoline,
            reinterpret_cast<u_char*>(this));
        if (result == PCAP_ERROR_BREAK) break;
        if (result == PCAP_ERROR) {
            std::cerr << "[SENSOR] Error durante la captura: " << pcap_geterr(handle_) << "\n";
            break;
        }
        if (tick_handler) tick_handler();
    }
}

void NetworkCapture::stop() {
    if (handle_) pcap_breakloop(handle_);
}

bool NetworkCapture::is_local_ipv4(const std::string& address) const {
    for (const auto& local_address : local_ipv4_addresses_) {
        if (address == local_address) return true;
    }
    return false;
}

void NetworkCapture::trampoline(u_char* user, const struct pcap_pkthdr* h, const u_char* bytes) {
    auto* self = reinterpret_cast<NetworkCapture*>(user);
    PacketInfo info;
    if (parse_ethernet_ipv4(bytes, h->caplen, h->len, h->ts.tv_sec, info)) {
        classify(info);
        if (self->handler_) self->handler_(info);
    }
}