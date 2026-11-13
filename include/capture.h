#pragma once

#include <pcap.h>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>

 
struct PacketInfo {
    std::string src_ip;
    std::string dst_ip;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    std::string protocol = "UNKNOWN";   
    uint8_t ip_proto = 0;               
    uint32_t length = 0;                
    int tcp_flag_bits = -1;             
    std::string tcp_flags;              
    int icmp_type = -1;
    int icmp_code = -1;

     
    std::string app_protocol = "Desconocido";
    std::string category = "desconocido";
    std::string risk = "LOW";           
    std::string risk_reason;
};

 
bool parse_ethernet_ipv4(const uint8_t* data, size_t caplen, uint32_t origlen,
                         int64_t timestamp, PacketInfo& out);

class NetworkCapture {
public:
    using PacketHandler = std::function<void(const PacketInfo&)>;

    
    explicit NetworkCapture(std::string interface_name = "");
    ~NetworkCapture();
    NetworkCapture(const NetworkCapture&) = delete;
    NetworkCapture& operator=(const NetworkCapture&) = delete;

    bool open();
    void run(PacketHandler handler);   
    void stop();
    const std::string& interface_name() const { return iface_; }

private:
    static void trampoline(u_char* user, const struct pcap_pkthdr* h, const u_char* bytes);
    static std::string pick_interface(std::string& err);

    std::string iface_;
    pcap_t* handle_ = nullptr;
    PacketHandler handler_;
};