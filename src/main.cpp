#include <unistd.h>

#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <string>

#include "capture.h"
#include "redis_publisher.h"

namespace {

NetworkCapture* g_capture = nullptr;

void on_signal(int) {
    if (g_capture) g_capture->stop();
}

std::string env_or(const char* name, const std::string& def) {
    const char* v = std::getenv(name);
    return (v && *v) ? v : def;
}

void print_packet(unsigned long long n, const PacketInfo& p, bool color) {
    const char* c = "";
    if (color) c = (p.risk == "HIGH") ? "\033[31m" : (p.risk == "MEDIUM") ? "\033[33m" : "";
    const char* reset = (*c) ? "\033[0m" : "";

    if (p.ip_proto == 6 || p.ip_proto == 17) {
        std::printf("%s[PKT #%llu] %s:%u → %s:%u [%s] %s · %s · %s len=%u%s\n", c, n, p.src_ip.c_str(),
                    static_cast<unsigned>(p.src_port), p.dst_ip.c_str(),
                    static_cast<unsigned>(p.dst_port), p.protocol.c_str(), p.app_protocol.c_str(),
                    p.category.c_str(), p.risk.c_str(), p.length, reset);
    } else {
        std::printf("%s[PKT #%llu] %s → %s [%s] %s · %s · %s len=%u%s\n", c, n, p.src_ip.c_str(),
                    p.dst_ip.c_str(), p.protocol.c_str(), p.app_protocol.c_str(),
                    p.category.c_str(), p.risk.c_str(), p.length, reset);
    }
    if (p.risk != "LOW") std::printf("%s    ↳ %s%s\n", c, p.risk_reason.c_str(), reset);
    std::fflush(stdout);
}

}   

int main(int argc, char** argv) {
     
    const std::string iface = (argc > 1) ? argv[1] : env_or("INTERFACE", "");
    const std::string host = env_or("REDIS_HOST", "127.0.0.1");
    const int port = std::atoi(env_or("REDIS_PORT", "6379").c_str());

    RedisPublisher publisher(host, port);
    if (!publisher.connect()) return 1;

    NetworkCapture capture(iface);
    if (!capture.open()) return 1;
    g_capture = &capture;

    struct sigaction sa {};
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);

    std::cout << "[SENSOR] Interfaz activa: " << capture.interface_name() << "\n"
              << "[SENSOR] Capturando en canal '" << publisher.channel() << "'\n"
              << "[SENSOR] Presiona Ctrl+C para detener.\n\n";

    const bool color = isatty(STDOUT_FILENO);
    unsigned long long total = 0, low = 0, medium = 0, high = 0, failed = 0;

    capture.run([&](const PacketInfo& p) {
        ++total;
        if (p.risk == "HIGH") ++high;
        else if (p.risk == "MEDIUM") ++medium;
        else ++low;

        if (!publisher.publish(p)) {
            if (++failed == 1 || failed % 100 == 0)
                std::fprintf(stderr, "[REDIS] No se pudo publicar (fallos acumulados: %llu)\n", failed);
        }
        print_packet(total, p, color);
    });

    std::printf("\n[SENSOR] Detenido. Paquetes: %llu | LOW: %llu | MEDIUM: %llu | HIGH: %llu | fallos Redis: %llu\n",
                total, low, medium, high, failed);
    return 0;
}