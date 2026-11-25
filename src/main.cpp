#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <string>

#ifdef _WIN32
#include <io.h>
#define OMNIGUARD_ISATTY _isatty
#define OMNIGUARD_STDOUT_FILENO _fileno(stdout)
#else
#include <unistd.h>
#define OMNIGUARD_ISATTY isatty
#define OMNIGUARD_STDOUT_FILENO STDOUT_FILENO
#endif

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

    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);

    std::cout << "[SENSOR] Interfaz activa: " << capture.interface_name() << "\n"
              << "[SENSOR] Capturando en canal '" << publisher.channel() << "'\n"
              << "[SENSOR] Presiona Ctrl+C para detener.\n\n";

    const bool color = OMNIGUARD_ISATTY(OMNIGUARD_STDOUT_FILENO) != 0;
    unsigned long long total = 0, low = 0, medium = 0, high = 0, failed = 0;
    TrafficMetricsWindow metrics;
    auto window_started = std::chrono::steady_clock::now();

    capture.run(
        [&](const PacketInfo& p) {
            ++total;
            if (p.risk == "HIGH") ++high;
            else if (p.risk == "MEDIUM") ++medium;
            else ++low;

            if (capture.is_local_ipv4(p.src_ip) || capture.is_local_ipv4(p.dst_ip)) {
                const bool inbound = !capture.is_local_ipv4(p.src_ip) &&
                                     capture.is_local_ipv4(p.dst_ip);
                metrics.record(p.length, inbound);
            }

            if (!publisher.publish(p)) {
                if (++failed == 1 || failed % 100 == 0)
                    std::fprintf(stderr, "[REDIS] No se pudo publicar (fallos acumulados: %llu)\n", failed);
            }
            print_packet(total, p, color);
        },
        [&]() {
            const auto now = std::chrono::steady_clock::now();
            const double elapsed = std::chrono::duration<double>(now - window_started).count();
            if (elapsed < 5.0) return;

            if (!publisher.publish_metrics(metrics.snapshot(elapsed))) {
                if (++failed == 1 || failed % 100 == 0)
                    std::fprintf(stderr, "[REDIS] No se pudo publicar telemetría (fallos acumulados: %llu)\n", failed);
            }
            metrics.reset();
            window_started = now;
        });

    std::printf("\n[SENSOR] Detenido. Paquetes: %llu | LOW: %llu | MEDIUM: %llu | HIGH: %llu | fallos Redis: %llu\n",
                total, low, medium, high, failed);
    return 0;
}