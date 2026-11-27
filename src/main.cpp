#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <io.h>
#include <set>
#define OMNIGUARD_ISATTY _isatty
#define OMNIGUARD_STDOUT_FILENO _fileno(stdout)
#else
#include <unistd.h>
#define OMNIGUARD_ISATTY isatty
#define OMNIGUARD_STDOUT_FILENO STDOUT_FILENO
#endif

#include "capture.h"
#include "http_publisher.h"

#ifndef _WIN32
#include <hiredis/hiredis.h>
#include "redis_publisher.h"
#endif

namespace {

NetworkCapture* g_capture = nullptr;
std::atomic<bool> g_paused{false};
std::atomic<bool> g_running{true};

void on_signal(int) {
    g_running.store(false);
    if (g_capture) g_capture->stop();
}

#ifdef _WIN32
BOOL WINAPI console_ctrl_handler(DWORD ctrl_type) {
    if (ctrl_type == CTRL_C_EVENT || ctrl_type == CTRL_BREAK_EVENT || ctrl_type == CTRL_CLOSE_EVENT) {
        g_running.store(false);
        if (g_capture) g_capture->stop();
        return TRUE;
    }
    return FALSE;
}
#endif

int audit_local_listening_ports() {
#ifdef _WIN32
    DWORD dwSize = 0;
    GetExtendedTcpTable(nullptr, &dwSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (dwSize == 0) return 0;

    std::vector<BYTE> buffer(dwSize);
    auto pTable = reinterpret_cast<PMIB_TCPTABLE_OWNER_PID>(buffer.data());

    if (GetExtendedTcpTable(pTable, &dwSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
        std::set<uint16_t> distinct_listening_ports;
        for (DWORD i = 0; i < pTable->dwNumEntries; ++i) {
            if (pTable->table[i].dwState == MIB_TCP_STATE_LISTEN) {
                uint16_t port = ntohs(static_cast<u_short>(pTable->table[i].dwLocalPort));
                if (port > 0) {
                    distinct_listening_ports.insert(port);
                }
            }
        }
        return static_cast<int>(distinct_listening_ports.size());
    }
    return 0;
#else
    return 0;
#endif
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

}   // namespace

int main(int argc, char** argv) {
    std::string iface = "";
    std::string ingest_url = env_or("INGEST_URL", "http://165.227.121.157/api/v1/internal/telemetry");
    std::string token = env_or("INTERNAL_API_TOKEN", "omniguard_m2m_secret_token_2026_soc_prod");
    std::string sensor_id = env_or("SENSOR_ID", "");

#ifdef _WIN32
    SetConsoleCtrlHandler(console_ctrl_handler, TRUE);
    if (ingest_url.empty()) {
        ingest_url = "http://165.227.121.157/api/v1/internal/telemetry";
    }
#endif

    // Procesar argumentos de línea de comandos
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--url" && i + 1 < argc) {
            ingest_url = argv[++i];
        } else if (arg == "--token" && i + 1 < argc) {
            token = argv[++i];
        } else if (arg == "--sensor-id" && i + 1 < argc) {
            sensor_id = argv[++i];
        } else if (iface.empty() && arg.rfind("--", 0) != 0) {
            iface = arg;
        }
    }

    if (sensor_id.empty()) {
        const char* comp = std::getenv("COMPUTERNAME");
        sensor_id = (comp && *comp) ? comp : "default-host";
    }

    std::cout << "========================================================\n"
              << "       OmniGuard SOC Network Sensor (Windows/Linux)      \n"
              << "========================================================\n"
              << "[SENSOR] Modo: Enlace Seguro HTTP/HTTPS\n"
              << "[SENSOR] Servidor Cloud: " << ingest_url << "\n"
              << "[SENSOR] Identificador de Host (Sensor ID): " << sensor_id << "\n"
              << "[SENSOR] Token M2M: " << (token.empty() ? "(ninguno)" : "(configurado)") << "\n"
              << "--------------------------------------------------------\n";

    HttpPublisher publisher(ingest_url, token, sensor_id);

    NetworkCapture capture(iface);
    if (!capture.open()) {
        std::cerr << "[SENSOR] Error al iniciar la captura de red.\n";
        return 1;
    }
    g_capture = &capture;

    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);

    const int initial_open_ports = audit_local_listening_ports();
    std::cout << "[AUDITORÍA] Puertos locales activos en escucha (LISTENING): " << initial_open_ports << "\n"
              << "[SENSOR] Interfaz activa: " << capture.interface_name() << "\n"
              << "[SENSOR] Capturando tráfico y transmitiendo a la nube...\n"
              << "[SENSOR] Presiona Ctrl+C para detener.\n\n";

    const bool color = OMNIGUARD_ISATTY(OMNIGUARD_STDOUT_FILENO) != 0;
    unsigned long long total = 0, low = 0, medium = 0, high = 0, failed = 0;
    TrafficMetricsWindow metrics;

    // Hilo dedicado de telemetría: publica métricas e historial al backend cada 5s
    std::thread ticker_thread([&publisher, &metrics, &failed]() {
        // Burst inicial t=0s para sincronización instantánea con el SOC Dashboard
        {
            TrafficMetricsSnapshot initial_snap{0, 0.0, 0, 0};
            const int open_ports = audit_local_listening_ports();
            if (!publisher.publish_metrics(initial_snap, "ACTIVE", open_ports)) {
                if (++failed == 1)
                    std::fprintf(stderr, "[TELEMETRÍA] Advertencia: Fallo en burst inicial t=0s\n");
            } else {
                std::printf("[TELEMETRÍA] Burst inicial t=0s enviado exitosamente. Puertos abiertos detectados: %d\n", open_ports);
                std::fflush(stdout);
            }
        }

        auto window_started = std::chrono::steady_clock::now();
        while (g_running.load()) {
            std::this_thread::sleep_for(std::chrono::seconds(5));
            if (!g_running.load()) break;

            const auto now = std::chrono::steady_clock::now();
            const double elapsed = std::chrono::duration<double>(now - window_started).count();
            window_started = now;

            const bool is_paused = g_paused.load();
            const std::string status = is_paused ? "PAUSED" : "ACTIVE";
            TrafficMetricsSnapshot snap = is_paused ? TrafficMetricsSnapshot{0, 0.0, 0, 0} : metrics.snapshot(elapsed);
            const int open_ports = audit_local_listening_ports();

            if (!publisher.publish_metrics(snap, status, open_ports)) {
                if (++failed == 1 || failed % 20 == 0)
                    std::fprintf(stderr, "[TELEMETRÍA] Advertencia: No se pudo enviar métricas (intentos fallidos: %llu)\n", failed);
            }
            metrics.reset();
        }
    });

    // Bucle principal de captura de paquetes
    capture.run(
        [&](const PacketInfo& p) {
            if (g_paused.load()) return;

            ++total;
            if (p.risk == "HIGH") ++high;
            else if (p.risk == "MEDIUM") ++medium;
            else ++low;

            const bool inbound = !capture.is_local_ipv4(p.src_ip);
            metrics.record(p.length, inbound);

            if (!publisher.publish(p)) {
                if (++failed == 1 || failed % 50 == 0)
                    std::fprintf(stderr, "[TELEMETRÍA] Advertencia: No se pudo enviar evento a la nube (fallos: %llu)\n", failed);
            }
            print_packet(total, p, color);
        });

    g_running.store(false);
    publisher.flush();
    if (ticker_thread.joinable()) ticker_thread.join();

    std::printf("\n========================================================\n"
                "[SENSOR] Detenido. Paquetes: %llu | LOW: %llu | MEDIUM: %llu | HIGH: %llu | Fallos de red: %llu\n"
                "========================================================\n",
                total, low, medium, high, failed);
    return 0;
}
