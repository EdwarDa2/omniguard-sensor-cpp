#include <iostream>
#include <csignal>
#include <atomic>
#include "capture.h"
#include "redis_publisher.h"

// ── Control de señales (Ctrl+C) ───────────────────────────────────────────────
static std::atomic<bool> g_running{true};
static NetworkCapture*   g_capture_ptr = nullptr;

void signal_handler(int) {
    std::cout << "\n[SENSOR] Deteniendo captura...\n";
    g_running = false;
    if (g_capture_ptr) g_capture_ptr->stop();
}

// ── Main ──────────────────────────────────────────────────────────────────────
int main(int argc, char* argv[])
{
    std::signal(SIGINT,  signal_handler);
    std::signal(SIGTERM, signal_handler);

    // Interfaz opcional: ./omniguard-sensor eth0
    std::string iface = (argc > 1) ? argv[1] : "";

    // ── Redis ─────────────────────────────────────────────────────────────────
    const std::string REDIS_HOST    = "127.0.0.1";
    const int         REDIS_PORT    = 6379;
    const std::string REDIS_CHANNEL = "network_events";

    RedisPublisher redis(REDIS_HOST, REDIS_PORT);
    if (!redis.is_connected()) {
        std::cerr << "[ERROR] No se pudo conectar a Redis. "
                  << "¿Está corriendo el contenedor?\n";
        return 1;
    }

    // ── Captura ───────────────────────────────────────────────────────────────
    NetworkCapture capture(iface);
    g_capture_ptr = &capture;

    std::cout << "[SENSOR] Capturando en canal '" << REDIS_CHANNEL << "'\n";
    std::cout << "[SENSOR] Presiona Ctrl+C para detener.\n\n";

    int packet_count = 0;

    // Captura indefinida (-1); Ctrl+C rompe el loop
    capture.start(-1, [&](const PacketInfo& pkt) {
        packet_count++;

        // Imprime en consola
        std::cout << "[PKT #" << packet_count << "] "
                  << pkt.src_ip << ":" << pkt.src_port
                  << " → "
                  << pkt.dst_ip << ":" << pkt.dst_port
                  << " [" << pkt.protocol << "]"
                  << " len=" << pkt.packet_len << "\n";

        // Publica en Redis
        if (!redis.publish(REDIS_CHANNEL, pkt)) {
            std::cerr << "[WARN] Fallo al publicar paquete #" << packet_count << "\n";
        }
    });

    std::cout << "[SENSOR] Total paquetes capturados: " << packet_count << "\n";
    return 0;
}