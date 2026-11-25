#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <string>
#include <thread>

#ifdef _WIN32
#include <io.h>
#define OMNIGUARD_ISATTY _isatty
#define OMNIGUARD_STDOUT_FILENO _fileno(stdout)
#else
#include <unistd.h>
#define OMNIGUARD_ISATTY isatty
#define OMNIGUARD_STDOUT_FILENO STDOUT_FILENO
#endif

#include <hiredis/hiredis.h>

#include "capture.h"
#include "redis_publisher.h"

namespace {

NetworkCapture* g_capture = nullptr;
std::atomic<bool> g_paused{false};
std::atomic<bool> g_running{true};

void on_signal(int) {
    g_running.store(false);
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

void check_initial_state(const std::string& host, int port) {
    timeval tv{1, 500000};
    redisContext* ctx = redisConnectWithTimeout(host.c_str(), port, tv);
    if (!ctx || ctx->err) {
        if (ctx) redisFree(ctx);
        return;
    }
    auto* reply = static_cast<redisReply*>(redisCommand(ctx, "GET sensor:desired_state"));
    if (reply) {
        if (reply->type == REDIS_REPLY_STRING && reply->str) {
            std::string state(reply->str);
            if (state == "PAUSED" || state == "STOP") {
                g_paused.store(true);
                std::cout << "[SENSOR] Estado inicial configurado en Redis: PAUSED" << std::endl;
            }
        }
        freeReplyObject(reply);
    }
    redisFree(ctx);
}

}   // namespace

int main(int argc, char** argv) {
    const std::string iface = (argc > 1) ? argv[1] : env_or("INTERFACE", "");
    const std::string host = env_or("REDIS_HOST", "127.0.0.1");
    const int port = std::atoi(env_or("REDIS_PORT", "6379").c_str());
    const std::string cmd_channel = env_or("SENSOR_COMMANDS_CHANNEL", "sensor_commands_channel");

    RedisPublisher publisher(host, port);
    if (!publisher.connect()) return 1;

    // Verificar si el estado guardado en Redis es PAUSED
    check_initial_state(host, port);

    // Hilo dedicado para escuchar comandos de control remoto desde Redis
    std::thread cmd_thread([host, port, cmd_channel]() {
        while (g_running.load()) {
            timeval tv{2, 0};
            redisContext* ctx = redisConnectWithTimeout(host.c_str(), port, tv);
            if (!ctx || ctx->err) {
                if (ctx) redisFree(ctx);
                std::this_thread::sleep_for(std::chrono::seconds(2));
                continue;
            }

            auto* reply = static_cast<redisReply*>(redisCommand(ctx, "SUBSCRIBE %s", cmd_channel.c_str()));
            if (reply) freeReplyObject(reply);
            std::cout << "[SENSOR] Escuchando comandos en canal Redis '" << cmd_channel << "'" << std::endl;

            while (g_running.load()) {
                void* r = nullptr;
                if (redisGetReply(ctx, &r) == REDIS_OK && r) {
                    auto* rep = static_cast<redisReply*>(r);
                    if (rep->type == REDIS_REPLY_ARRAY && rep->elements == 3) {
                        const std::string msg_type = (rep->element[0] && rep->element[0]->str) ? rep->element[0]->str : "";
                        if (msg_type == "message" && rep->element[2] && rep->element[2]->str) {
                            const std::string payload = rep->element[2]->str;
                            if (payload.find("PAUSE") != std::string::npos || payload.find("STOP") != std::string::npos) {
                                g_paused.store(true);
                                std::cout << "\n[SENSOR] >>> Comando recibido: PAUSA. Captura de paquetes suspendida." << std::endl;
                            } else if (payload.find("RESUME") != std::string::npos || payload.find("START") != std::string::npos) {
                                g_paused.store(false);
                                std::cout << "\n[SENSOR] >>> Comando recibido: ACTIVAR. Captura de paquetes reanudada." << std::endl;
                            }
                        }
                    }
                    freeReplyObject(rep);
                } else {
                    break;
                }
            }
            if (ctx) redisFree(ctx);
            if (g_running.load()) {
                std::this_thread::sleep_for(std::chrono::seconds(2));
            }
        }
    });

    NetworkCapture capture(iface);
    if (!capture.open()) {
        g_running.store(false);
        if (cmd_thread.joinable()) cmd_thread.detach();
        return 1;
    }
    g_capture = &capture;

    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);

    std::cout << "[SENSOR] Interfaz activa: " << capture.interface_name() << std::endl
              << "[SENSOR] Capturando en canal '" << publisher.channel() << "'" << std::endl
              << "[SENSOR] Presiona Ctrl+C para detener." << std::endl << std::endl;

    const bool color = OMNIGUARD_ISATTY(OMNIGUARD_STDOUT_FILENO) != 0;
    unsigned long long total = 0, low = 0, medium = 0, high = 0, failed = 0;
    TrafficMetricsWindow metrics;

    // Hilo dedicado de telemetría: publica métricas e historial a Redis cada 5s
    std::thread ticker_thread([&publisher, &metrics, &failed]() {
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

            if (!publisher.publish_metrics(snap, status)) {
                if (++failed == 1 || failed % 100 == 0)
                    std::fprintf(stderr, "[REDIS] No se pudo publicar telemetría (fallos acumulados: %llu)\n", failed);
            }
            metrics.reset();
        }
    });

    capture.run(
        [&](const PacketInfo& p) {
            // Si el sensor está pausado por el Frontend, descartar procesamiento
            if (g_paused.load()) {
                return;
            }

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
        });

    g_running.store(false);
    if (cmd_thread.joinable()) cmd_thread.detach();
    if (ticker_thread.joinable()) ticker_thread.detach();

    std::printf("\n[SENSOR] Detenido. Paquetes: %llu | LOW: %llu | MEDIUM: %llu | HIGH: %llu | fallos Redis: %llu\n",
                total, low, medium, high, failed);
    return 0;
}
