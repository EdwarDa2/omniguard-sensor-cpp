#include "redis_publisher.h"
#include <iostream>
#include <sstream>
#include <iomanip>

// ── Constructor ───────────────────────────────────────────────────────────────
RedisPublisher::RedisPublisher(const std::string& host, int port)
{
    struct timeval timeout = {2, 0}; // 2 segundos de timeout
    ctx_ = redisConnectWithTimeout(host.c_str(), port, timeout);

    if (!ctx_ || ctx_->err) {
        std::cerr << "[REDIS] Error de conexión: "
                  << (ctx_ ? ctx_->errstr : "no se pudo alocar contexto")
                  << "\n";
        if (ctx_) {
            redisFree(ctx_);
            ctx_ = nullptr;
        }
    } else {
        std::cout << "[REDIS] Conectado a " << host << ":" << port << "\n";
    }
}

// ── Destructor ────────────────────────────────────────────────────────────────
RedisPublisher::~RedisPublisher()
{
    if (ctx_) {
        redisFree(ctx_);
        ctx_ = nullptr;
    }
}

// ── publish ───────────────────────────────────────────────────────────────────
bool RedisPublisher::publish(const std::string& channel, const PacketInfo& pkt)
{
    if (!ctx_) return false;

    const std::string json = to_json(pkt);

    auto* reply = static_cast<redisReply*>(
        redisCommand(ctx_, "PUBLISH %s %s", channel.c_str(), json.c_str())
    );

    if (!reply) {
        std::cerr << "[REDIS] Error al publicar: " << ctx_->errstr << "\n";
        return false;
    }

    bool ok = (reply->type == REDIS_REPLY_INTEGER);
    freeReplyObject(reply);
    return ok;
}

// ── to_json ───────────────────────────────────────────────────────────────────
std::string RedisPublisher::to_json(const PacketInfo& pkt) const
{
    // Escapado simple de strings para evitar inyección en JSON
    auto escape = [](const std::string& s) -> std::string {
        std::string out;
        for (char c : s) {
            if (c == '"')  out += "\\\"";
            else if (c == '\\') out += "\\\\";
            else out += c;
        }
        return out;
    };

    std::ostringstream ss;
    ss << "{"
       << "\"src_ip\":"   << "\"" << escape(pkt.src_ip)  << "\","
       << "\"dst_ip\":"   << "\"" << escape(pkt.dst_ip)  << "\","
       << "\"src_port\":"          << pkt.src_port        << ","
       << "\"dst_port\":"          << pkt.dst_port        << ","
       << "\"protocol\":" << "\"" << escape(pkt.protocol) << "\","
       << "\"length\":"            << pkt.packet_len      << ","
       << "\"timestamp\":"         << pkt.timestamp
       << "}";

    return ss.str();
}