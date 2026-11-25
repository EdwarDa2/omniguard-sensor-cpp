#include "redis_publisher.h"

#include <hiredis/hiredis.h>

#include <cstdio>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <sstream>

namespace {

std::string json_escape(const std::string& s) {
    std::string o;
    o.reserve(s.size() + 2);
    for (unsigned char c : s) {
        switch (c) {
            case '"': o += "\\\""; break;
            case '\\': o += "\\\\"; break;
            case '\n': o += "\\n"; break;
            case '\r': o += "\\r"; break;
            case '\t': o += "\\t"; break;
            default:
                if (c < 0x20) {
                    char b[8];
                    std::snprintf(b, sizeof(b), "\\u%04x", c);
                    o += b;
                } else {
                    o += static_cast<char>(c);
                }
        }
    }
    return o;
}

}  // namespace

RedisPublisher::RedisPublisher(std::string host, int port, std::string channel)
    : host_(std::move(host)), port_(port), channel_(std::move(channel)) {}

RedisPublisher::~RedisPublisher() {
    if (ctx_) redisFree(ctx_);
}

bool RedisPublisher::connect(bool verbose) {
    if (ctx_) {
        redisFree(ctx_);
        ctx_ = nullptr;
    }
    last_attempt_ = std::chrono::steady_clock::now();
    timeval tv{1, 0};
    ctx_ = redisConnectWithTimeout(host_.c_str(), port_, tv);
    if (!ctx_ || ctx_->err) {
        if (verbose)
            std::cerr << "[REDIS] No se pudo conectar a " << host_ << ":" << port_ << " - "
                      << (ctx_ ? ctx_->errstr : "sin memoria") << "\n";
        if (ctx_) {
            redisFree(ctx_);
            ctx_ = nullptr;
        }
        return false;
    }
    if (verbose) std::cout << "[REDIS] Conectado a " << host_ << ":" << port_ << "\n";
    return true;
}

std::string RedisPublisher::to_json(const PacketInfo& p) {
    std::ostringstream j;
    j << "{\"src_ip\":\"" << json_escape(p.src_ip) << "\""
      << ",\"dst_ip\":\"" << json_escape(p.dst_ip) << "\""
      << ",\"src_port\":" << p.src_port
      << ",\"dst_port\":" << p.dst_port
      << ",\"protocol\":\"" << json_escape(p.protocol) << "\""
      << ",\"length\":" << p.length
      << ",\"timestamp\":" << p.timestamp
      << ",\"app_protocol\":\"" << json_escape(p.app_protocol) << "\""
      << ",\"category\":\"" << json_escape(p.category) << "\""
      << ",\"risk\":\"" << json_escape(p.risk) << "\""
      << ",\"risk_reason\":\"" << json_escape(p.risk_reason) << "\"";
    if (p.tcp_flag_bits >= 0) j << ",\"tcp_flags\":\"" << json_escape(p.tcp_flags) << "\"";
    if (p.icmp_type >= 0) j << ",\"icmp_type\":" << p.icmp_type;
    if (!p.product_version.empty())
        j << ",\"product_version\":\"" << json_escape(p.product_version) << "\"";
    if (!p.cpe_name.empty())
        j << ",\"cpe_name\":\"" << json_escape(p.cpe_name) << "\"";
    j << "}";
    return j.str();
}

bool RedisPublisher::publish(const PacketInfo& pkt) {
    const std::string json = to_json(pkt);
    for (int attempt = 0; attempt < 2; ++attempt) {
        if (!ctx_) {
             
            const auto now = std::chrono::steady_clock::now();
            if (now - last_attempt_ < std::chrono::seconds(2) || !connect(false)) return false;
        }
        auto* reply = static_cast<redisReply*>(
            redisCommand(ctx_, "PUBLISH %s %b", channel_.c_str(), json.data(), json.size()));
        if (reply) {
            const bool success = reply->type != REDIS_REPLY_ERROR;
            freeReplyObject(reply);
            return success;
        }
        redisFree(ctx_);
        ctx_ = nullptr;
    }
    return false;
}

bool RedisPublisher::publish_metrics(const TrafficMetricsSnapshot& metrics, const std::string& sensor_status) {
    std::ostringstream json;
    json << std::fixed << std::setprecision(6)
         << "{\"packets_per_sec\":" << metrics.packets_per_sec
         << ",\"bandwidth_mbps\":" << metrics.bandwidth_mbps
         << ",\"sensor_status\":\"" << json_escape(sensor_status) << "\""
         << ",\"inbound\":" << metrics.inbound
         << ",\"outbound\":" << metrics.outbound
         << "}";
    const std::string payload = json.str();

    // Obtener marca de tiempo actual en UTC HH:mm:ss
    auto now = std::chrono::system_clock::now();
    std::time_t tt = std::chrono::system_clock::to_time_t(now);
    std::tm gm{};
#ifdef _WIN32
    gmtime_s(&gm, &tt);
#else
    gmtime_r(&tt, &gm);
#endif
    char time_buf[16];
    std::strftime(time_buf, sizeof(time_buf), "%H:%M:%S", &gm);

    // Agregar punto a la serie histórica en memoria (máximo 15 puntos acumulados)
    history_.push_back({time_buf, metrics.inbound, metrics.outbound});
    while (history_.size() > 15) {
        history_.pop_front();
    }

    // Serializar arreglo histórico
    std::ostringstream hist_json;
    hist_json << "[";
    for (size_t i = 0; i < history_.size(); ++i) {
        if (i > 0) hist_json << ",";
        hist_json << "{\"time\":\"" << json_escape(history_[i].time) << "\""
                  << ",\"inbound\":" << history_[i].inbound
                  << ",\"outbound\":" << history_[i].outbound
                  << "}";
    }
    hist_json << "]";
    const std::string hist_payload = hist_json.str();

    for (int attempt = 0; attempt < 2; ++attempt) {
        if (!ctx_) {
            const auto steady_now = std::chrono::steady_clock::now();
            if (steady_now - last_attempt_ < std::chrono::seconds(2) || !connect(false)) return false;
        }
        auto* reply = static_cast<redisReply*>(
            redisCommand(ctx_, "SETEX metrics:traffic:latest 15 %b", payload.data(), payload.size()));
        if (reply) {
            const bool success = reply->type != REDIS_REPLY_ERROR;
            freeReplyObject(reply);

            // Almacenar serie temporal en Redis para el dashboard
            auto* hist_reply = static_cast<redisReply*>(
                redisCommand(ctx_, "SETEX metrics:traffic:history 60 %b", hist_payload.data(), hist_payload.size()));
            if (hist_reply) freeReplyObject(hist_reply);

            // Publicar evento en canal de telemetría viva
            auto* pub_reply = static_cast<redisReply*>(
                redisCommand(ctx_, "PUBLISH metrics:traffic %b", payload.data(), payload.size()));
            if (pub_reply) freeReplyObject(pub_reply);

            return success;
        }
        redisFree(ctx_);
        ctx_ = nullptr;
    }
    return false;
}