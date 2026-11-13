#include "redis_publisher.h"

#include <hiredis/hiredis.h>

#include <cstdio>
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
            freeReplyObject(reply);
            return true;
        }
        redisFree(ctx_);
        ctx_ = nullptr;
    }
    return false;
}