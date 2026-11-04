#pragma once

#include <string>
#include <hiredis/hiredis.h>
#include "capture.h"

class RedisPublisher {
public:
    // host y port del contenedor Redis (por defecto: localhost:6379)
    RedisPublisher(const std::string& host = "127.0.0.1", int port = 6379);
    ~RedisPublisher();

    // Serializa PacketInfo a JSON y hace PUBLISH al canal indicado
    bool publish(const std::string& channel, const PacketInfo& pkt);

    bool is_connected() const { return ctx_ != nullptr; }

private:
    std::string  to_json(const PacketInfo& pkt) const;

    redisContext* ctx_ = nullptr;
};