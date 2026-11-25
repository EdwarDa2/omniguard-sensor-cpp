#pragma once

#include <chrono>
#include <string>

#include "capture.h"
#include "traffic_metrics.h"

struct redisContext;

class RedisPublisher {
public:
    RedisPublisher(std::string host, int port, std::string channel = "network_events");
    ~RedisPublisher();
    RedisPublisher(const RedisPublisher&) = delete;
    RedisPublisher& operator=(const RedisPublisher&) = delete;

    bool connect(bool verbose = true);
    bool publish(const PacketInfo& pkt);
    bool publish_metrics(const TrafficMetricsSnapshot& metrics);

    const std::string& host() const { return host_; }
    int port() const { return port_; }
    const std::string& channel() const { return channel_; }

    static std::string to_json(const PacketInfo& pkt);

private:
    std::string host_;
    int port_;
    std::string channel_;
    redisContext* ctx_ = nullptr;
    std::chrono::steady_clock::time_point last_attempt_{};
};