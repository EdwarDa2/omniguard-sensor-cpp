#pragma once

#include <chrono>
#include <deque>
#include <mutex>
#include <string>
#include <vector>

#include "capture.h"
#include "traffic_metrics.h"

struct HttpHistoryPoint {
    std::string time;
    uint64_t inbound = 0;
    uint64_t outbound = 0;
};

class HttpPublisher {
public:
    HttpPublisher(std::string base_url, std::string auth_token, std::string sensor_id = "");
    ~HttpPublisher();

    HttpPublisher(const HttpPublisher&) = delete;
    HttpPublisher& operator=(const HttpPublisher&) = delete;

    bool publish(const PacketInfo& pkt);
    bool flush();
    bool publish_metrics(const TrafficMetricsSnapshot& metrics, const std::string& sensor_status = "ACTIVE", int open_ports = 0);

    static std::string to_json(const PacketInfo& pkt);

    const std::string& base_url() const { return base_url_; }
    const std::string& auth_token() const { return auth_token_; }

private:
    bool send_post(const std::string& path, const std::string& json_payload);

    std::string base_url_;
    std::string auth_token_;
    std::string sensor_id_;
    std::mutex mutex_{};
    std::deque<HttpHistoryPoint> history_{};
    std::vector<PacketInfo> batch_buffer_{};
    std::chrono::steady_clock::time_point last_flush_{};
};
