#pragma once

#include <atomic>
#include <cstdint>

struct TrafficMetricsSnapshot {
    uint64_t packets_per_sec = 0;
    double bandwidth_mbps = 0.0;
    uint64_t inbound = 0;
    uint64_t outbound = 0;
};

class TrafficMetricsWindow {
public:
    TrafficMetricsWindow() = default;
    TrafficMetricsWindow(const TrafficMetricsWindow&) = delete;
    TrafficMetricsWindow& operator=(const TrafficMetricsWindow&) = delete;

    void record(uint32_t packet_bytes, bool inbound);
    TrafficMetricsSnapshot snapshot(double elapsed_seconds) const;
    void reset();

private:
    std::atomic<uint64_t> packets_{0};
    std::atomic<uint64_t> bytes_{0};
    std::atomic<uint64_t> inbound_packets_{0};
    std::atomic<uint64_t> outbound_packets_{0};
};
