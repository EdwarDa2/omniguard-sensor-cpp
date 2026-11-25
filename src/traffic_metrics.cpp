#include "traffic_metrics.h"

#include <cmath>

void TrafficMetricsWindow::record(uint32_t packet_bytes, bool inbound) {
    packets_.fetch_add(1, std::memory_order_relaxed);
    bytes_.fetch_add(packet_bytes, std::memory_order_relaxed);
    if (inbound) {
        inbound_packets_.fetch_add(1, std::memory_order_relaxed);
    } else {
        outbound_packets_.fetch_add(1, std::memory_order_relaxed);
    }
}

TrafficMetricsSnapshot TrafficMetricsWindow::snapshot(double elapsed_seconds) const {
    if (elapsed_seconds <= 0.0) {
        return {};
    }

    const uint64_t p = packets_.load(std::memory_order_relaxed);
    const uint64_t b = bytes_.load(std::memory_order_relaxed);
    const uint64_t in = inbound_packets_.load(std::memory_order_relaxed);
    const uint64_t out = outbound_packets_.load(std::memory_order_relaxed);

    return {
        static_cast<uint64_t>(std::llround(p / elapsed_seconds)),
        (static_cast<double>(b) * 8.0) / (elapsed_seconds * 1024.0 * 1024.0),
        static_cast<uint64_t>(std::llround(in / elapsed_seconds)),
        static_cast<uint64_t>(std::llround(out / elapsed_seconds)),
    };
}

void TrafficMetricsWindow::reset() {
    packets_.store(0, std::memory_order_relaxed);
    bytes_.store(0, std::memory_order_relaxed);
    inbound_packets_.store(0, std::memory_order_relaxed);
    outbound_packets_.store(0, std::memory_order_relaxed);
}
