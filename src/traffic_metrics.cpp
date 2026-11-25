#include "traffic_metrics.h"

#include <cmath>

void TrafficMetricsWindow::record(uint32_t packet_bytes, bool inbound) {
    ++packets_;
    bytes_ += packet_bytes;
    if (inbound) {
        ++inbound_packets_;
    } else {
        ++outbound_packets_;
    }
}

TrafficMetricsSnapshot TrafficMetricsWindow::snapshot(double elapsed_seconds) const {
    if (elapsed_seconds <= 0.0) {
        return {};
    }

    return {
        static_cast<uint64_t>(std::llround(packets_ / elapsed_seconds)),
        (static_cast<double>(bytes_) * 8.0) / (elapsed_seconds * 1024.0 * 1024.0),
        static_cast<uint64_t>(std::llround(inbound_packets_ / elapsed_seconds)),
        static_cast<uint64_t>(std::llround(outbound_packets_ / elapsed_seconds)),
    };
}

void TrafficMetricsWindow::reset() {
    packets_ = 0;
    bytes_ = 0;
    inbound_packets_ = 0;
    outbound_packets_ = 0;
}
