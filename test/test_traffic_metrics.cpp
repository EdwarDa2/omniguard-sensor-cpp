#include <cmath>
#include <cstdio>

#include "traffic_metrics.h"

static int failures = 0;

#define CHECK(condition)                                                   \
    do {                                                                   \
        if (!(condition)) {                                                \
            std::printf("FALLO (línea %d): %s\n", __LINE__, #condition);   \
            ++failures;                                                    \
        }                                                                  \
    } while (false)

int main() {
    TrafficMetricsWindow window;
    for (int i = 0; i < 5; ++i) {
        window.record(100, true);
        window.record(100, false);
    }

    const auto metrics = window.snapshot(5.0);
    CHECK(metrics.packets_per_sec == 2);
    CHECK(metrics.inbound == 1);
    CHECK(metrics.outbound == 1);
    CHECK(std::abs(metrics.bandwidth_mbps - (8000.0 / (5.0 * 1024.0 * 1024.0))) < 1e-12);

    window.reset();
    const auto empty = window.snapshot(5.0);
    CHECK(empty.packets_per_sec == 0);
    CHECK(empty.bandwidth_mbps == 0.0);
    CHECK(empty.inbound == 0);
    CHECK(empty.outbound == 0);
    CHECK(window.snapshot(0.0).packets_per_sec == 0);

    if (failures == 0) std::printf("OK: métricas de tráfico verificadas\n");
    return failures ? 1 : 0;
}
