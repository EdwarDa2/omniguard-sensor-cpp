#include <hiredis/hiredis.h>

#include <cstdio>
#include <cstdlib>
#include <string>

#include "redis_publisher.h"

int main(int argc, char** argv) {
    if (argc != 3) {
        std::fprintf(stderr, "Uso: redis_metrics_test <host> <port>\n");
        return 2;
    }

    const std::string host = argv[1];
    const int port = std::atoi(argv[2]);
    if (port < 1 || port > 65535) {
        std::fprintf(stderr, "Puerto Redis inválido\n");
        return 2;
    }

    RedisPublisher publisher(host, port);
    if (!publisher.connect(false)) {
        std::fprintf(stderr, "No se pudo conectar a Redis\n");
        return 1;
    }

    const TrafficMetricsSnapshot metrics{42, 1.25, 30, 12};
    if (!publisher.publish_metrics(metrics)) {
        std::fprintf(stderr, "No se pudieron publicar métricas\n");
        return 1;
    }

    timeval timeout{1, 0};
    redisContext* context = redisConnectWithTimeout(host.c_str(), port, timeout);
    if (!context || context->err) {
        std::fprintf(stderr, "No se pudo verificar Redis\n");
        if (context) redisFree(context);
        return 1;
    }

    auto* value = static_cast<redisReply*>(
        redisCommand(context, "GET metrics:traffic:latest"));
    const std::string expected =
        "{\"packets_per_sec\":42,\"bandwidth_mbps\":1.250000,"
        "\"sensor_status\":\"ACTIVE\",\"inbound\":30,\"outbound\":12}";
    const bool value_matches =
        value && value->type == REDIS_REPLY_STRING && value->str &&
        expected == std::string(value->str, value->len);
    if (value) freeReplyObject(value);

    auto* ttl = static_cast<redisReply*>(
        redisCommand(context, "TTL metrics:traffic:latest"));
    const bool ttl_matches =
        ttl && ttl->type == REDIS_REPLY_INTEGER && ttl->integer >= 0 && ttl->integer <= 15;
    if (ttl) freeReplyObject(ttl);
    redisFree(context);

    if (!value_matches || !ttl_matches) {
        std::fprintf(stderr, "El payload o el TTL de telemetría no coincide\n");
        return 1;
    }

    std::printf("OK: payload real en Redis y TTL de 15 segundos\n");
    return 0;
}
