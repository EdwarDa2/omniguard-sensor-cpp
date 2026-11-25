# Despliegue web — OmniGuard Sensor C++

Consulte el plan maestro en el repositorio central:

[WEB-DEPLOYMENT-PLAN.md](../WEB-DEPLOYMENT-PLAN.md)

## Rol

Captura tráfico propio con libpcap sin modo promiscuo, clasifica eventos y
publica métricas en Redis.

## Variables

```text
REDIS_HOST
REDIS_PORT
INTERFACE
BPF_FILTER
```

El sensor actualiza `metrics:traffic:latest` cada cinco segundos y establece
un TTL de quince segundos. El filtro BPF configurado se combina siempre con
las direcciones IPv4 propias de la interfaz; no amplía la captura a terceros.

## Producción

- Ejecutar con permisos para captura de paquetes.
- Usar `NET_RAW` y `NET_ADMIN`.
- Documentar la interfaz física o virtual real.
- Mantener Redis interno.

## Inicio

La imagen se construye desde el Dockerfile de `omniguard-infra`.
