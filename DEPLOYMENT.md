# Despliegue web — OmniGuard Sensor C++

Consulte el plan maestro en el repositorio central:

[WEB-DEPLOYMENT-PLAN.md](../WEB-DEPLOYMENT-PLAN.md)

## Rol

Captura tráfico con libpcap, clasifica eventos y los publica en Redis.

## Variables

```text
REDIS_HOST
REDIS_PORT
INTERFACE
BPF_FILTER
```

## Producción

- Ejecutar con permisos para captura de paquetes.
- Usar `NET_RAW` y `NET_ADMIN`.
- Documentar la interfaz física o virtual real.
- Mantener Redis interno.

## Inicio

La imagen se construye desde el Dockerfile de `omniguard-infra`.
