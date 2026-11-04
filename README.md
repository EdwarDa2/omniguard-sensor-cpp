# omniguard-sensor-cpp

Sensor de red del proyecto **OmniGuard SOC** (plataforma de ciberseguridad Blue Team). Captura tráfico IPv4 de una interfaz de red con **libpcap**, extrae los datos clave de cada paquete y los publica como JSON en un canal **Redis Pub/Sub** para que otros servicios los analicen.

---

## Cómo funciona

```
Interfaz de red ──libpcap──▶ NetworkCapture ──PacketInfo──▶ RedisPublisher ──PUBLISH──▶ Redis (canal: network_events)
```

| Componente | Archivo | Responsabilidad |
|---|---|---|
| `PacketInfo` | `include/capture.h` | Estructura con los datos del paquete |
| `NetworkCapture` | `src/capture.cpp` | Captura con libpcap (modo promiscuo, filtro BPF `ip`) y extrae IP, puertos y protocolo (TCP/UDP/OTHER) |
| `RedisPublisher` | `src/redis_publisher.cpp` | Serializa a JSON y publica con hiredis |
| `main` | `src/main.cpp` | Punto de entrada, bucle principal y cierre limpio con `Ctrl+C` |

### Formato del evento publicado

```json
{
  "src_ip": "172.24.208.167",
  "dst_ip": "185.125.190.121",
  "src_port": 55419,
  "dst_port": 123,
  "protocol": "UDP",
  "length": 230,
  "timestamp": 1793759054
}
```

---

## Requisitos

- Linux (Ubuntu 22.04 o superior) o Windows con **WSL2 + Ubuntu**
- Compilador con soporte C++17, CMake ≥ 3.16
- Docker (solo para levantar Redis de prueba)

```bash
sudo apt update
sudo apt install -y build-essential cmake pkg-config libpcap-dev libhiredis-dev
```

> ⚠️ **Usuarios de WSL2:** clona el repositorio **dentro del sistema de archivos de Linux** (por ejemplo `~/omniguard-sensor-cpp`), no en `/mnt/c/...` ni en carpetas de OneDrive. CMake falla con `Operation not permitted` en esas rutas.

---

## Compilación

```bash
git clone <URL_DEL_REPOSITORIO>
cd omniguard-sensor-cpp
mkdir build && cd build
cmake .. && make -j$(nproc)
```

Resultado esperado: `[100%] Built target omniguard-sensor`.

---

## Ejecución

**1. Levantar Redis**

```bash
docker run --name redis-temp -p 6379:6379 -d redis:alpine
docker exec -it redis-temp redis-cli ping      # debe responder: PONG
```

Si el contenedor ya existe: `docker start redis-temp`.

**2. Escuchar el canal (terminal aparte)**

```bash
docker exec -it redis-temp redis-cli SUBSCRIBE network_events
```

**3. Ejecutar el sensor** (requiere `sudo` para capturar paquetes)

```bash
sudo ./build/omniguard-sensor
```

Salida esperada:

```
[REDIS] Conectado a 127.0.0.1:6379
[SENSOR] Interfaz activa: eth0
[SENSOR] Capturando en canal 'network_events'
[PKT #1] 172.24.208.167:55419 → 185.125.190.121:123 [UDP] len=230
```

**4. Generar tráfico de prueba** (desde la terminal de Ubuntu, no desde Windows):

```bash
curl -s https://example.com > /dev/null
ping -c 3 8.8.8.8
```

Cada paquete capturado aparece en el sensor como `[PKT #n]` y como un JSON en la terminal del paso 2. Para detener el sensor, `Ctrl+C`.

---

## Solución de problemas

| Síntoma | Causa | Solución |
|---|---|---|
| `configure_file: Operation not permitted` | Proyecto en `/mnt/c` u OneDrive | Mover el proyecto a `~/` |
| `Could not find PCAP_LIB` | Búsqueda de libpcap con `find_library` | Instalar `libpcap-dev` y `pkg-config`; el `CMakeLists.txt` usa `pkg_check_modules` |
| `sudo: not found` / `apt: command not found` | Terminal incorrecta (Git Bash o WSL interno de Docker) | Usar la terminal de Ubuntu (`wsl -d Ubuntu`) |
| El sensor no conecta a Redis | Contenedor detenido | `docker start redis-temp` y verificar con `docker ps` |
| No se ve el tráfico del `curl` | Ejecutado en Windows/Git Bash | Ejecutarlo en la terminal de Ubuntu |
| `Permission denied` al capturar | Faltan privilegios | Ejecutar con `sudo` |

---

## Limitaciones conocidas

- **En WSL2 solo se captura la interfaz virtual `eth0` de Linux**, no la tarjeta Wi-Fi/Ethernet de Windows. Para vigilar una red real se necesita un host Linux nativo o una VM con interfaz en modo *bridge*.
- Solo se captura **IPv4** (filtro BPF `ip`).
- La conexión a Redis está fija en `127.0.0.1:6379` y la interfaz se selecciona automáticamente.
- Si Redis estuviera en la misma interfaz que se captura, convendría usar el filtro `ip and not port 6379` para evitar que el sensor capture su propio tráfico.

---

## Hoja de ruta

- [x] Captura de paquetes IPv4 con libpcap
- [x] Publicación de eventos JSON en Redis
- [x] Cierre limpio con señales
- [ ] Configuración por variables de entorno (`REDIS_HOST`, `REDIS_PORT`, `INTERFACE`)
- [ ] Filtro BPF configurable
- [ ] Dockerfile (`network_mode: host`, capacidades `NET_RAW` y `NET_ADMIN`)
- [ ] Integración en el `docker-compose.yml` maestro (`omniguard-infra`)

---
