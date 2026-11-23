# omniguard-sensor-cpp

Sensor de red del proyecto **OmniGuard SOC** (plataforma de ciberseguridad Blue Team). Captura tráfico IPv4 con **libpcap**, **identifica el protocolo y el tipo de tráfico**, le asigna un **nivel de riesgo** y publica cada paquete como JSON en un canal **Redis Pub/Sub** para que otros servicios lo analicen.

---

## Cómo funciona

```
Interfaz de red ─libpcap─▶ parse_ethernet_ipv4 ─▶ classify ─▶ RedisPublisher ─PUBLISH─▶ Redis (network_events)
```

| Componente | Archivo | Responsabilidad |
|---|---|---|
| `PacketInfo` + parser | `include/capture.h`, `src/capture.cpp` | Interpreta la trama (Ethernet/VLAN → IPv4 → TCP/UDP/ICMP) con comprobación de límites |
| `NetworkCapture` | `src/capture.cpp` | Captura con libpcap en modo promiscuo; elige la interfaz activa o la indicada |
| `classify()` | `src/classifier.cpp` | Protocolo de aplicación, categoría y riesgo |
| `RedisPublisher` | `src/redis_publisher.cpp` | Serializa a JSON y publica con hiredis; reconecta si Redis se cae |
| `main` | `src/main.cpp` | Bucle principal, salida por consola con colores y cierre limpio con `Ctrl+C` |

---

## Identificación del tráfico

### Protocolo (ya no existe `OTHER`)

El sensor lee el número de protocolo IP y lo nombra: `TCP`, `UDP`, `ICMP`, `IGMP`, `GRE`, `ESP`, `AH`, `OSPF`, `VRRP`, `SCTP`, `IPIP`, `IPV6`; cualquier otro se publica como `IP-<n>` (por ejemplo `IP-200`).

### Protocolo de aplicación y categoría

Se deducen por el puerto (el destino primero, y si no, el origen para identificar respuestas) y se distinguen TCP de UDP (443/TCP es HTTPS; 443/UDP es QUIC). Ejemplos:

| Tráfico | `app_protocol` | `category` |
|---|---|---|
| TCP 443 | HTTPS | web |
| UDP 53 | DNS | resolucion_dns |
| UDP 123 | NTP | sincronizacion_hora |
| UDP 1900 / 5353 | SSDP/UPnP / mDNS | descubrimiento |
| TCP 22 | SSH | acceso_remoto |
| TCP 445 | SMB | compartir_archivos |
| TCP 3306 | MySQL | base_de_datos |
| ICMP tipo 8 | Echo Request (ping) | diagnostico_red |
| IP 47 | Túnel GRE | tunel |

El catálogo completo está en `src/classifier.cpp` (más de 60 servicios).

### Nivel de riesgo (`LOW` / `MEDIUM` / `HIGH`)

| Nivel | Significado | Ejemplos |
|---|---|---|
| `LOW` | Tráfico esperado | HTTPS, DNS, NTP, mDNS, ping normal |
| `MEDIUM` | A vigilar: servicios sin cifrar, administración remota o servicios expuestos | SSH, RDP, SMB, FTP, bases de datos, LLMNR, túneles GRE, FIN sin ACK |
| `HIGH` | Indicador de amenaza | Telnet, puertos de backdoors (4444, 31337, 12345), API de Docker sin TLS, flags TCP inválidos (NULL, XMAS, SYN+FIN, SYN+RST) |

Cada paquete incluye además `risk_reason` con el motivo en lenguaje claro.

> **Alcance:** la clasificación es **por paquete**, basada en puertos, protocolo IP y flags TCP; no inspecciona el contenido. Un paquete a SSH no es un ataque en sí mismo: es un indicador a vigilar. Las decisiones que requieren memoria (escaneo de puertos, fuerza bruta, ráfagas) se toman en el servicio de análisis, que consume estos eventos.

---

## Formato del evento publicado

```json
{
  "src_ip": "10.0.0.5",
  "dst_ip": "10.0.0.9",
  "src_port": 50000,
  "dst_port": 22,
  "protocol": "TCP",
  "length": 74,
  "timestamp": 1793759054,
  "app_protocol": "SSH",
  "category": "acceso_remoto",
  "risk": "MEDIUM",
  "risk_reason": "Administración remota: objetivo habitual de fuerza bruta",
  "tcp_flags": "SYN",
  "product_version": "9.2",
  "cpe_name": "cpe:2.3:a:openbsd:openssh:9.2:*:*:*:*:*:*:*"
}
```

Los campos base siguen siendo el contrato mínimo. `tcp_flags` aparece solo en TCP,
`icmp_type` solo en ICMP y `product_version`/`cpe_name` solo cuando existe evidencia.

### Descubrimiento pasivo de versiones

Cuando una respuesta TCP contiene un banner SSH verificable, el sensor puede extraer
`OpenSSH_<versión>` y publicar su CPE para NVD.

Ejemplo:

```text
SSH-2.0-OpenSSH_9.2p1
```

Resultado publicado:

- `product_version`: `9.2`
- `cpe_name`: `cpe:2.3:a:openbsd:openssh:9.2:*:*:*:*:*:*:*`

No se inventan versiones ni CPE para servicios desconocidos.

---

## Requisitos

- Linux (Ubuntu 22.04 o superior) o Windows con **WSL2 + Ubuntu**
- Compilador C++17, CMake ≥ 3.16
- Docker (solo para levantar Redis de prueba)

```bash
sudo apt update
sudo apt install -y build-essential cmake pkg-config libpcap-dev libhiredis-dev
```

> ⚠️ **Usuarios de WSL2:** clona el repositorio **dentro del sistema de archivos de Linux** (por ejemplo `~/omniguard-sensor-cpp`), no en `/mnt/c/...` ni en OneDrive. CMake falla con `Operation not permitted` en esas rutas.

---

## Compilación y pruebas

```bash
git clone <URL_DEL_REPOSITORIO>
cd omniguard-sensor-cpp
mkdir build && cd build
cmake -DBUILD_TESTS=ON .. && make -j$(nproc)
./classifier_test        # debe imprimir: OK: todas las pruebas pasaron
```

Las pruebas unitarias construyen paquetes de ejemplo (SSH, Telnet, escaneos NULL/XMAS, ICMP, GRE, protocolo desconocido, tramas truncadas) y verifican el parser y el clasificador sin necesidad de red. Sin `-DBUILD_TESTS=ON` solo se compila el sensor.

---

## Ejecución

**1. Redis**

```bash
docker run --name redis-temp -p 6379:6379 -d redis:alpine
docker exec -it redis-temp redis-cli ping      # PONG
```

Si ya existe: `docker start redis-temp`.

**2. Escuchar el canal (terminal aparte)**

```bash
docker exec -it redis-temp redis-cli SUBSCRIBE network_events
```

**3. Sensor** (requiere `sudo`)

```bash
sudo ./build/omniguard-sensor              # interfaz automática
sudo ./build/omniguard-sensor eth0         # o indicando la interfaz
```

Salida esperada (MEDIUM en amarillo y HIGH en rojo cuando hay terminal):

```
[REDIS] Conectado a 127.0.0.1:6379
[SENSOR] Filtro BPF: ip
[SENSOR] Interfaz activa: eth0
[SENSOR] Capturando en canal 'network_events'

[PKT #1] 172.24.208.167:55419 → 185.125.190.121:123 [UDP] NTP · sincronizacion_hora · LOW len=230
[PKT #2] 172.24.208.167:48212 → 10.0.0.9:22 [TCP] SSH · acceso_remoto · MEDIUM len=74
    ↳ Administración remota: objetivo habitual de fuerza bruta
```

Al detenerlo con `Ctrl+C` muestra un resumen: total de paquetes, cuántos LOW/MEDIUM/HIGH y fallos de publicación en Redis.

**4. Generar tráfico variado** (desde la terminal de Ubuntu):

```bash
curl -s https://example.com > /dev/null      # HTTPS (LOW)
curl -s http://example.com  > /dev/null      # HTTP (LOW, sin cifrar)
ping -c 3 8.8.8.8                            # ICMP Echo (LOW)
nc -zv 172.24.208.1 22 23 3389               # SSH, Telnet, RDP (MEDIUM/HIGH)
```

Para ver los flags inválidos, escanea únicamente **equipos propios** (por ejemplo la puerta de enlace de WSL, que es tu Windows):

```bash
sudo apt install -y nmap
sudo nmap -sX -p 20-30 172.24.208.1          # escaneo XMAS → HIGH / reconocimiento
sudo nmap -sN -p 20-30 172.24.208.1          # escaneo NULL  → HIGH / reconocimiento
```

---

## Variables de entorno (opcionales)

| Variable | Por defecto | Descripción |
|---|---|---|
| `INTERFACE` | automática | Interfaz a capturar (el argumento tiene prioridad) |
| `REDIS_HOST` | `127.0.0.1` | Host de Redis |
| `REDIS_PORT` | `6379` | Puerto de Redis |
| `BPF_FILTER` | `ip` | Filtro BPF; por ejemplo `ip and not port 6379` si Redis está en la interfaz capturada |

---

## Solución de problemas

| Síntoma | Causa | Solución |
|---|---|---|
| `configure_file: Operation not permitted` | Proyecto en `/mnt/c` u OneDrive | Mover el proyecto a `~/` |
| `Could not find PCAP_LIB` | Búsqueda de libpcap | Instalar `libpcap-dev` y `pkg-config`; el CMake usa `pkg_check_modules` |
| `sudo: not found` / `apt: command not found` | Terminal incorrecta (Git Bash o WSL de Docker) | Usar la terminal de Ubuntu |
| `command not found: ./build/omniguard-sensor` | No se compiló en esa carpeta | Compilar en `~/` y ejecutar desde allí |
| `No se pudo conectar a Redis` | Contenedor detenido | `docker start redis-temp` |
| `No se pudo abrir '<iface>'` | Faltan privilegios o la interfaz no existe | Usar `sudo` y comprobar con `ip -br link` |
| No se ve el tráfico del `curl` | Ejecutado en Windows/Git Bash | Ejecutarlo en la terminal de Ubuntu |

---

## Limitaciones conocidas

- **En WSL2 solo se captura la interfaz virtual de Linux**, no la tarjeta Wi-Fi/Ethernet de Windows. Para vigilar una red real, el sensor debe correr en un host Linux nativo, idealmente como gateway o punto de acceso.
- En una red Wi-Fi, un equipo solo ve su propio tráfico más el broadcast y multicast; para ver otros dispositivos debe ser el gateway o conectarse a un puerto espejo.
- Solo **IPv4** y enlaces **Ethernet** (otros tipos de enlace se rechazan con un mensaje claro).
- El servicio se deduce por el **puerto**: un servicio en un puerto no estándar aparecerá como `Desconocido`, y un puerto conocido no garantiza el protocolo real.
- Captura solo cabeceras (`snaplen` de 128 bytes), por lo que no se guarda el contenido de los usuarios.
- Capturar tráfico de terceros requiere **autorización expresa**: usa el sensor solo en redes propias o con permiso.

---

## Hoja de ruta

- [x] Captura de paquetes IPv4 con libpcap y publicación JSON en Redis
- [x] Identificación de protocolo (sin `OTHER`), categoría y nivel de riesgo
- [x] Detección de flags TCP inválidos (NULL, XMAS, SYN+FIN, SYN+RST)
- [x] Interfaz, Redis y filtro BPF configurables
- [x] Pruebas unitarias del parser y del clasificador
- [x] Dockerfile para `network_mode: host` y permisos de red
- [x] Integración con el `docker-compose.yml` de `omniguard-infra`
- [x] Descubrimiento básico de CPE mediante banner OpenSSH

---

## Autor

_Tu nombre_ — Proyecto OmniGuard SOC