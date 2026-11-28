# Acerca de omniguard-sensor-cpp

## Descripción General

`omniguard-sensor-cpp` es el motor de captura y análisis de tráfico de red a bajo nivel de la plataforma **OmniGuard SOC**. Programado en **C++17** sobre **libpcap** y **hiredis**, opera en modo promiscuo con filtrado en kernel mediante **Berkeley Packet Filter (BPF)** para interceptar tramas Ethernet, IPv4, TCP, UDP e ICMP con mínima latencia y sobrecarga de CPU.

Clasifica más de 60 protocolos de red mediante inspección de puertos y banderas de control, deduce de forma pasiva banners y versiones de servicios (como OpenSSH) para generar identificadores **CPE (Common Platform Enumeration)** y publica cada evento estructurado en formato JSON hacia el canal `network_events` del bus Redis.

## Contexto del Proyecto

* **Plataforma:** OmniGuard SOC (Security Operations Center Distribuido)
* **Capa Arquitectónica:** Capa de Adquisición de Datos y Sensor de Red
* **Tecnologías Principales:** C++17, CMake, `libpcap` / Npcap, `hiredis`, Berkeley Packet Filter (BPF), Raw Sockets
* **Licencia:** MIT License
* **Institución:** Universidad Politécnica de Chiapas — Ingeniería en Tecnologías de la Información e Innovación Digital
* **Autores:** Edwar Daniel Gonzalez Hernandez, Andres Eduardo Gonzalez Ruiz

---

## Metadatos para la sección "About" de GitHub

Copiar y pegar estos valores en el panel lateral derecho (icono de engranaje en **About**) del repositorio en GitHub:

* **Description:**
  `Sensor de red de alto rendimiento en C++17 y libpcap para OmniGuard SOC. Captura en modo promiscuo con BPF, clasificacion de protocolos, extraccion CPE y publicacion en Redis.`
* **Topics:**
  `cpp`, `libpcap`, `network-security`, `packet-capture`, `redis`, `nids`, `cybersecurity`, `blue-team`, `omniguard`
