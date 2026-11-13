#pragma once

#include "capture.h"

// Identifica el protocolo de aplicación, la categoría del tráfico y un nivel de
// riesgo (LOW / MEDIUM / HIGH) con su motivo. Es una clasificación por paquete,
// basada en puertos, protocolo IP y flags TCP; no inspecciona el contenido.
void classify(PacketInfo& pkt);