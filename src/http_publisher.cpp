#include "http_publisher.h"

#include <cstdio>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <sstream>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winhttp.h>
#endif

namespace {

std::string json_escape(const std::string& s) {
    std::string o;
    o.reserve(s.size() + 2);
    for (unsigned char c : s) {
        switch (c) {
            case '"': o += "\\\""; break;
            case '\\': o += "\\\\"; break;
            case '\n': o += "\\n"; break;
            case '\r': o += "\\r"; break;
            case '\t': o += "\\t"; break;
            default:
                if (c < 0x20) {
                    char b[8];
                    std::snprintf(b, sizeof(b), "\\u%04x", c);
                    o += b;
                } else {
                    o += static_cast<char>(c);
                }
        }
    }
    return o;
}

#ifdef _WIN32
bool parse_url(const std::string& url, bool& is_https, std::wstring& host_out,
               INTERNET_PORT& port_out, std::wstring& path_prefix_out) {
    std::string u = url;
    is_https = false;
    port_out = 80;

    if (u.rfind("https://", 0) == 0) {
        is_https = true;
        port_out = 443;
        u = u.substr(8);
    } else if (u.rfind("http://", 0) == 0) {
        is_https = false;
        port_out = 80;
        u = u.substr(7);
    }

    size_t slash = u.find('/');
    std::string host_port = (slash != std::string::npos) ? u.substr(0, slash) : u;
    std::string path = (slash != std::string::npos) ? u.substr(slash) : "";

    size_t colon = host_port.find(':');
    if (colon != std::string::npos) {
        std::string host = host_port.substr(0, colon);
        int p = std::atoi(host_port.substr(colon + 1).c_str());
        if (p > 0) port_out = static_cast<INTERNET_PORT>(p);
        host_out.assign(host.begin(), host.end());
    } else {
        host_out.assign(host_port.begin(), host_port.end());
    }

    if (path.empty() || path.back() == '/') {
        if (!path.empty()) path.pop_back();
    }
    path_prefix_out.assign(path.begin(), path.end());
    return true;
}
#endif

}  // namespace

HttpPublisher::HttpPublisher(std::string base_url, std::string auth_token, std::string sensor_id)
    : base_url_(std::move(base_url)),
      auth_token_(std::move(auth_token)),
      sensor_id_(std::move(sensor_id)),
      last_flush_(std::chrono::steady_clock::now()) {
    if (sensor_id_.empty()) {
        const char* comp = std::getenv("COMPUTERNAME");
        sensor_id_ = (comp && *comp) ? comp : "default-host";
    }
    std::cout << "[HTTP-PUBLISHER] Configurado hacia: " << base_url_ << " (Sensor ID: " << sensor_id_ << ")" << std::endl;
}

HttpPublisher::~HttpPublisher() {
    flush();
}

std::string HttpPublisher::to_json(const PacketInfo& p) {
    std::ostringstream j;
    j << "{\"src_ip\":\"" << json_escape(p.src_ip) << "\""
      << ",\"dst_ip\":\"" << json_escape(p.dst_ip) << "\""
      << ",\"src_port\":" << p.src_port
      << ",\"dst_port\":" << p.dst_port
      << ",\"protocol\":\"" << json_escape(p.protocol) << "\""
      << ",\"length\":" << p.length
      << ",\"timestamp\":" << p.timestamp
      << ",\"app_protocol\":\"" << json_escape(p.app_protocol) << "\""
      << ",\"category\":\"" << json_escape(p.category) << "\""
      << ",\"risk\":\"" << json_escape(p.risk) << "\""
      << ",\"risk_reason\":\"" << json_escape(p.risk_reason) << "\"";
    if (p.tcp_flag_bits >= 0) j << ",\"tcp_flags\":\"" << json_escape(p.tcp_flags) << "\"";
    if (p.icmp_type >= 0) j << ",\"icmp_type\":" << p.icmp_type;
    if (!p.product_version.empty())
        j << ",\"product_version\":\"" << json_escape(p.product_version) << "\"";
    if (!p.cpe_name.empty())
        j << ",\"cpe_name\":\"" << json_escape(p.cpe_name) << "\"";
    j << "}";
    return j.str();
}

bool HttpPublisher::publish(const PacketInfo& pkt) {
    std::lock_guard<std::mutex> lock(mutex_);
    batch_buffer_.push_back(pkt);

    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_flush_).count();

    // Enviar lote si se acumulan 15 paquetes o si han pasado más de 250ms
    if (batch_buffer_.size() >= 15 || elapsed >= 250) {
        return flush();
    }
    return true;
}

bool HttpPublisher::flush() {
    if (batch_buffer_.empty()) return true;

    std::ostringstream batch_json;
    batch_json << "[";
    for (size_t i = 0; i < batch_buffer_.size(); ++i) {
        if (i > 0) batch_json << ",";
        batch_json << to_json(batch_buffer_[i]);
    }
    batch_json << "]";

    batch_buffer_.clear();
    last_flush_ = std::chrono::steady_clock::now();

    return send_post("/events", batch_json.str());
}

bool HttpPublisher::publish_metrics(const TrafficMetricsSnapshot& metrics, const std::string& sensor_status, int open_ports) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::ostringstream json;
    json << std::fixed << std::setprecision(6)
         << "{\"packets_per_sec\":" << metrics.packets_per_sec
         << ",\"bandwidth_mbps\":" << metrics.bandwidth_mbps
         << ",\"sensor_status\":\"" << json_escape(sensor_status) << "\""
         << ",\"inbound\":" << metrics.inbound
         << ",\"outbound\":" << metrics.outbound
         << ",\"open_ports\":" << open_ports
         << ",\"sensor_id\":\"" << json_escape(sensor_id_) << "\""
         << "}";
    const std::string payload = json.str();

    auto now = std::chrono::system_clock::now();
    std::time_t tt = std::chrono::system_clock::to_time_t(now);
    std::tm gm{};
#ifdef _WIN32
    gmtime_s(&gm, &tt);
#else
    gmtime_r(&tt, &gm);
#endif
    char time_buf[16];
    std::strftime(time_buf, sizeof(time_buf), "%H:%M:%S", &gm);

    history_.push_back({time_buf, metrics.inbound, metrics.outbound});
    while (history_.size() > 15) {
        history_.pop_front();
    }

    std::ostringstream hist_json;
    hist_json << "[";
    for (size_t i = 0; i < history_.size(); ++i) {
        if (i > 0) hist_json << ",";
        hist_json << "{\"time\":\"" << json_escape(history_[i].time) << "\""
                  << ",\"inbound\":" << history_[i].inbound
                  << ",\"outbound\":" << history_[i].outbound
                  << "}";
    }
    hist_json << "]";

    std::ostringstream full_body;
    full_body << "{\"metrics\":" << payload << ",\"history\":" << hist_json.str() << "}";

    return send_post("/metrics", full_body.str());
}

bool HttpPublisher::send_post(const std::string& subpath, const std::string& json_payload) {
#ifdef _WIN32
    bool is_https = false;
    std::wstring host;
    INTERNET_PORT port = 80;
    std::wstring path_prefix;

    if (!parse_url(base_url_, is_https, host, port, path_prefix)) {
        std::cerr << "[HTTP-PUBLISHER] Error al parsear URL: " << base_url_ << std::endl;
        return false;
    }

    std::wstring full_path = path_prefix;
    std::wstring w_subpath(subpath.begin(), subpath.end());
    full_path += w_subpath;

    HINTERNET hSession = WinHttpOpen(L"OmniGuardSensor-Win32/1.0",
                                     WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                     WINHTTP_NO_PROXY_NAME,
                                     WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return false;

    // Timeout de conexión: 2s conexión, 3s envío/recepción
    WinHttpSetTimeouts(hSession, 2000, 2000, 3000, 3000);

    HINTERNET hConnect = WinHttpConnect(hSession, host.c_str(), port, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return false;
    }

    DWORD flags = is_https ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", full_path.c_str(),
                                           nullptr, WINHTTP_NO_REFERER,
                                           WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    // Cabeceras HTTP
    std::wstring headers = L"Content-Type: application/json\r\n";
    if (!auth_token_.empty()) {
        std::wstring w_token(auth_token_.begin(), auth_token_.end());
        headers += L"X-Internal-Token: " + w_token + L"\r\n";
    }

    BOOL send_res = WinHttpSendRequest(
        hRequest,
        headers.c_str(), static_cast<DWORD>(headers.length()),
        const_cast<char*>(json_payload.data()), static_cast<DWORD>(json_payload.length()),
        static_cast<DWORD>(json_payload.length()), 0
    );

    bool success = false;
    if (send_res && WinHttpReceiveResponse(hRequest, nullptr)) {
        DWORD status_code = 0;
        DWORD size = sizeof(status_code);
        WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                            WINHTTP_HEADER_NAME_BY_INDEX, &status_code, &size, WINHTTP_NO_HEADER_INDEX);
        if (status_code >= 200 && status_code < 300) {
            success = true;
        } else {
            std::cerr << "[HTTP-PUBLISHER] Error HTTP " << status_code << " en " << subpath << std::endl;
        }
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return success;
#else
    std::cout << "[HTTP-PUBLISHER-MOCK] Enviando a " << base_url_ << subpath << " (" << json_payload.length() << " bytes)\n";
    return true;
#endif
}
