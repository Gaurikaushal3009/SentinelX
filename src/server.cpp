
#include <iostream>
#include <string>
#include <sstream>
#include <cctype>
#include <cstdlib>
#include <limits>
#include <filesystem>
#include <mutex>

#include "httplib.h"
#include "detector.h"
#include "db.h"
#include "sqlite/sqlite3.h"

namespace fs = std::filesystem;

namespace {
std::mutex databaseMutex;
}

// Escape text so it can safely be included in JSON.
std::string jsonEscape(const std::string& input) {
    std::string output;

    for (unsigned char c : input) {
        switch (c) {
            case '"':  output += "\\\""; break;
            case '\\': output += "\\\\"; break;
            case '\n': output += "\\n";  break;
            case '\r': output += "\\r";  break;
            case '\t': output += "\\t";  break;
            case '\b': output += "\\b";  break;
            case '\f': output += "\\f";  break;

            default:
                if (c < 0x20) {
                    output += ' ';
                } else {
                    output += static_cast<char>(c);
                }
        }
    }

    return output;
}

// Read a simple JSON string field.
bool getStringField(
    const std::string& body,
    const std::string& key,
    std::string& value
) {
    const std::string marker = "\"" + key + "\"";
    std::size_t pos = body.find(marker);

    if (pos == std::string::npos) return false;

    pos = body.find(':', pos + marker.size());
    if (pos == std::string::npos) return false;

    pos = body.find_first_not_of(" \t\r\n", pos + 1);
    if (pos == std::string::npos || body[pos] != '"') return false;

    ++pos;
    std::string result;

    while (pos < body.size()) {
        char c = body[pos++];

        if (c == '"') {
            value = result;
            return true;
        }

        if (c == '\\') {
            if (pos >= body.size()) return false;

            char escaped = body[pos++];

            switch (escaped) {
                case '"':  result += '"';  break;
                case '\\': result += '\\'; break;
                case '/':  result += '/';  break;
                case 'n':  result += '\n'; break;
                case 'r':  result += '\r'; break;
                case 't':  result += '\t'; break;
                case 'b':  result += '\b'; break;
                case 'f':  result += '\f'; break;
                default: return false;
            }
        } else {
            if (static_cast<unsigned char>(c) < 0x20) return false;
            result += c;
        }
    }

    return false;
}

// Read a non-negative integer field.
bool getIntField(
    const std::string& body,
    const std::string& key,
    int& value
) {
    const std::string marker = "\"" + key + "\"";
    std::size_t pos = body.find(marker);

    if (pos == std::string::npos) return false;

    pos = body.find(':', pos + marker.size());
    if (pos == std::string::npos) return false;

    pos = body.find_first_not_of(" \t\r\n", pos + 1);
    if (pos == std::string::npos) return false;

    std::size_t end = pos;

    while (end < body.size() &&
           std::isdigit(static_cast<unsigned char>(body[end]))) {
        ++end;
    }

    if (end == pos) return false;

    try {
        long long number = std::stoll(body.substr(pos, end - pos));

        if (number > std::numeric_limits<int>::max()) {
            return false;
        }

        value = static_cast<int>(number);
    } catch (...) {
        return false;
    }

    return true;
}

// Return saved threat records from SQLite.
std::string getThreats() {
    std::lock_guard<std::mutex> lock(databaseMutex);

    sqlite3* db = nullptr;

    if (sqlite3_open("database/sentinelx.db", &db) != SQLITE_OK) {
        if (db) sqlite3_close(db);
        return "[]";
    }

    const char* sql =
        "SELECT id, ip, path, failed_logins, requests_per_minute, "
        "threat_score, severity, reason, created_at "
        "FROM threat_history ORDER BY id DESC;";

    sqlite3_stmt* stmt = nullptr;

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        sqlite3_close(db);
        return "[]";
    }

    std::ostringstream json;
    json << "[";

    bool first = true;

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        if (!first) json << ",";
        first = false;

        auto textColumn = [&](int column) -> std::string {
            const unsigned char* text = sqlite3_column_text(stmt, column);

            return text
                ? reinterpret_cast<const char*>(text)
                : "";
        };

        json << "{"
             << "\"id\":" << sqlite3_column_int(stmt, 0) << ","
             << "\"ip\":\"" << jsonEscape(textColumn(1)) << "\","
             << "\"path\":\"" << jsonEscape(textColumn(2)) << "\","
             << "\"failedLogins\":" << sqlite3_column_int(stmt, 3) << ","
             << "\"requestsPerMinute\":" << sqlite3_column_int(stmt, 4) << ","
             << "\"score\":" << sqlite3_column_int(stmt, 5) << ","
             << "\"severity\":\"" << jsonEscape(textColumn(6)) << "\","
             << "\"reason\":\"" << jsonEscape(textColumn(7)) << "\","
             << "\"createdAt\":\"" << jsonEscape(textColumn(8)) << "\""
             << "}";
    }

    json << "]";

    sqlite3_finalize(stmt);
    sqlite3_close(db);

    return json.str();
}

int main() {
    std::cout << "=============================\n";
    std::cout << "   SENTINELX WEB API SERVER\n";
    std::cout << "=============================\n";

    // Ensure the SQLite database directory exists.
    std::error_code directoryError;
    fs::create_directories("database", directoryError);

    if (directoryError) {
        std::cerr << "Could not create database directory: "
                  << directoryError.message() << "\n";
        return 1;
    }

    if (!initializeDatabase()) {
        std::cerr << "Database initialization failed.\n";
        return 1;
    }

    httplib::Server server;

    // Health check.
    server.Get("/api/health", [](const httplib::Request&,
                                 httplib::Response& response) {
        response.set_content(
            R"({"status":"ok","service":"SentinelX"})",
            "application/json"
        );
    });

    // Threat history.
    server.Get("/api/threats", [](const httplib::Request&,
                                  httplib::Response& response) {
        response.set_content(getThreats(), "application/json");
    });

    // Threat analysis.
    server.Post("/api/analyze", [](const httplib::Request& request,
                                   httplib::Response& response) {
        RequestEvent event{};

        bool valid =
            getStringField(request.body, "ip", event.ip) &&
            getStringField(request.body, "path", event.path) &&
            getIntField(request.body, "failedLogins", event.failedLogins) &&
            getIntField(
                request.body,
                "requestsPerMinute",
                event.requestsPerMinute
            );

        if (!valid ||
            event.ip.empty() ||
            event.ip.size() > 45 ||
            event.path.empty() ||
            event.path.size() > 2048 ||
            event.path[0] != '/' ||
            event.failedLogins < 0 ||
            event.failedLogins > 1000000 ||
            event.requestsPerMinute < 0 ||
            event.requestsPerMinute > 1000000) {

            response.status = 400;
            response.set_content(
                R"({"error":"Invalid request. Check all fields and values."})",
                "application/json"
            );
            return;
        }

        DetectionResult result = analyzeRequest(event);

        bool saved = false;

        {
            std::lock_guard<std::mutex> lock(databaseMutex);
            saved = saveThreat(event, result);
        }

        if (!saved) {
            response.status = 500;
            response.set_content(
                R"({"error":"Could not save threat record."})",
                "application/json"
            );
            return;
        }

        std::ostringstream json;

        json << "{"
             << "\"message\":\"Threat analysis completed\","
             << "\"ip\":\"" << jsonEscape(event.ip) << "\","
             << "\"path\":\"" << jsonEscape(event.path) << "\","
             << "\"score\":" << result.score << ","
             << "\"severity\":\"" << jsonEscape(result.severity) << "\","
             << "\"reason\":\"" << jsonEscape(result.reason) << "\""
             << "}";

        response.set_content(json.str(), "application/json");
    });

    // Serve the existing frontend.
    if (!server.set_mount_point("/", "./frontend")) {
        std::cerr << "Could not mount the frontend directory.\n";
        return 1;
    }

    // Register the explicit homepage route after mounting static files.
    server.Get("/", [](const httplib::Request&,
                       httplib::Response& response) {
        response.set_redirect("/home.html");
    });

    // Render provides PORT; local development defaults to 8080.
    const char* portText = std::getenv("PORT");
    int port = 8080;

    if (portText && *portText) {
        try {
            std::size_t parsed = 0;
            int candidate = std::stoi(portText, &parsed);

            if (parsed != std::string(portText).size() ||
                candidate < 1 || candidate > 65535) {
                std::cerr << "Invalid PORT environment variable.\n";
                return 1;
            }

            port = candidate;
        } catch (...) {
            std::cerr << "Invalid PORT environment variable.\n";
            return 1;
        }
    }

    std::cout << "Frontend: http://0.0.0.0:" << port << "\n";
    std::cout << "Homepage: /home.html\n";
    std::cout << "Dashboard: /index.html\n";
    std::cout << "Health API: /api/health\n";
    std::cout << "Threat API: /api/threats\n";
    std::cout << "Analyze API: POST /api/analyze\n";
    std::cout << "Press Ctrl+C to stop the server.\n";

    if (!server.listen("0.0.0.0", port)) {
        std::cerr << "Could not start server on port "
                  << port << ".\n";
        return 1;
    }

    return 0;
}
