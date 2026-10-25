
#include <iostream>

#include "detector.h"
#include "db.h"

int main() {
    std::cout << "=============================\n";
    std::cout << "       SENTINELX SYSTEM      \n";
    std::cout << "=============================\n";

    if (!initializeDatabase()) {
        std::cerr << "Database initialization failed.\n";
        return 1;
    }

    // Sample request event for testing.
    RequestEvent event = {
        "127.0.0.1",
        "/login",
        7,
        120
    };

    DetectionResult result = analyzeRequest(event);

    std::cout << "\nCyber Threat Detection Engine\n";
    std::cout << "IP Address: " << event.ip << "\n";
    std::cout << "Request Path: " << event.path << "\n";
    std::cout << "Failed Logins: " << event.failedLogins << "\n";
    std::cout << "Requests Per Minute: "
              << event.requestsPerMinute << "\n";

    std::cout << "\n--- Detection Result ---\n";
    std::cout << "Threat Score: " << result.score << "/100\n";
    std::cout << "Severity: " << result.severity << "\n";
    std::cout << "Reason: " << result.reason << "\n";

    if (!saveThreat(event, result)) {
        std::cerr << "Threat history was not saved.\n";
        return 1;
    }

    displayThreatHistory();

    return 0;
}
