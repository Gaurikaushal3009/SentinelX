#include <iostream>
#include <fstream>
#include <sstream>
#include <string>

#include "detector.h"
#include "db.h"

int main() {
    std::cout << "=============================\n";
    std::cout << " SENTINELX LOG IMPORTER\n";
    std::cout << "=============================\n";

    // Initialize the existing SQLite database.
    if (!initializeDatabase()) {
        std::cerr << "Database initialization failed.\n";
        return 1;
    }

    // Open the sample request log file.
    std::ifstream file("logs/requests.csv");

    if (!file.is_open()) {
        std::cerr << "Could not open logs/requests.csv\n";
        return 1;
    }

    std::string line;
    int imported = 0;
    int skipped = 0;

    while (std::getline(file, line)) {
        if (line.empty()) {
            continue;
        }

        std::stringstream ss(line);

        RequestEvent event;
        std::string failedLoginsText;
        std::string requestsPerMinuteText;

        // Read the four CSV fields.
        if (!std::getline(ss, event.ip, ',') ||
            !std::getline(ss, event.path, ',') ||
            !std::getline(ss, failedLoginsText, ',') ||
            !std::getline(ss, requestsPerMinuteText, ',')) {
            std::cout << "Skipping invalid record: "
                      << line << "\n";
            skipped++;
            continue;
        }

        try {
            std::size_t pos1 = 0;
            std::size_t pos2 = 0;

            event.failedLogins =
                std::stoi(failedLoginsText, &pos1);

            event.requestsPerMinute =
                std::stoi(requestsPerMinuteText, &pos2);

            if (pos1 != failedLoginsText.size() ||
                pos2 != requestsPerMinuteText.size() ||
                event.failedLogins < 0 ||
                event.requestsPerMinute < 0 ||
                event.ip.empty()) {
                throw std::invalid_argument("Invalid field value");
            }
        }
        catch (const std::exception&) {
            std::cout << "Skipping invalid record: "
                      << line << "\n";
            skipped++;
            continue;
        }

        // Apply SentinelX's existing detection rules.
        DetectionResult result = analyzeRequest(event);

        // Save the analysis result in SQLite.
        if (saveThreat(event, result)) {
            std::cout << "\nRequest analyzed successfully\n";
            std::cout << "IP Address: " << event.ip << "\n";
            std::cout << "Path: " << event.path << "\n";
            std::cout << "Threat Score: "
                      << result.score << "/100\n";
            std::cout << "Severity: "
                      << result.severity << "\n";
            std::cout << "Reason: "
                      << result.reason << "\n";

            imported++;
        }
        else {
            std::cout << "Failed to save record for "
                      << event.ip << "\n";
            skipped++;
        }
    }

    file.close();

    std::cout << "\n=============================\n";
    std::cout << " IMPORT SUMMARY\n";
    std::cout << "=============================\n";
    std::cout << "Successfully imported: " << imported << "\n";
    std::cout << "Skipped records: " << skipped << "\n";
    std::cout << "=============================\n";

    return 0;
}