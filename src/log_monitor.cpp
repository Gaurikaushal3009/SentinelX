
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <thread>
#include <chrono>
#include <stdexcept>

#include "detector.h"
#include "db.h"

bool processLine(const std::string& line) {
    std::stringstream ss(line);
    RequestEvent event;
    std::string failedText, rateText;

    if (!std::getline(ss, event.ip, ',') ||
        !std::getline(ss, event.path, ',') ||
        !std::getline(ss, failedText, ',') ||
        !std::getline(ss, rateText)) {
        std::cout << "Skipped invalid log: " << line << "\n";
        return false;
    }

    try {
        std::size_t p1 = 0, p2 = 0;
        event.failedLogins = std::stoi(failedText, &p1);
        event.requestsPerMinute = std::stoi(rateText, &p2);

        if (p1 != failedText.size() ||
            p2 != rateText.size() ||
            event.ip.empty() ||
            event.failedLogins < 0 ||
            event.requestsPerMinute < 0) {
            throw std::invalid_argument("Invalid values");
        }
    } catch (const std::exception&) {
        std::cout << "Skipped invalid log: " << line << "\n";
        return false;
    }

    DetectionResult result = analyzeRequest(event);

    if (!saveThreat(event, result)) {
        std::cout << "Database save failed for " << event.ip << "\n";
        return false;
    }

    std::cout << "\nNew request detected!\n";
    std::cout << "IP: " << event.ip << "\n";
    std::cout << "Path: " << event.path << "\n";
    std::cout << "Score: " << result.score << "/100\n";
    std::cout << "Severity: " << result.severity << "\n";
    std::cout << "Reason: " << result.reason << "\n";

    return true;
}

int main() {
    std::cout << "=============================\n";
    std::cout << " SENTINELX AUTO LOG MONITOR\n";
    std::cout << "=============================\n";

    if (!initializeDatabase()) {
        std::cerr << "Database initialization failed.\n";
        return 1;
    }

    const std::string filePath = "logs/requests.csv";
    std::size_t processedLines = 0;

    // Start from the end of the existing file to avoid
    // importing its old records again on startup.
    {
        std::ifstream file(filePath);
        if (!file.is_open()) {
            std::cerr << "Cannot open " << filePath << "\n";
            return 1;
        }

        std::string line;
        while (std::getline(file, line)) {
            ++processedLines;
        }
    }

    std::cout << "Monitoring: " << filePath << "\n";
    std::cout << "Existing lines skipped: " << processedLines << "\n";
    std::cout << "Append a new CSV row to test the monitor.\n";
    std::cout << "Press Ctrl+C to stop.\n";

    while (true) {
        std::ifstream file(filePath);

        if (file.is_open()) {
            std::string line;
            std::size_t currentLine = 0;

            while (std::getline(file, line)) {
                ++currentLine;

                if (currentLine <= processedLines) {
                    continue;
                }

                if (!line.empty()) {
                    processLine(line);
                }

                processedLines = currentLine;
            }
        } else {
            std::cerr << "Cannot read log file. Retrying...\n";
        }

        std::this_thread::sleep_for(std::chrono::seconds(2));
    }

    return 0;
}
