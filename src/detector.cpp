
#include "detector.h"

DetectionResult analyzeRequest(const RequestEvent& event) {
    int score = 0;
    std::string reason;

    // Rule 1: Repeated failed logins
    if (event.failedLogins >= 5) {
        score += 40;
        reason += "Repeated failed logins. ";
    }

    // Rule 2: High request rate
    if (event.requestsPerMinute > 100) {
        score += 35;
        reason += "High request rate. ";
    }

    // Rule 3: Invalid request path
    if (event.path.empty() || event.path[0] != '/') {
        score += 20;
        reason += "Invalid request path. ";
    }

    // Classify the threat
    std::string severity = "Low";

    if (score >= 60) {
        severity = "High";
    } else if (score >= 30) {
        severity = "Medium";
    }

    if (reason.empty()) {
        reason = "No configured rule was triggered.";
    }

    return {score, severity, reason};
}
