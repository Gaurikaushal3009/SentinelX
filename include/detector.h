
#ifndef DETECTOR_H
#define DETECTOR_H

#include <string>

struct RequestEvent {
    std::string ip;
    std::string path;
    int failedLogins;
    int requestsPerMinute;
};

struct DetectionResult {
    int score;
    std::string severity;
    std::string reason;
};

DetectionResult analyzeRequest(const RequestEvent& event);

#endif
