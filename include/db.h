
#ifndef DB_H
#define DB_H

#include "detector.h"

bool initializeDatabase();

bool saveThreat(
    const RequestEvent& event,
    const DetectionResult& result
);

void displayThreatHistory();

#endif
