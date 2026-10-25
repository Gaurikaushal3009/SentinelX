
#include <iostream>
#include <filesystem>
#include <system_error>

#include "db.h"
#include "sqlite/sqlite3.h"

bool initializeDatabase() {
    std::error_code error;

    std::filesystem::create_directories("database", error);

    if (error) {
        std::cerr << "Could not create database folder: "
                  << error.message() << "\n";
        return false;
    }

    sqlite3* db = nullptr;

    int rc = sqlite3_open("database/sentinelx.db", &db);

    if (rc != SQLITE_OK) {
        std::cerr << "Database opening failed: "
                  << (db ? sqlite3_errmsg(db) : "Unknown error")
                  << "\n";

        if (db) {
            sqlite3_close(db);
        }

        return false;
    }

    const char* sql =
        "CREATE TABLE IF NOT EXISTS threat_history ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "ip TEXT NOT NULL,"
        "path TEXT NOT NULL,"
        "failed_logins INTEGER NOT NULL,"
        "requests_per_minute INTEGER NOT NULL,"
        "threat_score INTEGER NOT NULL,"
        "severity TEXT NOT NULL,"
        "reason TEXT NOT NULL,"
        "created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP"
        ");";

    char* errorMessage = nullptr;

    rc = sqlite3_exec(db, sql, nullptr, nullptr, &errorMessage);

    if (rc != SQLITE_OK) {
        std::cerr << "Table creation failed: "
                  << (errorMessage ? errorMessage : "Unknown error")
                  << "\n";

        sqlite3_free(errorMessage);
        sqlite3_close(db);
        return false;
    }

    sqlite3_close(db);

    std::cout << "SQLite database initialized successfully.\n";
    return true;
}

bool saveThreat(
    const RequestEvent& event,
    const DetectionResult& result
) {
    sqlite3* db = nullptr;

    if (sqlite3_open("database/sentinelx.db", &db) != SQLITE_OK) {
        std::cerr << "Could not open database.\n";

        if (db) {
            sqlite3_close(db);
        }

        return false;
    }

    const char* sql =
        "INSERT INTO threat_history "
        "(ip, path, failed_logins, requests_per_minute, "
        "threat_score, severity, reason) "
        "VALUES (?, ?, ?, ?, ?, ?, ?);";

    sqlite3_stmt* statement = nullptr;

    int rc = sqlite3_prepare_v2(
        db, sql, -1, &statement, nullptr
    );

    if (rc != SQLITE_OK) {
        std::cerr << "SQL preparation failed: "
                  << sqlite3_errmsg(db) << "\n";

        sqlite3_close(db);
        return false;
    }

    sqlite3_bind_text(
        statement, 1, event.ip.c_str(),
        -1, SQLITE_TRANSIENT
    );

    sqlite3_bind_text(
        statement, 2, event.path.c_str(),
        -1, SQLITE_TRANSIENT
    );

    sqlite3_bind_int(statement, 3, event.failedLogins);
    sqlite3_bind_int(statement, 4, event.requestsPerMinute);
    sqlite3_bind_int(statement, 5, result.score);

    sqlite3_bind_text(
        statement, 6, result.severity.c_str(),
        -1, SQLITE_TRANSIENT
    );

    sqlite3_bind_text(
        statement, 7, result.reason.c_str(),
        -1, SQLITE_TRANSIENT
    );

    rc = sqlite3_step(statement);

    bool success = (rc == SQLITE_DONE);

    if (success) {
        std::cout << "Threat saved to database successfully.\n";
    } else {
        std::cerr << "Failed to save threat: "
                  << sqlite3_errmsg(db) << "\n";
    }

    sqlite3_finalize(statement);
    sqlite3_close(db);

    return success;
}

void displayThreatHistory() {
    sqlite3* db = nullptr;

    if (sqlite3_open("database/sentinelx.db", &db) != SQLITE_OK) {
        std::cerr << "Could not open threat history database.\n";

        if (db) {
            sqlite3_close(db);
        }

        return;
    }

    const char* sql =
        "SELECT id, ip, path, threat_score, severity, "
        "reason, created_at "
        "FROM threat_history ORDER BY id DESC;";

    sqlite3_stmt* statement = nullptr;

    if (sqlite3_prepare_v2(
            db, sql, -1, &statement, nullptr
        ) != SQLITE_OK) {

        std::cerr << "Could not read threat history: "
                  << sqlite3_errmsg(db) << "\n";

        sqlite3_close(db);
        return;
    }

    std::cout << "\n========== THREAT HISTORY ==========\n";

    bool found = false;
    int rc;

    while ((rc = sqlite3_step(statement)) == SQLITE_ROW) {
        found = true;

        std::cout << "\nRecord ID: "
                  << sqlite3_column_int(statement, 0) << "\n";

        std::cout << "IP Address: "
                  << sqlite3_column_text(statement, 1) << "\n";

        std::cout << "Path: "
                  << sqlite3_column_text(statement, 2) << "\n";

        std::cout << "Threat Score: "
                  << sqlite3_column_int(statement, 3) << "/100\n";

        std::cout << "Severity: "
                  << sqlite3_column_text(statement, 4) << "\n";

        std::cout << "Reason: "
                  << sqlite3_column_text(statement, 5) << "\n";

        std::cout << "Created At: "
                  << sqlite3_column_text(statement, 6) << "\n";

        std::cout << "-----------------------------------\n";
    }

    if (rc != SQLITE_DONE) {
        std::cerr << "Error while reading history: "
                  << sqlite3_errmsg(db) << "\n";
    } else if (!found) {
        std::cout << "No threat records found.\n";
    }

    sqlite3_finalize(statement);
    sqlite3_close(db);
}
