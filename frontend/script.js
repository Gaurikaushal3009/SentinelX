
"use strict";

// SENTINELX - INDEPENDENT THREAT RECORDS TABLE

const API_URL = "/api/threats";

const tableBody = document.getElementById("threatTableBody");
const searchInput = document.getElementById("searchInput");
const severityFilter = document.getElementById("severityFilter");
const refreshButton = document.getElementById("refreshButton");
const resultCount = document.getElementById("resultCount");

let threats = [];
function updateOverview() {
    document.getElementById("totalEvents").textContent = threats.length;

    document.getElementById("highEvents").textContent =
        threats.filter(t => t.severity?.toLowerCase() === "high").length;

    document.getElementById("mediumEvents").textContent =
        threats.filter(t => t.severity?.toLowerCase() === "medium").length;

    document.getElementById("lowEvents").textContent =
        threats.filter(t => t.severity?.toLowerCase() === "low").length;
}

function escapeHTML(value) {
    return String(value ?? "").replace(/[&<>"']/g, char => ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;"
    })[char]);
}

function renderTable() {
    if (!tableBody) {
        console.error("Table body #threatTableBody not found.");
        return;
    }

    const search = searchInput
        ? searchInput.value.trim().toLowerCase()
        : "";

    const severity = severityFilter
        ? severityFilter.value.toLowerCase()
        : "all";

    const filtered = threats.filter(item => {
        const itemSeverity = String(item.severity || "").toLowerCase();

        const matchesSeverity =
            severity === "all" || itemSeverity === severity;

        const text = [
            item.id,
            item.ip,
            item.path,
            item.reason,
            item.severity,
            item.score
        ].join(" ").toLowerCase();

        return matchesSeverity && text.includes(search);
    });

    if (filtered.length === 0) {
        tableBody.innerHTML = `
            <tr>
                <td colspan="6" class="empty-state">
                    No threat records found.
                </td>
            </tr>
        `;
    } else {
        tableBody.innerHTML = filtered.map(item => {
            const score = Number(item.score ?? 0);
            const level = String(item.severity || "Low");
            const severityClass =
                level.toLowerCase() === "high" ? "severity-high" :
                level.toLowerCase() === "medium" ? "severity-medium" :
                "severity-low";

            return `
                <tr>
                    <td>${escapeHTML(item.id)}</td>
                    <td>${escapeHTML(item.ip)}</td>
                    <td>${escapeHTML(item.path)}</td>
                    <td><strong>${score}/100</strong></td>
                    <td>
                        <span class="severity-badge ${severityClass}">
                            ${escapeHTML(level)}
                        </span>
                    </td>
                    <td class="reason-cell">
                        ${escapeHTML(item.reason)}
                    </td>
                </tr>
            `;
        }).join("");
    }

    if (resultCount) {
        resultCount.textContent =
            `Showing ${filtered.length} of ${threats.length} records`;
    }
}

async function loadThreatRecords() {
    if (!tableBody) return;

    tableBody.innerHTML = `
        <tr>
            <td colspan="6" class="empty-state">
                Loading threat records...
            </td>
        </tr>
    `;

    if (refreshButton) {
        refreshButton.disabled = true;
        refreshButton.textContent = "Loading...";
    }

    try {
        const response = await fetch(API_URL, {
            method: "GET",
            cache: "no-store"
        });

        if (!response.ok) {
            throw new Error("Server error: " + response.status);
        }

        const data = await response.json();

        if (!Array.isArray(data)) {
            throw new Error("API response is not a JSON array.");
        }

        threats = data;
        updateOverview();
        renderTable();

        console.log("SentinelX records loaded:", threats.length);

    } catch (error) {
        console.error("Table loading failed:", error);

        tableBody.innerHTML = `
            <tr>
                <td colspan="6" class="empty-state">
                    Could not load records: ${escapeHTML(error.message)}
                </td>
            </tr>
        `;

        if (resultCount) {
            resultCount.textContent = "Unable to load records";
        }

    } finally {
        if (refreshButton) {
            refreshButton.disabled = false;
            refreshButton.textContent = "↻ Refresh Records";
        }
    }
}

if (searchInput) {
    searchInput.addEventListener("input", renderTable);
}

if (severityFilter) {
    severityFilter.addEventListener("change", renderTable);
}

if (refreshButton) {
    refreshButton.addEventListener("click", loadThreatRecords);
}

// Load records when the page opens.
loadThreatRecords();

// Automatically refresh every 5 seconds.
window.setInterval(loadThreatRecords, 5000);

/* ==========================================
   SENTINELX - ANALYZE REQUEST FUNCTIONALITY
========================================== */

const analyzeForm = document.getElementById("analyzeForm");
const analyzeButton = document.getElementById("analyzeButton");
const analysisResult = document.getElementById("analysisResult");

if (analyzeForm) {
    analyzeForm.addEventListener("submit", async function (event) {
        event.preventDefault();

        const ip = document.getElementById("ipAddress").value.trim();
        const path = document.getElementById("requestPath").value.trim();

        const failedLogins = Number(
            document.getElementById("failedLogins").value
        );

        const requestsPerMinute = Number(
            document.getElementById("requestsPerMinute").value
        );

        if (!ip || !path) {
            showMessage("Please enter IP Address and Request Path.", true);
            return;
        }

        if (
            !Number.isSafeInteger(failedLogins) ||
            !Number.isSafeInteger(requestsPerMinute) ||
            failedLogins < 0 ||
            requestsPerMinute < 0
        ) {
            showMessage("Please enter valid non-negative whole numbers.", true);
            return;
        }

        if (analyzeButton) {
            analyzeButton.disabled = true;
            analyzeButton.textContent = "Analyzing...";
        }

        showMessage("Analyzing request...", false);

        try {
            const response = await fetch("/api/analyze", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    ip: ip,
                    path: path,
                    failedLogins: failedLogins,
                    requestsPerMinute: requestsPerMinute
                })
            });

            const result = await response.json();

            if (!response.ok) {
                throw new Error(
                    result.error || "Analysis failed: " + response.status
                );
            }

            showMessage(
                "Analysis completed successfully!\n" +
                "IP Address: " + ip + "\n" +
                "Threat Score: " + result.score + "/100\n" +
                "Severity: " + result.severity + "\n" +
                "Reason: " + result.reason,
                false
            );

            // Refresh the threat records table.
            await loadThreatRecords();

        } catch (error) {
            console.error("Analysis error:", error);
            showMessage("Unable to analyze request: " + error.message, true);

        } finally {
            if (analyzeButton) {
                analyzeButton.disabled = false;
                analyzeButton.textContent = "Analyze Request →";
            }
        }
    });
}

function showMessage(message, isError) {
    if (!analysisResult) {
        console.error(message);
        return;
    }

    analysisResult.textContent = message;
    analysisResult.classList.add("visible");
    analysisResult.classList.toggle("error", isError);
}

// Clear the analysis message when the form is reset.
if (analyzeForm) {
    analyzeForm.addEventListener("reset", function () {
        if (analysisResult) {
            analysisResult.textContent = "";
            analysisResult.classList.remove("visible", "error");
        }
    });
}
