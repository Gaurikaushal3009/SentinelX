
"use strict";

/* ==========================================
   SENTINELX - FRONTEND APPLICATION
   ========================================== */

const API_BASE = "";
const CHECK_INTERVAL = 5000;
const MAX_VISIBLE_ALERTS = 10;

const connectionStatus = document.getElementById("connectionStatus");
const threatTableBody = document.getElementById("threatTableBody");

const totalEvents = document.getElementById("totalEvents");
const highEvents = document.getElementById("highEvents");
const mediumEvents = document.getElementById("mediumEvents");
const lowEvents = document.getElementById("lowEvents");

const searchInput = document.getElementById("searchInput");
const severityFilter = document.getElementById("severityFilter");
const refreshButton = document.getElementById("refreshButton");

const analyzeForm = document.getElementById("analyzeForm");
const analyzeButton = document.getElementById("analyzeButton");
const analysisResult = document.getElementById("analysisResult");

let allThreats = [];
let lastKnownThreatIds = new Set();
let alertInitialized = false;
let loadingThreats = false;

/* ==========================================
   CREATE OR REUSE THE SIDEBAR ALERT PANEL
   ========================================== */

function createAlertPanel() {
    const sidebar = document.querySelector(".sidebar");

    if (!sidebar) {
        console.error("SentinelX sidebar was not found.");
        return null;
    }

    // Reuse the panel if it already exists in index.html.
    let panel = document.getElementById("sentinelAlertPanel");

    // Create the panel only if it is missing.
    if (!panel) {
        panel = document.createElement("section");
        panel.id = "sentinelAlertPanel";
        panel.className = "sentinel-alert-panel";
        panel.setAttribute("aria-label", "High severity threat alerts");
    }

    // Ensure the panel is a direct child of the sidebar.
    // This makes the sidebar CSS selectors work correctly.
    if (panel.parentElement !== sidebar) {
        sidebar.appendChild(panel);
    }

    let heading = panel.querySelector(".sentinel-alert-heading");

    if (!heading) {
        heading = document.createElement("h2");
        heading.className = "sentinel-alert-heading";
        heading.textContent = "Threat Alerts";
        panel.prepend(heading);
    }

    let status = panel.querySelector(".sentinel-alert-status");

    if (!status) {
        status = document.createElement("p");
        status.className = "sentinel-alert-status";
        status.textContent = "Checking threats...";
        heading.after(status);
    }

    let list = panel.querySelector("#sentinelAlertList");

    if (!list) {
        list = document.createElement("div");
        list.id = "sentinelAlertList";
        list.className = "sentinel-alert-list";
        list.setAttribute("aria-live", "polite");
        panel.appendChild(list);
    }

    // Ensure the expected IDs and classes are present.
    panel.id = "sentinelAlertPanel";
    panel.classList.add("sentinel-alert-panel");
    list.id = "sentinelAlertList";
    list.classList.add("sentinel-alert-list");

    return panel;
}

const alertPanel = createAlertPanel();
const alertList = alertPanel
    ? alertPanel.querySelector("#sentinelAlertList")
    : null;

/* ==========================================
   HELPER FUNCTIONS
   ========================================== */

function escapeHTML(value) {
    return String(value ?? "").replace(/[&<>"']/g, function (character) {
        const entities = {
            "&": "&amp;",
            "<": "&lt;",
            ">": "&gt;",
            '"': "&quot;",
            "'": "&#39;"
        };

        return entities[character];
    });
}


function setConnectionStatus(connected, message) {
    if (!connectionStatus) return;

    connectionStatus.classList.toggle("connected", connected);
    connectionStatus.classList.toggle("disconnected", !connected);

    const dot = connectionStatus.querySelector(".status-dot");

    if (dot) {
        dot.setAttribute(
            "aria-label",
            connected ? "Connected" : "Disconnected"
        );
    }

    // Remove old text and create exactly one status message.
    Array.from(connectionStatus.childNodes).forEach(function (node) {
        if (node.nodeType === Node.TEXT_NODE) {
            node.remove();
        }
    });

    connectionStatus.appendChild(
        document.createTextNode(" " + message)
    );
}


function getSeverityClass(severity) {
    const value = String(severity || "").toLowerCase();

    if (value === "high") return "severity-high";
    if (value === "medium") return "severity-medium";

    return "severity-low";
}

/* ==========================================
   DASHBOARD STATISTICS
   ========================================== */

function updateStatistics(threats) {
    if (totalEvents) {
        totalEvents.textContent = threats.length;
    }

    if (highEvents) {
        highEvents.textContent = threats.filter(
            threat => String(threat.severity).toLowerCase() === "high"
        ).length;
    }

    if (mediumEvents) {
        mediumEvents.textContent = threats.filter(
            threat => String(threat.severity).toLowerCase() === "medium"
        ).length;
    }

    if (lowEvents) {
        lowEvents.textContent = threats.filter(
            threat => String(threat.severity).toLowerCase() === "low"
        ).length;
    }
}

/* ==========================================
   THREAT ALERT CARDS
   ========================================== */

function showHighAlert(threat, historical = false) {
    if (!alertPanel || !alertList) return;

    const card = document.createElement("article");
    card.className = "sentinel-alert-card";

    const heading = document.createElement("div");
    heading.className = "sentinel-alert-card-title";
    heading.textContent = historical
        ? "HIGH-SEVERITY THREAT (SAVED)"
        : "HIGH-SEVERITY THREAT DETECTED";

    const details = document.createElement("p");
    details.className = "sentinel-alert-card-details";

    const score = getThreatScore(threat);
    const ip = threat.ip ?? threat.ip_address ?? "Unknown IP";
    const path = threat.path ?? threat.request_path ?? "Unknown path";
    const reason =
        threat.reason ?? "A High-severity rule was triggered.";

    details.textContent =
        "IP address: " + ip + "\n" +
        "Request path: " + path + "\n" +
        "Threat score: " + score + "/100\n" +
        "Reason: " + reason;

    const footer = document.createElement("div");
    footer.className = "sentinel-alert-card-footer";
    footer.textContent = historical
        ? "Previously recorded threat"
        : "New threat detected just now";

    const dismiss = document.createElement("button");
    dismiss.type = "button";
    dismiss.className = "sentinel-alert-dismiss";
    dismiss.textContent = "Dismiss";

    dismiss.addEventListener("click", function () {
        card.remove();
        updateAlertStatus();
    });

    card.append(heading, details, footer, dismiss);
    alertList.prepend(card);

    // Keep only the most recent visible alerts.
    while (alertList.children.length > MAX_VISIBLE_ALERTS) {
        alertList.lastElementChild.remove();
    }

    updateAlertStatus();
}

function updateAlertStatus() {
    if (!alertPanel || !alertList) return;

    const status = alertPanel.querySelector(".sentinel-alert-status");

    if (!status) return;

    const count = alertList.children.length;

    status.textContent = count === 0
        ? "No High-severity alerts"
        : count + " alert(s) shown";
}

/* ==========================================
   DETECT NEW HIGH-SEVERITY RECORDS
   ========================================== */

function processThreatAlerts(threats) {
    const currentIds = new Set();

    // First load: display existing High-severity records as saved.
    if (!alertInitialized) {
        for (const threat of threats) {
            const key = getThreatKey(threat);
            currentIds.add(key);

            if (String(threat.severity).toLowerCase() === "high") {
                showHighAlert(threat, true);
            }
        }

        lastKnownThreatIds = currentIds;
        alertInitialized = true;
        updateAlertStatus();
        return;
    }

    // Later loads: notify only for previously unseen records.
    for (const threat of threats) {
        const key = getThreatKey(threat);
        currentIds.add(key);

        if (lastKnownThreatIds.has(key)) continue;

        if (String(threat.severity).toLowerCase() === "high") {
            showHighAlert(threat, false);
        }
    }

    lastKnownThreatIds = currentIds;
    updateAlertStatus();
}

/* ==========================================
   THREAT HISTORY TABLE
   ========================================== */

function renderThreats() {
    if (!threatTableBody) return;

    const searchTerm = searchInput
        ? searchInput.value.trim().toLowerCase()
        : "";

    const selectedSeverity = severityFilter
        ? severityFilter.value.toLowerCase()
        : "all";

    const filteredThreats = allThreats.filter(function (threat) {
        const severity = String(threat.severity || "").toLowerCase();

        const matchesSeverity =
            selectedSeverity === "all" ||
            severity === selectedSeverity;

        const searchableText = [
            threat.id,
            threat.ip ?? threat.ip_address,
            threat.path ?? threat.request_path,
            threat.reason,
            threat.severity
        ].join(" ").toLowerCase();

        return matchesSeverity && searchableText.includes(searchTerm);
    });

    if (filteredThreats.length === 0) {
        threatTableBody.innerHTML = `
            <tr>
                <td colspan="6" class="empty-state">
                    No matching threat records found.
                </td>
            </tr>
        `;
    } else {
        threatTableBody.innerHTML = filteredThreats.map(function (threat) {
            const score = getThreatScore(threat);
            const severity = String(threat.severity || "Low");

            return `
                <tr>
                    <td>${escapeHTML(threat.id)}</td>
                    <td>${escapeHTML(threat.ip ?? threat.ip_address)}</td>
                    <td>${escapeHTML(threat.path ?? threat.request_path)}</td>
                    <td><strong>${score}/100</strong></td>
                    <td>
                        <span class="severity-badge ${getSeverityClass(severity)}">
                            ${escapeHTML(severity)}
                        </span>
                    </td>
                    <td class="reason-cell">${escapeHTML(threat.reason)}</td>
                </tr>
            `;
        }).join("");
    }

    const resultCount = document.getElementById("resultCount");

    if (resultCount) {
        resultCount.textContent =
            `Showing ${filteredThreats.length} of ${allThreats.length} records`;
    }
}

/* ==========================================
   LOAD THREATS FROM THE C++ BACKEND
   ========================================== */

async function loadThreats() {
    if (loadingThreats) return;

    loadingThreats = true;

    if (refreshButton) {
        refreshButton.disabled = true;
        refreshButton.textContent = "Loading...";
    }

    try {
        const response = await fetch(`${API_BASE}/api/threats`, {
            method: "GET",
            cache: "no-store"
        });

        if (!response.ok) {
            throw new Error(`API returned status ${response.status}`);
        }

        const data = await response.json();

        if (!Array.isArray(data)) {
            throw new Error("The threats API did not return a list.");
        }

        allThreats = data;

        updateStatistics(allThreats);
        renderThreats();
        processThreatAlerts(allThreats);

        setConnectionStatus(true, "API Connected");
    } catch (error) {
        console.error("Unable to load threats:", error);
        setConnectionStatus(false, "API Disconnected");

        if (threatTableBody) {
            threatTableBody.innerHTML = `
                <tr>
                    <td colspan="6" class="empty-state">
                        Unable to load records. Check that the SentinelX
                        server is running, then click Refresh Records.
                    </td>
                </tr>
            `;
        }

        const status = alertPanel
            ? alertPanel.querySelector(".sentinel-alert-status")
            : null;

        if (status) {
            status.textContent =
                "Unable to check alerts. Check the server connection.";
        }
    } finally {
        loadingThreats = false;

        if (refreshButton) {
            refreshButton.disabled = false;
            refreshButton.textContent = "↻ Refresh Records";
        }
    }
}

/* ==========================================
   REFRESH, SEARCH AND FILTER
   ========================================== */

if (refreshButton) {
    refreshButton.addEventListener("click", loadThreats);
}

if (searchInput) {
    searchInput.addEventListener("input", renderThreats);
}

if (severityFilter) {
    severityFilter.addEventListener("change", renderThreats);
}

/* ==========================================
   ANALYZE A REQUEST
   ========================================== */

function showAnalysisMessage(message, isError) {
    if (!analysisResult) return;

    analysisResult.textContent = message;
    analysisResult.classList.add("visible");
    analysisResult.classList.toggle("error", isError);
}

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
            showAnalysisMessage(
                "Please enter an IP address and request path.",
                true
            );
            return;
        }

        if (
            !Number.isSafeInteger(failedLogins) ||
            !Number.isSafeInteger(requestsPerMinute) ||
            failedLogins < 0 ||
            requestsPerMinute < 0
        ) {
            showAnalysisMessage(
                "Enter non-negative whole numbers for failed logins and requests per minute.",
                true
            );
            return;
        }

        const requestData = {
            ip: ip,
            path: path,
            failedLogins: failedLogins,
            requestsPerMinute: requestsPerMinute
        };

        if (analyzeButton) {
            analyzeButton.disabled = true;
            analyzeButton.textContent = "Analyzing...";
        }

        showAnalysisMessage("Analyzing request...", false);

        try {
            const response = await fetch(`${API_BASE}/api/analyze`, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify(requestData)
            });

            const result = await response.json();

            if (!response.ok) {
                throw new Error(
                    result.error || `Request failed (${response.status}).`
                );
            }

            showAnalysisMessage(
                `Analysis complete. Threat Score: ${result.score}/100. ` +
                `Severity: ${result.severity}. Reason: ${result.reason}`,
                false
            );

            await loadThreats();
        } catch (error) {
            console.error("Request analysis failed:", error);

            showAnalysisMessage(
                `Could not analyze request: ${error.message}. ` +
                "Check the server and try again.",
                true
            );
        } finally {
            if (analyzeButton) {
                analyzeButton.disabled = false;
                analyzeButton.textContent = "Analyze Request →";
            }
        }
    });
}

if (analyzeForm) {
    analyzeForm.addEventListener("reset", function () {
        if (analysisResult) {
            analysisResult.textContent = "";
            analysisResult.classList.remove("visible", "error");
        }
    });
}
loadThreats();
window.setInterval(loadThreats, CHECK_INTERVAL);
