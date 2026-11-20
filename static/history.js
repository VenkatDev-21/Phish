document.addEventListener("DOMContentLoaded", () => {
    const root = document.querySelector("[data-investigation-history]");
    if (!root) return;

    const one = (selector) => root.querySelector(selector);
    const range = one("[data-history-range]");
    const refresh = one("[data-history-refresh]");
    const alertBox = one("[data-history-alert]");
    const pageSize = Number(root.dataset.pageSize) || 25;
    const state = { page: 1, requestId: 0, searchTimer: null };

    function element(tag, className, text) {
        const node = document.createElement(tag);
        if (className) node.className = className;
        if (text !== undefined && text !== null) node.textContent = String(text);
        return node;
    }

    function formatNumber(value) {
        const number = Number(value);
        return Number.isFinite(number) ? number.toLocaleString() : "—";
    }

    function formatDate(value) {
        if (!value) return "—";
        const date = new Date(String(value).replace(" ", "T"));
        return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString();
    }

    function rangeParams(extra) {
        const params = new URLSearchParams({ range: range.value });
        if (range.value === "custom") {
            const start = one("[data-history-start]").value;
            const end = one("[data-history-end]").value;
            if (start) params.set("start", start);
            if (end) params.set("end", end);
        }
        Object.entries(extra || {}).forEach(([key, value]) => {
            if (value !== undefined && value !== null && value !== "") {
                params.set(key, value);
            }
        });
        return params;
    }

    async function getJson(path, parameters) {
        const response = await fetch(`${path}?${rangeParams(parameters).toString()}`, {
            headers: { Accept: "application/json" },
        });
        const payload = await response.json();
        if (!response.ok) {
            throw new Error(payload.error || `Request failed (${response.status}).`);
        }
        return payload;
    }

    function showError(message) {
        alertBox.textContent = message;
        alertBox.hidden = !message;
        alertBox.classList.toggle("soc-alert-error", Boolean(message));
    }

    function appendCell(row, value, className) {
        const cell = element("td", className || "", value);
        row.append(cell);
        return cell;
    }

    function severityClass(value) {
        return `severity-${String(value || "informational").toLowerCase().replaceAll(" ", "-")}`;
    }

    function currentFilters() {
        return {
            source: one("[data-history-source]").value,
            severity: one("[data-history-severity]").value,
            event_type: one("[data-history-type]").value,
            q: one("[data-history-search]").value.trim(),
            page: String(state.page),
            page_size: String(pageSize),
        };
    }

    function updateExportLink() {
        const filters = currentFilters();
        delete filters.page;
        delete filters.page_size;
        one("[data-history-export]").href =
            `/api/dashboard/recent-events.csv?${rangeParams(filters).toString()}`;
    }

    function renderHistory(data) {
        const body = one("[data-history-rows]");
        body.replaceChildren();
        const events = data.events || [];
        events.forEach((event) => {
            const row = document.createElement("tr");
            appendCell(row, formatDate(event.timestamp));
            const source = appendCell(row, event.source || "");
            source.append(element("span", "soc-subtext", event.source_type));
            appendCell(row, String(event.event_type || "").replaceAll("_", " "));
            appendCell(row, event.category);
            appendCell(row, `${formatNumber(event.risk_score)}%`, "soc-risk-pill");
            appendCell(row, event.severity, `soc-severity ${severityClass(event.severity)}`);
            appendCell(row, event.engine);
            appendCell(row, event.status);
            const openCell = appendCell(row, "");
            const open = element("a", "soc-open-link", "Open →");
            open.href = event.investigation_url;
            openCell.append(open);
            body.append(row);
        });

        one("[data-history-count]").textContent =
            `${formatNumber(data.total)} scan record${data.total === 1 ? "" : "s"}`;
        one("[data-history-empty]").hidden = events.length !== 0;
        one("[data-history-page-label]").textContent =
            `Page ${data.pages ? data.page : 0} of ${data.pages} · ${formatNumber(data.total)} records`;
        one("[data-history-prev]").disabled = data.page <= 1;
        one("[data-history-next]").disabled = data.page >= data.pages;
        updateExportLink();
    }

    async function loadHistory() {
        const requestId = ++state.requestId;
        refresh.disabled = true;
        showError("");
        try {
            const data = await getJson(
                "/api/dashboard/recent-events",
                currentFilters()
            );
            if (requestId === state.requestId) renderHistory(data);
        } catch (error) {
            if (requestId === state.requestId) {
                showError(`Could not load investigation history: ${error.message}`);
            }
        } finally {
            if (requestId === state.requestId) refresh.disabled = false;
        }
    }

    function toggleCustomRange() {
        one("[data-history-custom-range]").hidden = range.value !== "custom";
    }

    range.addEventListener("change", () => {
        toggleCustomRange();
        if (range.value !== "custom") {
            state.page = 1;
            loadHistory();
        }
    });
    one("[data-history-apply]").addEventListener("click", () => {
        const start = one("[data-history-start]").value;
        const end = one("[data-history-end]").value;
        if (!start || !end || start >= end) {
            showError("Choose a valid custom range with a start earlier than its end.");
            return;
        }
        state.page = 1;
        loadHistory();
    });
    refresh.addEventListener("click", loadHistory);

    ["[data-history-source]", "[data-history-severity]", "[data-history-type]"].forEach((selector) => {
        one(selector).addEventListener("change", () => {
            state.page = 1;
            loadHistory();
        });
    });
    one("[data-history-search]").addEventListener("input", () => {
        window.clearTimeout(state.searchTimer);
        state.searchTimer = window.setTimeout(() => {
            state.page = 1;
            loadHistory();
        }, 250);
    });
    one("[data-history-prev]").addEventListener("click", () => {
        if (state.page > 1) {
            state.page -= 1;
            loadHistory();
        }
    });
    one("[data-history-next]").addEventListener("click", () => {
        state.page += 1;
        loadHistory();
    });

    const refreshSeconds = Number(root.dataset.refreshSeconds);
    if (Number.isFinite(refreshSeconds) && refreshSeconds > 0) {
        window.setInterval(() => {
            if (!document.hidden) loadHistory();
        }, refreshSeconds * 1000);
    }
    toggleCustomRange();
    loadHistory();
});
