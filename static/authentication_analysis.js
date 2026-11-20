document.addEventListener("DOMContentLoaded", () => {
    const root = document.querySelector("[data-authentication-page]");
    if (!root) return;

    const one = (selector) => root.querySelector(selector);
    const range = one("[data-authentication-range]");
    const search = one("[data-authentication-search]");
    const refresh = one("[data-authentication-refresh]");
    const alertBox = one("[data-authentication-alert]");
    const pageSize = Number(root.dataset.pageSize) || 25;
    const state = {
        requestId: 0,
        searchTimer: null,
        pages: { email: 1, file: 1, url: 1 },
    };

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

    function formatBytes(value) {
        let bytes = Number(value);
        if (!Number.isFinite(bytes)) return "—";
        if (bytes < 1024) return `${bytes} B`;
        const units = ["KB", "MB", "GB", "TB"];
        bytes /= 1024;
        let unit = 0;
        while (bytes >= 1024 && unit < units.length - 1) {
            bytes /= 1024;
            unit += 1;
        }
        return `${bytes.toFixed(1)} ${units[unit]}`;
    }

    function setError(message) {
        alertBox.textContent = message;
        alertBox.hidden = !message;
        alertBox.classList.toggle("soc-alert-error", Boolean(message));
    }

    async function getJson(path, parameters) {
        const query = new URLSearchParams(parameters);
        const response = await fetch(`${path}?${query.toString()}`, {
            headers: { Accept: "application/json" },
        });
        const payload = await response.json();
        if (!response.ok) {
            throw new Error(payload.error || `Request failed (${response.status}).`);
        }
        return payload;
    }

    function appendCell(row, value, className) {
        const cell = element("td", className || "", value);
        row.append(cell);
        return cell;
    }

    function setPagination(source, total, page) {
        const pages = Math.ceil(Number(total || 0) / pageSize);
        const prefix = source === "email" ? "authentication" : `auth-${source}`;
        one(`[data-${prefix}-page-label]`).textContent =
            `Page ${pages ? page : 0} of ${pages} · ${formatNumber(total)} records`;
        one(`[data-${prefix}-prev]`).disabled = page <= 1;
        one(`[data-${prefix}-next]`).disabled = page >= pages;
        one(`[data-auth-${source}-tab-count]`).textContent = formatNumber(total);
    }

    function renderMethods(data, emailTotal) {
        const target = one("[data-authentication-methods]");
        target.replaceChildren();
        ["spf", "dkim", "dmarc"].forEach((method) => {
            const values = (data.methods || {})[method] || {};
            const card = element("article", "soc-auth-card");
            card.append(element("h3", "", method.toUpperCase()));
            const stats = element("div", "soc-auth-values");
            ["pass", "fail", "none", "unknown"].forEach((status) => {
                const item = element("div", "");
                item.append(
                    element("span", "", status),
                    element("strong", "", formatNumber(values[status]))
                );
                stats.append(item);
            });
            const ratio = values.pass_percentage === null || values.pass_percentage === undefined
                ? "No reported pass/fail ratio"
                : `${values.pass_percentage}% reported pass among pass/fail claims`;
            card.append(stats, element("div", "soc-auth-percent", ratio));
            target.append(card);
        });
        one("[data-authentication-summary]").textContent =
            `Emails analyzed: ${formatNumber(emailTotal)} · DNS lookups explicitly requested: ${formatNumber(data.dns_lookups)} · Reported DMARC alignment concerns: ${formatNumber(data.alignment_failures)}`;
    }

    function renderEmailHistory(data) {
        const body = one("[data-authentication-rows]");
        body.replaceChildren();
        (data.records || []).forEach((record) => {
            const row = document.createElement("tr");
            appendCell(row, formatDate(record.timestamp));
            appendCell(row, record.sender || "(unknown sender)");
            appendCell(row, record.domain);
            appendCell(row, record.subject || "(no subject)");
            appendCell(row, record.spf);
            appendCell(row, record.dkim);
            appendCell(row, record.dmarc);
            const openCell = appendCell(row, "");
            const open = element("a", "soc-open-link", "Open report →");
            open.href = record.investigation_url;
            openCell.append(open);
            body.append(row);
        });

        one("[data-authentication-count]").textContent =
            `${formatNumber(data.records_total)} email record${data.records_total === 1 ? "" : "s"}`;
        one("[data-authentication-empty]").hidden = Boolean((data.records || []).length);
        setPagination("email", data.records_total, data.page);
    }

    function renderFileHistory(data) {
        const body = one("[data-auth-file-rows]");
        body.replaceChildren();
        (data.records || []).forEach((record) => {
            const row = document.createElement("tr");
            appendCell(row, formatDate(record.timestamp));
            appendCell(row, record.filename);
            appendCell(row, record.file_type || "Type unavailable");
            appendCell(row, formatBytes(record.file_size));
            appendCell(row, record.sha256 || "—");
            const engines = (record.engines || []).map((engine) => {
                const name = engine.provider || engine.name || "Scanner";
                const status = engine.status || "unknown";
                return `${name}: ${status}`;
            });
            appendCell(row, engines.length ? engines.join(", ") : "No engine details");
            appendCell(row, record.status);
            const openCell = appendCell(row, "");
            const open = element("a", "soc-open-link", "Open report →");
            open.href = record.investigation_url;
            openCell.append(open);
            body.append(row);
        });

        one("[data-auth-file-count]").textContent =
            `${formatNumber(data.total)} file record${data.total === 1 ? "" : "s"}`;
        one("[data-auth-file-empty]").hidden = Boolean((data.records || []).length);
        setPagination("file", data.total, state.pages.file);
    }

    function renderUrlHistory(data) {
        const body = one("[data-auth-url-rows]");
        body.replaceChildren();
        (data.records || []).forEach((record) => {
            const row = document.createElement("tr");
            appendCell(row, formatDate(record.timestamp));
            appendCell(row, record.url);
            appendCell(row, record.host || "Host unavailable");
            appendCell(row, record.result);
            appendCell(row, record.probability === null
                ? "—"
                : `${formatNumber(record.probability)}%`);
            appendCell(row, record.risk_level);
            const openCell = appendCell(row, "");
            const open = element("a", "soc-open-link", "Open report →");
            open.href = record.investigation_url;
            openCell.append(open);
            body.append(row);
        });

        one("[data-auth-url-count]").textContent =
            `${formatNumber(data.total)} URL record${data.total === 1 ? "" : "s"}`;
        one("[data-auth-url-empty]").hidden = Boolean((data.records || []).length);
        setPagination("url", data.total, data.page);
    }

    function loadParameters(source) {
        const parameters = {
            range: range.value,
            page: String(state.pages[source]),
            page_size: String(pageSize),
        };
        if (source === "email") parameters.q = search.value.trim();
        return parameters;
    }

    async function loadAll() {
        const requestId = ++state.requestId;
        refresh.disabled = true;
        setError("");
        const responses = await Promise.allSettled([
            getJson("/api/dashboard/authentication-statistics", { range: range.value }),
            getJson("/api/dashboard/email-statistics", loadParameters("email")),
            getJson("/api/dashboard/file-statistics", loadParameters("file")),
            getJson("/api/dashboard/url-statistics", loadParameters("url")),
        ]);
        if (requestId !== state.requestId) return;

        const failures = [];
        if (responses[0].status === "fulfilled") {
            renderMethods(
                responses[0].value,
                responses[1].status === "fulfilled" ? responses[1].value.total : undefined
            );
        } else {
            failures.push(`Authentication statistics: ${responses[0].reason.message}`);
        }
        if (responses[1].status === "fulfilled") {
            renderEmailHistory(responses[1].value);
        } else {
            failures.push(`Email history: ${responses[1].reason.message}`);
        }
        if (responses[2].status === "fulfilled") {
            renderFileHistory(responses[2].value);
        } else {
            failures.push(`File history: ${responses[2].reason.message}`);
        }
        if (responses[3].status === "fulfilled") {
            renderUrlHistory(responses[3].value);
        } else {
            failures.push(`URL history: ${responses[3].reason.message}`);
        }
        setError(failures.join(" · "));
        refresh.disabled = false;
    }

    function activateTab(source, focus) {
        root.querySelectorAll("[data-auth-history-tab]").forEach((button) => {
            const selected = button.dataset.authHistoryTab === source;
            button.classList.toggle("active", selected);
            button.setAttribute("aria-selected", String(selected));
            button.tabIndex = selected ? 0 : -1;
            if (selected && focus) button.focus();
        });
        root.querySelectorAll("[data-auth-history-panel]").forEach((panel) => {
            panel.hidden = panel.dataset.authHistoryPanel !== source;
        });
    }

    range.addEventListener("change", () => {
        state.pages = { email: 1, file: 1, url: 1 };
        loadAll();
    });
    refresh.addEventListener("click", loadAll);
    search.addEventListener("input", () => {
        window.clearTimeout(state.searchTimer);
        state.searchTimer = window.setTimeout(() => {
            state.pages.email = 1;
            loadAll();
        }, 250);
    });
    root.querySelectorAll("[data-auth-history-tab]").forEach((button, index, buttons) => {
        button.addEventListener("click", () => activateTab(button.dataset.authHistoryTab, false));
        button.addEventListener("keydown", (event) => {
            if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
            event.preventDefault();
            const nextIndex = event.key === "Home"
                ? 0
                : event.key === "End"
                    ? buttons.length - 1
                    : (index + (event.key === "ArrowRight" ? 1 : buttons.length - 1)) % buttons.length;
            activateTab(buttons[nextIndex].dataset.authHistoryTab, true);
        });
    });
    ["email", "file", "url"].forEach((source) => {
        const prefix = source === "email" ? "authentication" : `auth-${source}`;
        one(`[data-${prefix}-prev]`).addEventListener("click", () => {
            if (state.pages[source] > 1) {
                state.pages[source] -= 1;
                loadAll();
            }
        });
        one(`[data-${prefix}-next]`).addEventListener("click", () => {
            state.pages[source] += 1;
            loadAll();
        });
    });

    const refreshSeconds = Number(root.dataset.refreshSeconds);
    if (Number.isFinite(refreshSeconds) && refreshSeconds > 0) {
        window.setInterval(() => {
            if (!document.hidden) loadAll();
        }, refreshSeconds * 1000);
    }
    activateTab("email", false);
    loadAll();
});
