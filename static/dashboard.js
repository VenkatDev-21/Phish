document.addEventListener("DOMContentLoaded", () => {
    const root = document.querySelector("[data-dashboard]");
    if (!root) return;

    const one = (selector) => root.querySelector(selector);
    const alertBox = one("[data-dashboard-alert]");
    const rangeSelect = one("[data-dashboard-range]");
    const refreshButton = one("[data-dashboard-refresh]");
    const bucketSelect = one("[data-activity-bucket]");
    const state = {
        globalSearchTimer: null,
        refreshing: false,
        chartSeries: null,
    };

    const seriesInfo = {
        emails: { label: "Emails", color: "#63b7ff" },
        phishing_emails: { label: "Phishing-risk emails", color: "#ff7486" },
        files: { label: "Files", color: "#b69bff" },
        malicious_files: { label: "Malicious files", color: "#ff9b55" },
        urls: { label: "URLs", color: "#4de2c1" },
        malicious_urls: { label: "Phishing URLs", color: "#ebc66d" },
    };

    function element(tag, className, text) {
        const node = document.createElement(tag);
        if (className) node.className = className;
        if (text !== undefined && text !== null) node.textContent = String(text);
        return node;
    }

    function clear(node) {
        node.replaceChildren();
    }

    function formatNumber(value) {
        const number = Number(value);
        return Number.isFinite(number) ? number.toLocaleString() : "—";
    }

    function formatDate(value) {
        if (!value) return "—";
        const parsed = new Date(String(value).replace(" ", "T"));
        return Number.isNaN(parsed.getTime()) ? String(value) : parsed.toLocaleString();
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

    function showError(message, success) {
        alertBox.textContent = message;
        alertBox.hidden = false;
        alertBox.classList.toggle("soc-alert-success", Boolean(success));
        alertBox.classList.toggle("soc-alert-error", !success);
    }

    function clearError() {
        alertBox.textContent = "";
        alertBox.hidden = true;
        alertBox.classList.remove("soc-alert-success", "soc-alert-error");
    }

    function queryParams(extra) {
        const params = new URLSearchParams();
        const selected = rangeSelect.value;
        params.set("range", selected);
        if (selected === "custom") {
            const start = one("[data-range-start]").value;
            const end = one("[data-range-end]").value;
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

    async function getJson(path, extra) {
        const response = await fetch(`${path}?${queryParams(extra).toString()}`, {
            headers: { Accept: "application/json" },
        });
        const payload = await response.json();
        if (!response.ok) {
            throw new Error(payload.error || `Request failed (${response.status}).`);
        }
        return payload;
    }

    async function loadAll() {
        if (state.refreshing) return;
        state.refreshing = true;
        refreshButton.disabled = true;
        clearError();
        const requests = [
            ["summary", "/api/dashboard/summary"],
            ["activity", "/api/dashboard/activity", { bucket: bucketSelect.value }],
            ["distribution", "/api/dashboard/threat-distribution"],
            ["email", "/api/dashboard/email-statistics"],
            ["url", "/api/dashboard/url-statistics"],
            ["file", "/api/dashboard/file-statistics"],
            ["indicators", "/api/dashboard/top-indicators"],
        ];
        const results = await Promise.all(requests.map(async ([key, path, extra]) => {
            try {
                return [key, await getJson(path, extra), null];
            } catch (error) {
                return [key, null, error];
            }
        }));

        const failed = [];
        results.forEach(([key, data, error]) => {
            if (error) {
                failed.push(`${key}: ${error.message}`);
                return;
            }
            try {
                renderers[key](data);
            } catch (renderError) {
                failed.push(`${key}: could not render response (${renderError.message})`);
            }
        });
        const updated = one("[data-last-updated]");
        updated.textContent = new Date().toLocaleTimeString();
        if (failed.length) showError(`Some dashboard data could not be loaded. ${failed.join(" · ")}`);
        state.refreshing = false;
        refreshButton.disabled = false;
        if (one("[data-global-search]").value.trim().length >= 2) globalSearch();
    }

    function renderKpis(data) {
        const selected = new Set([
            "emails", "files", "urls", "events", "phishing_emails",
            "malicious_files", "malicious_urls",
        ]);
        const colors = {
            emails: "#63b7ff",
            files: "#b69bff",
            urls: "#4de2c1",
            events: "#a9bdcb",
            phishing_emails: "#ff7486",
            malicious_files: "#ff9b55",
            malicious_urls: "#ebc66d",
        };
        const icons = {
            emails: "✉", files: "◈", urls: "⌕", events: "≋",
            phishing_emails: "!", malicious_files: "!", malicious_urls: "!",
        };
        const cards = (data.kpis || []).filter((item) => selected.has(item.key));
        clear(one("[data-kpis]"));
        cards.forEach((item) => {
            const card = element("article", "soc-kpi panel");
            card.style.setProperty("--kpi-color", colors[item.key] || "#4de2c1");
            const top = element("div", "soc-kpi-top");
            top.append(element("span", "", item.label), element("span", "soc-kpi-icon", icons[item.key] || "•"));
            const value = element("div", "soc-kpi-value", formatNumber(item.value));
            const bottom = element("div", "soc-kpi-bottom");
            const change = item.change_percent;
            const changeLabel = change === null
                ? "NEW"
                : `${change > 0 ? "+" : ""}${change}%`;
            bottom.append(
                element("span", "soc-kpi-change", changeLabel),
                element("span", "", "vs previous period")
            );
            card.append(top, value, bottom);
            one("[data-kpis]").append(card);
        });
    }

    function renderChartLegend(series) {
        const legend = one("[data-chart-legend]");
        clear(legend);
        if (state.chartSeries === null) state.chartSeries = new Set(series || []);
        (series || []).forEach((key) => {
            const info = seriesInfo[key];
            if (!info) return;
            const label = element("label", "soc-series-toggle");
            label.style.setProperty("--series-color", info.color);
            const checkbox = document.createElement("input");
            checkbox.type = "checkbox";
            checkbox.checked = state.chartSeries.has(key);
            checkbox.addEventListener("change", () => {
                if (checkbox.checked) state.chartSeries.add(key);
                else state.chartSeries.delete(key);
                drawChart(window.dashboardActivity || { points: [], series: [] });
            });
            label.append(checkbox, element("span", "soc-series-swatch"), element("span", "", info.label));
            legend.append(label);
        });
    }

    function svgNode(name, attributes) {
        const node = document.createElementNS("http://www.w3.org/2000/svg", name);
        Object.entries(attributes || {}).forEach(([key, value]) => node.setAttribute(key, value));
        return node;
    }

    function drawChart(data) {
        const svg = one("[data-activity-chart]");
        const empty = one("[data-activity-empty]");
        const tooltip = one("[data-chart-tooltip]");
        clear(svg);
        const points = data.points || [];
        if (!points.length) {
            svg.hidden = true;
            empty.hidden = false;
            tooltip.textContent = "";
            return;
        }
        svg.hidden = false;
        empty.hidden = true;
        const width = 1000;
        const height = 280;
        const padding = { top: 16, right: 24, bottom: 38, left: 34 };
        const plotWidth = width - padding.left - padding.right;
        const plotHeight = height - padding.top - padding.bottom;
        const activeSeries = state.chartSeries === null
            ? (data.series || [])
            : Array.from(state.chartSeries);
        const maxValue = Math.max(1, ...points.flatMap((point) =>
            activeSeries.map((key) => Number(point[key] || 0))
        ));
        [0, 0.5, 1].forEach((fraction) => {
            const y = padding.top + plotHeight * fraction;
            svg.append(svgNode("line", {
                x1: padding.left, y1: y, x2: width - padding.right, y2: y,
                class: "soc-chart-gridline",
            }));
            const label = svgNode("text", {
                x: padding.left - 8, y: y + 3, "text-anchor": "end",
                class: "soc-chart-label",
            });
            label.textContent = String(Math.round(maxValue * (1 - fraction)));
            svg.append(label);
        });
        const xFor = (index) => points.length === 1
            ? padding.left + plotWidth / 2
            : padding.left + index * plotWidth / (points.length - 1);
        const yFor = (value) => padding.top + plotHeight - (Number(value || 0) / maxValue) * plotHeight;
        activeSeries.forEach((key) => {
            const info = seriesInfo[key];
            if (!info) return;
            const path = points.map((point, index) =>
                `${index ? "L" : "M"} ${xFor(index)} ${yFor(point[key])}`
            ).join(" ");
            svg.append(svgNode("path", {
                d: path,
                class: "soc-chart-path",
                style: `--series-color:${info.color}`,
            }));
            points.forEach((point, index) => {
                const circle = svgNode("circle", {
                    cx: xFor(index), cy: yFor(point[key]), r: 3,
                    class: "soc-chart-point",
                    style: `--series-color:${info.color}`,
                });
                circle.addEventListener("mouseenter", () => {
                    tooltip.textContent = `${formatDate(point.timestamp)} · ${info.label}: ${formatNumber(point[key])}`;
                });
                circle.addEventListener("focus", () => {
                    tooltip.textContent = `${formatDate(point.timestamp)} · ${info.label}: ${formatNumber(point[key])}`;
                });
                svg.append(circle);
            });
        });
        const labelCount = Math.min(points.length, 6);
        for (let index = 0; index < labelCount; index += 1) {
            const pointIndex = Math.round(index * (points.length - 1) / Math.max(1, labelCount - 1));
            const label = svgNode("text", {
                x: xFor(pointIndex), y: height - 11, "text-anchor": "middle",
                class: "soc-chart-label",
            });
            label.textContent = String(points[pointIndex].timestamp || "").slice(5, 16);
            svg.append(label);
        }
        tooltip.textContent = `${formatDate(points[points.length - 1].timestamp)} · ${points.length} recorded time buckets`;
    }

    function renderLegendList(target, values, palette) {
        const list = typeof target === "string" ? one(target) : target;
        clear(list);
        const entries = Object.entries(values || {}).filter(([, value]) => value !== null && value !== undefined);
        const isSeverity = list.matches("[data-legend='severity']");
        if (!entries.length) {
            list.append(element("div", "soc-empty", "No recorded results."));
            if (isSeverity) {
                const donut = one("[data-donut='severity']");
                donut.style.background = "conic-gradient(#35475b 0% 100%)";
                donut.dataset.total = "0";
            }
            return;
        }
        const total = entries.reduce((sum, [, value]) => sum + Number(value || 0), 0);
        entries.forEach(([label, value], index) => {
            const row = element("div", "soc-legend-row");
            const color = palette[index % palette.length];
            const description = label.replaceAll("_", " ");
            row.append(element("span", "soc-legend-dot"));
            row.lastElementChild.style.setProperty("--legend-color", color);
            row.append(element("span", "", description), element("strong", "", formatNumber(value)));
            list.append(row);
        });
        if (isSeverity) {
            const donut = one("[data-donut='severity']");
            const stops = [];
            let offset = 0;
            entries.forEach(([label, value], index) => {
                const fraction = total ? Number(value) / total * 100 : 0;
                stops.push(`${palette[index % palette.length]} ${offset}% ${offset + fraction}%`);
                offset += fraction;
            });
            donut.style.background = total
                ? `conic-gradient(${stops.join(",")})`
                : "conic-gradient(#35475b 0% 100%)";
            donut.dataset.total = formatNumber(total);
        }
    }

    function renderCategories(items) {
        const list = one("[data-category-distribution]");
        clear(list);
        const rows = items || [];
        if (!rows.length) {
            list.append(element("div", "soc-empty", "No recorded categories."));
            return;
        }
        const max = Math.max(1, ...rows.map((row) => Number(row.value || 0)));
        rows.forEach((item) => {
            const row = element("div", "soc-category-row");
            row.append(element("span", "", item.label || "Uncategorized"));
            const bar = element("span", "soc-category-bar");
            const fill = document.createElement("span");
            fill.style.width = `${Math.max(0, Math.min(100, Number(item.value || 0) / max * 100))}%`;
            bar.append(fill);
            row.append(bar, element("strong", "", formatNumber(item.value)));
            list.append(row);
        });
    }

    function setEmpty(selector, visible, message) {
        const node = one(selector);
        if (message) node.textContent = message;
        node.hidden = !visible;
    }

    function appendCell(row, value, className) {
        const cell = element("td", className || "", value);
        row.append(cell);
        return cell;
    }

    function addLink(cell, href, text, className) {
        const link = element("a", className || "", text);
        link.href = href || "#";
        cell.replaceChildren(link);
        return link;
    }

    function renderMetrics(selector, items) {
        const box = one(selector);
        clear(box);
        items.forEach(([label, value]) => {
            const metric = element("div", "soc-mini-metric");
            metric.append(element("span", "", label), element("strong", "", value));
            box.append(metric);
        });
    }

    function renderEmail(data) {
        renderMetrics("[data-email-metrics]", [
            ["Messages", formatNumber(data.total)],
            ["High risk", formatNumber(data.phishing)],
            ["Suspicious", formatNumber(data.suspicious)],
            ["Low signal", formatNumber(data.low_signal)],
            ["SPF failures", formatNumber(data.spf_failures)],
            ["Sender spoofing", formatNumber(data.sender_spoofing)],
            ["URLs observed", formatNumber(data.url_count)],
            ["Attachments", formatNumber(data.attachment_count)],
        ]);
        const body = one("[data-email-rows]");
        clear(body);
        (data.records || []).forEach((record) => {
            const row = document.createElement("tr");
            addLink(appendCell(row, ""), record.investigation_url, record.sender || "(unknown sender)");
            appendCell(row, record.recipient);
            appendCell(row, record.subject || "(no subject)");
            appendCell(row, record.domain);
            appendCell(row, formatNumber(record.attachment_count));
            appendCell(row, formatNumber(record.url_count));
            appendCell(row, `${formatNumber(record.risk_score)}/100`);
            appendCell(row, record.verdict);
            body.append(row);
        });
        setEmpty("[data-email-empty]", !(data.records || []).length);
    }

    function renderUrls(data) {
        renderMetrics("[data-url-metrics]", [
            ["Scans", formatNumber(data.total)],
            ["Phishing", formatNumber(data.phishing)],
            ["Legitimate predictions", formatNumber(data.legitimate)],
            ["IP-based", formatNumber(data.ip_based)],
            ["Punycode", formatNumber(data.punycode)],
            ["Shortened", formatNumber(data.shortened)],
            ["Avg. phishing probability", data.average_phishing_probability === null
                ? "—" : `${data.average_phishing_probability}%`],
        ]);
        const body = one("[data-url-rows]");
        clear(body);
        (data.records || []).forEach((record) => {
            const row = document.createElement("tr");
            const urlCell = appendCell(row, "");
            addLink(urlCell, record.investigation_url, record.url);
            urlCell.append(element("span", "soc-subtext", record.host || "Host unavailable"));
            appendCell(row, record.result);
            appendCell(row, record.probability === null ? "—" : `${record.probability}%`);
            appendCell(row, formatDate(record.timestamp));
            addLink(appendCell(row, ""), record.investigation_url, "Open →", "soc-open-link");
            body.append(row);
        });
        setEmpty("[data-url-empty]", !(data.records || []).length);
    }

    function renderFiles(data) {
        const classification = data.classification || {};
        renderMetrics("[data-file-metrics]", [
            ["Scans", formatNumber(data.total)],
            ["Completed", formatNumber(data.completed)],
            ["Malicious detections", formatNumber(classification.malicious)],
            ["No detections", formatNumber(classification.clean)],
            ["Unknown", formatNumber(classification.unknown)],
            ["Pending", formatNumber(data.pending)],
            ["Failed", formatNumber(data.failed)],
        ]);
        const body = one("[data-file-rows]");
        clear(body);
        (data.records || []).forEach((record) => {
            const row = document.createElement("tr");
            const fileCell = appendCell(row, "");
            addLink(fileCell, record.investigation_url, record.filename);
            fileCell.append(element("span", "soc-subtext", record.file_type || "Type unavailable"));
            appendCell(row, formatBytes(record.file_size));
            appendCell(row, record.sha256 || "—");
            const enginesCell = appendCell(row, "");
            const engines = (record.engines || []).map((engine) =>
                `${engine.provider || engine.name || "Scanner"}: ${engine.status || "unknown"}`
            );
            enginesCell.textContent = engines.length ? engines.join(", ") : "No engine details";
            appendCell(row, record.status);
            addLink(appendCell(row, ""), record.investigation_url, "Open →", "soc-open-link");
            body.append(row);
        });
        setEmpty("[data-file-empty]", !(data.records || []).length);
    }

    function renderIndicators(data) {
        const target = one("[data-top-indicators]");
        clear(target);
        const groups = [
            ["Sender domains", data.sender_domains],
            ["Phishing URL hosts", data.suspicious_urls],
            ["Detected file hashes", data.file_hashes],
            ["High-risk subjects", data.phishing_subjects],
            ["Finding categories", data.categories],
        ];
        groups.forEach(([title, items]) => {
            const section = element("div", "soc-indicator-group");
            section.append(element("h3", "", title));
            const values = items || [];
            if (!values.length) {
                section.append(element("div", "soc-indicator-item", "No recorded indicators"));
            } else {
                values.forEach((item) => {
                    const row = element("div", "soc-indicator-item");
                    row.append(element("span", "", item.label || "Unavailable"), element("strong", "", formatNumber(item.count)));
                    section.append(row);
                });
            }
            target.append(section);
        });
    }

    const renderers = {
        summary: renderKpis,
        activity: (data) => {
            window.dashboardActivity = data;
            renderChartLegend(data.series);
            drawChart(data);
        },
        distribution: (data) => {
            const colors = ["#ff6578", "#ff9b55", "#ebc66d", "#55d5b6", "#77a8ff"];
            const severity = {};
            ["Critical", "High", "Medium", "Low", "Informational"].forEach((key) => {
                if (data.severity && data.severity[key]) severity[key] = data.severity[key];
            });
            renderLegendList("[data-legend='severity']", severity, colors);
            renderCategories(data.categories);
            renderLegendList("[data-legend='files']", data.files, ["#ff7486", "#55d5b6", "#ebc66d", "#7990a3"]);
            renderLegendList("[data-legend='urls']", data.urls, ["#ff7486", "#55d5b6", "#ebc66d", "#7990a3"]);
        },
        email: renderEmail,
        url: renderUrls,
        file: renderFiles,
        indicators: renderIndicators,
    };

    async function globalSearch() {
        const input = one("[data-global-search]");
        const resultsBox = one("[data-global-search-results]");
        const query = input.value.trim();
        clear(resultsBox);
        if (query.length < 2) {
            resultsBox.hidden = true;
            return;
        }
        try {
            const data = await getJson("/api/dashboard/search", { q: query });
            clear(resultsBox);
            if (!data.results.length) {
                resultsBox.append(element("div", "soc-search-empty", "No matching scans or incidents in this time range."));
            } else {
                data.results.forEach((result) => {
                    const row = element("a", "soc-search-result");
                    row.href = result.url;
                    row.append(
                        element("span", "soc-search-kind", result.kind),
                        element("strong", "", result.label || "No label"),
                        element("small", "", `${result.detail || ""} · ${formatDate(result.timestamp)}`)
                    );
                    resultsBox.append(row);
                });
            }
            resultsBox.hidden = false;
        } catch (error) {
            resultsBox.append(element("div", "soc-search-empty", error.message));
            resultsBox.hidden = false;
        }
    }

    function setCustomRangeVisibility() {
        const custom = rangeSelect.value === "custom";
        one("[data-custom-range]").hidden = !custom;
    }

    rangeSelect.addEventListener("change", () => {
        setCustomRangeVisibility();
        if (rangeSelect.value !== "custom") loadAll();
    });
    one("[data-apply-range]").addEventListener("click", () => {
        const start = one("[data-range-start]").value;
        const end = one("[data-range-end]").value;
        if (!start || !end || start >= end) {
            showError("Choose a valid custom range with a start earlier than its end.");
            return;
        }
        loadAll();
    });
    refreshButton.addEventListener("click", () => loadAll());
    bucketSelect.addEventListener("change", () => {
        getJson("/api/dashboard/activity", { bucket: bucketSelect.value })
            .then(renderers.activity)
            .catch((error) => showError(`Could not load activity chart: ${error.message}`));
    });
    one("[data-global-search]").addEventListener("input", () => {
        window.clearTimeout(state.globalSearchTimer);
        state.globalSearchTimer = window.setTimeout(globalSearch, 250);
    });
    document.addEventListener("click", (event) => {
        if (!event.target.closest(".soc-global-search") && !event.target.closest("[data-global-search-results]")) {
            one("[data-global-search-results]").hidden = true;
        }
    });
    const refreshSeconds = Number(root.dataset.refreshSeconds);
    if (Number.isFinite(refreshSeconds) && refreshSeconds > 0) {
        window.setInterval(() => {
            if (!document.hidden) loadAll();
        }, refreshSeconds * 1000);
    }
    setCustomRangeVisibility();
    loadAll();
});
