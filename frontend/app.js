"use strict";

/* CyberLens Frontend Application
   Clean full version - no template literals
*/

const API = Object.freeze({
    health: "/api/health",
    dashboard: "/api/dashboard",
    scans: "/api/scans",

    scanDetails: function (id) {
        return "/api/scans/" + encodeURIComponent(String(id));
    },

    scanUrl: "/api/scan/url",
    scanCode: "/api/scan/code",
    scanDependencies: "/api/scan/dependencies",
    scanProject: "/api/scan/project",
    aiExplain: "/api/ai/explain"
});


const state = {
    dashboard: {},
    scans: [],
    filteredScans: [],
    latestAiAnalysis: null,
    latestScanDetails: null,
    activePage: "dashboard",
    activeScanTab: "url",
    isScanning: false
};


/* =========================================================
   Basic DOM Helpers
========================================================= */

function byId(id) {
    return document.getElementById(id);
}


function all(selector, root) {
    return Array.from(
        (root || document).querySelectorAll(selector)
    );
}


function one(selector, root) {
    return (root || document).querySelector(selector);
}


function setText(id, value) {
    const el = byId(id);

    if (el) {
        el.textContent = String(
            value === undefined || value === null
                ? ""
                : value
        );
    }
}


/* =========================================================
   Safe Text / HTML Helpers
========================================================= */

function escapeHtml(value) {
    return String(
        value === undefined || value === null
            ? ""
            : value
    )
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}


function safeText(value, fallback) {
    const text = String(
        value === undefined || value === null
            ? ""
            : value
    ).trim();

    return text || String(
        fallback === undefined
            ? "غير متوفر"
            : fallback
    );
}


/* =========================================================
   Number Helpers
========================================================= */

function toNumber(value, fallback) {
    const n = Number(value);

    return Number.isFinite(n)
        ? n
        : (
            fallback === undefined
                ? 0
                : fallback
        );
}


function clampScore(value) {
    return Math.max(
        0,
        Math.min(
            100,
            Math.round(
                toNumber(value, 0)
            )
        )
    );
}


function formatNumber(value) {
    try {
        return new Intl.NumberFormat(
            "ar"
        ).format(
            toNumber(value, 0)
        );
    }
    catch (error) {
        return String(
            toNumber(value, 0)
        );
    }
}


/* =========================================================
   Date Helpers
========================================================= */

function formatDate(value) {
    if (!value) {
        return "غير متوفر";
    }

    const date = new Date(value);

    if (
        Number.isNaN(
            date.getTime()
        )
    ) {
        return String(value);
    }

    try {
        return new Intl.DateTimeFormat(
            "ar",
            {
                year: "numeric",
                month: "short",
                day: "numeric",
                hour: "2-digit",
                minute: "2-digit"
            }
        ).format(date);
    }
    catch (error) {
        return date.toLocaleString();
    }
}


function renderCurrentDate() {
    const container = byId(
        "currentDate"
    );

    const span = container
        ? one(
            "span",
            container
        )
        : null;

    if (!span) {
        return;
    }
    try {
        span.textContent =
            new Intl.DateTimeFormat(
                "ar",
                {
                    weekday: "long",
                    year: "numeric",
                    month: "long",
                    day: "numeric"
                }
            ).format(
                new Date()
            );
    }
    catch (error) {
        span.textContent =
            new Date().toLocaleDateString();
    }
}


/* =========================================================
   Severity Helpers
========================================================= */

function normalizeSeverity(value) {
    const severity = String(
        value === undefined || value === null
            ? "info"
            : value
    )
        .trim()
        .toLowerCase();

    return [
        "critical",
        "high",
        "medium",
        "low",
        "info",
        "none"
    ].includes(severity)
        ? severity
        : "info";
}


function severityLabel(value) {
    const labels = {
        critical: "حرجة",
        high: "عالية",
        medium: "متوسطة",
        low: "منخفضة",
        info: "معلوماتية",
        none: "لا توجد"
    };

    return labels[
        normalizeSeverity(value)
    ] || "معلوماتية";
}


function severityTextClass(value) {
    return "text-" +
        normalizeSeverity(value);
}


function cvssBadge(score, vector) {
    const numericScore =
        Number(score);

    if (!numericScore || Number.isNaN(numericScore)) {
        return "";
    }

    return (
        '<span class="badge badge-cvss" title="' +
        escapeHtml(vector || "") +
        '">CVSS ' +
        escapeHtml(numericScore.toFixed(1)) +
        "</span>"
    );
}


function severityBadge(value) {
    const severity =
        normalizeSeverity(value);

    return (
        '<span class="badge badge-' +
        escapeHtml(severity) +
        '">' +
        escapeHtml(
            severityLabel(severity)
        ) +
        "</span>"
    );
}


function severityRank(value) {
    const ranks = {
        critical: 5,
        high: 4,
        medium: 3,
        low: 2,
        info: 1,
        none: 0
    };

    return ranks[
        normalizeSeverity(value)
    ] || 0;
}


function highestSeverityFromCounts(counts) {
    const source =
        counts &&
        typeof counts === "object"
            ? counts
            : {};

    for (
        const severity
        of [
            "critical",
            "high",
            "medium",
            "low",
            "info"
        ]
    ) {
        if (
            toNumber(
                source[severity],
                0
            ) > 0
        ) {
            return severity;
        }
    }

    return "none";
}


/* =========================================================
   Scan Type Helpers
========================================================= */

function normalizeScanType(value) {
    const type = String(
        value === undefined || value === null
            ? "general"
            : value
    )
        .trim()
        .toLowerCase();

    return [
        "url",
        "code",
        "dependencies",
        "project",
        "general"
    ].includes(type)
        ? type
        : "general";
}


function scanTypeLabel(value) {
    const labels = {
        url: "رابط",
        code: "كود",
        dependencies: "مكتبات",
        project: "مشروع",
        general: "عام"
    };

    return labels[
        normalizeScanType(value)
    ] || "عام";
}


function scanTypeBadge(value) {
    const type =
        normalizeScanType(value);

    return (
        '<span class="badge badge-' +
        escapeHtml(type) +
        '">' +
        escapeHtml(
            scanTypeLabel(type)
        ) +
        "</span>"
    );
}


/* =========================================================
   Score Helpers
========================================================= */

function scoreClass(score) {
    const n = toNumber(
        score,
        0
    );

    if (n >= 80) {
        return "score-good";
    }

    if (n >= 50) {
        return "score-warning";
    }

    return "score-danger";
}


function scoreBadge(score) {
    const n = clampScore(score);

    return (
        '<span class="score-badge ' +
        scoreClass(n) +
        '">' +
        '<span class="score-dot"></span>' +
        escapeHtml(n) +
        "</span>"
    );
}
function riskLabelFromScore(score) {
    const n = toNumber(
        score,
        0
    );

    if (n >= 80) {
        return "منخفض";
    }

    if (n >= 50) {
        return "متوسط";
    }

    if (n >= 25) {
        return "مرتفع";
    }

    return "حرج";
}


/* =========================================================
   API Response Helpers
========================================================= */

function payloadData(payload, fallback) {
    if (
        payload &&
        Object.prototype.hasOwnProperty.call(
            payload,
            "data"
        )
    ) {
        return payload.data;
    }

    return fallback;
}


function normalizeScan(scan) {
    const s =
        scan &&
        typeof scan === "object"
            ? scan
            : {};

    return {
        id: s.id,

        scan_type:
            s.scan_type ||
            s.type ||
            "general",

        target_name:
            s.target_name ||
            s.target ||
            s.filename ||
            "غير متوفر",

        total_findings:
            s.total_findings !== undefined
                ? s.total_findings
                : (
                    Array.isArray(s.findings)
                        ? s.findings.length
                        : 0
                ),

        security_score:
            s.security_score !== undefined
                ? s.security_score
                : (
                    s.score !== undefined
                        ? s.score
                        : 0
                ),

        highest_severity:
            s.highest_severity ||
            s.severity ||
            "none",

        created_at:
            s.created_at ||
            s.timestamp ||
            s.date ||
            null,

        findings:
            Array.isArray(s.findings)
                ? s.findings
                : [],

        metadata:
            s.metadata &&
            typeof s.metadata === "object"
                ? s.metadata
                : {},

        ai_analysis:
            s.ai_analysis &&
            typeof s.ai_analysis === "object"
                ? s.ai_analysis
                : null
    };
}


/* =========================================================
   Global Alert
========================================================= */

let alertTimer = null;


function showAlert(
    message,
    type,
    duration
) {
    const alert = byId(
        "globalAlert"
    );

    if (!alert) {
        return;
    }

    if (alertTimer) {
        clearTimeout(
            alertTimer
        );

        alertTimer = null;
    }

    alert.className =
        "global-alert " +
        (type || "info");

    alert.textContent =
        String(message || "");

    alert.hidden = false;

    const timeout =
        duration === undefined
            ? 5000
            : duration;

    if (timeout > 0) {
        alertTimer =
            setTimeout(
                function () {
                    alert.hidden = true;
                },
                timeout
            );
    }
}


function hideAlert() {
    const alert = byId(
        "globalAlert"
    );

    if (alert) {
        alert.hidden = true;
    }
}


/* =========================================================
   API Request
========================================================= */

async function apiRequest(
    url,
    options
) {
    let response;

    try {
        response =
            await fetch(
                url,
                Object.assign(
                    {
                        credentials:
                            "same-origin"
                    },
                    options || {}
                )
            );
    }
    catch (error) {
        throw new Error(
            "تعذر الاتصال بخادم CyberLens."
        );
    }

    let payload = null;

    try {
        payload =
            await response.json();
    }
    catch (error) {
        payload = null;
    }
    if (!response.ok) {
        const message =
            (
                payload &&
                payload.message
            ) ||
            (
                payload &&
                payload.error
            ) ||
            (
                "فشل الطلب برمز " +
                response.status
            );

        throw new Error(
            String(message)
        );
    }

    if (
        payload &&
        payload.success === false
    ) {
        throw new Error(
            String(
                payload.message ||
                payload.error ||
                "فشل تنفيذ الطلب."
            )
        );
    }

    return payload;
}


/* =========================================================
   Health Check
========================================================= */

async function checkHealth() {
    const dot = byId(
        "sidebarStatusDot"
    );

    const text = byId(
        "sidebarStatusText"
    );

    try {
        const payload =
            await apiRequest(
                API.health
            );

        const data =
            payloadData(
                payload,
                {}
            );

        const status =
            data &&
            data.status
                ? data.status
                : "online";

        if (status !== "online") {
            throw new Error(
                "offline"
            );
        }

        if (dot) {
            dot.className =
                "status-dot online";
        }

        if (text) {
            text.textContent =
                "النظام يعمل";
        }

        return true;
    }
    catch (error) {
        if (dot) {
            dot.className =
                "status-dot offline";
        }

        if (text) {
            text.textContent =
                "تعذر الاتصال";
        }

        return false;
    }
}


/* =========================================================
   Pages
========================================================= */

const PAGE_CONFIG = {
    dashboard: {
        title:
            "لوحة التحكم الأمنية",

        subtitle:
            "مراقبة وتحليل نتائج الفحوصات الأمنية"
    },

    scanner: {
        title:
            "مركز الفحص الأمني",

        subtitle:
            "تحليل الروابط والكود والمكتبات والمشاريع"
    },

    dependencies: {
        title:
            "أمان المكتبات",

        subtitle:
            "تحليل الاعتماديات والثغرات المعروفة"
    },

    history: {
        title:
            "سجل الفحوصات",

        subtitle:
            "العمليات والتقارير الأمنية المحفوظة"
    },

    vulnerabilities: {
        title:
            "مركز النتائج",

        subtitle:
            "استعراض أحدث النتائج والثغرات الأمنية"
    },

    ai: {
        title:
            "المحلل الأمني الذكي",

        subtitle:
            "الأولويات والعلاقات والتوصيات الأمنية"
    }
};


function openPage(pageName) {
    const page =
        PAGE_CONFIG[pageName]
            ? pageName
            : "dashboard";

    state.activePage = page;

    all(
        "[data-page-section]"
    ).forEach(
        function (section) {
            const active =
                section.dataset.pageSection
                === page;

            section.hidden =
                !active;

            section.classList.toggle(
                "active",
                active
            );
        }
    );

    all(
        ".nav-item[data-page]"
    ).forEach(
        function (button) {
            button.classList.toggle(
                "active",
                button.dataset.page
                === page
            );
        }
    );

    setText(
        "pageTitle",
        PAGE_CONFIG[page].title
    );

    setText(
        "pageSubtitle",
        PAGE_CONFIG[page].subtitle
    );

    closeMobileSidebar();

    try {
        window.scrollTo({
            top: 0,
            behavior: "smooth"
        });
    }
    catch (error) {
        window.scrollTo(
            0,
            0
        );
    }

    if (page === "history") {
        renderHistoryTable();
    }
    if (page === "dependencies") {
        renderDependencyHistory();
    }

    if (page === "vulnerabilities") {
        renderVulnerabilities();
    }

    if (page === "ai") {
        renderAiPage();
    }
}


/* =========================================================
   Mobile Sidebar
========================================================= */

function openMobileSidebar() {
    const sidebar = byId(
        "sidebar"
    );

    const overlay = byId(
        "mobileOverlay"
    );

    if (sidebar) {
        sidebar.classList.add(
            "open"
        );
    }

    if (overlay) {
        overlay.classList.add(
            "open"
        );

        overlay.setAttribute(
            "aria-hidden",
            "false"
        );
    }

    document.body.classList.add(
        "sidebar-open"
    );
}


function closeMobileSidebar() {
    const sidebar = byId(
        "sidebar"
    );

    const overlay = byId(
        "mobileOverlay"
    );

    if (sidebar) {
        sidebar.classList.remove(
            "open"
        );
    }

    if (overlay) {
        overlay.classList.remove(
            "open"
        );

        overlay.setAttribute(
            "aria-hidden",
            "true"
        );
    }

    document.body.classList.remove(
        "sidebar-open"
    );
}


/* =========================================================
   Dashboard
========================================================= */

async function loadDashboard(showSuccess) {
    try {
        const payload =
            await apiRequest(
                API.dashboard
            );

        const data =
            payloadData(
                payload,
                {}
            );

        state.dashboard =
            data &&
            typeof data === "object"
                ? data
                : {};

        renderDashboard();

        if (showSuccess) {
            showAlert(
                "تم تحديث بيانات لوحة التحكم.",
                "success",
                3000
            );
        }

        return state.dashboard;
    }
    catch (error) {
        showAlert(
            error.message,
            "error",
            6000
        );

        return null;
    }
}


function renderDashboard() {
    const d =
        state.dashboard || {};

    const summary =
        d.summary &&
        typeof d.summary === "object"
            ? d.summary
            : {};

    const averageScore =
        toNumber(
            d.average_score !== undefined
                ? d.average_score
                : summary.average_score,
            100
        );

    const totalFindings =
        toNumber(
            d.total_findings !== undefined
                ? d.total_findings
                : summary.total_findings,
            0
        );

    const totalScans =
        toNumber(
            d.total_scans !== undefined
                ? d.total_scans
                : summary.total_scans,
            0
        );

    const severityCounts =
        d.severity_counts &&
        typeof d.severity_counts === "object"
            ? d.severity_counts
            : {};

    const scanTypeCounts =
        d.scan_type_counts &&
        typeof d.scan_type_counts === "object"
            ? d.scan_type_counts
            : {};

    const latestScan =
        d.latest_scan &&
        typeof d.latest_scan === "object"
            ? d.latest_scan
            : null;

    const recentScans =
        Array.isArray(
            d.recent_scans
        )
            ? d.recent_scans
            : state.scans.slice(
                0,
                6
            );

    setText(
        "averageScoreValue",
        Math.round(
            averageScore
        )
    );

    setText(
        "averageScoreStatus",
        riskLabelFromScore(
            averageScore
        )
    );

    setText(
        "totalFindingsValue",
        formatNumber(
            totalFindings
        )
    );

    setText(
        "totalScansValue",
        formatNumber(
            totalScans
        )
    );
    const highestSeverity =
        d.highest_severity ||
        (
            latestScan &&
            latestScan.highest_severity
        ) ||
        highestSeverityFromCounts(
            severityCounts
        );

    const highestRisk = byId(
        "highestRiskValue"
    );

    if (highestRisk) {
        highestRisk.textContent =
            severityLabel(
                highestSeverity
            );

        highestRisk.className =
            "risk-text " +
            severityTextClass(
                highestSeverity
            );
    }

    setText(
        "highestRiskHint",
        totalScans > 0
            ? "حسب الفحوصات المحفوظة"
            : "لا توجد فحوصات بعد"
    );

    renderSeverityChart(
        severityCounts
    );

    renderScanTypeBars(
        scanTypeCounts
    );

    renderRecentScans(
        recentScans
    );

    renderGeneralRecommendation(
        averageScore,
        highestSeverity
    );
}


/* =========================================================
   Severity Chart
========================================================= */

function renderSeverityChart(counts) {
    const c =
        counts &&
        typeof counts === "object"
            ? counts
            : {};

    const critical =
        toNumber(
            c.critical,
            0
        );

    const high =
        toNumber(
            c.high,
            0
        );

    const medium =
        toNumber(
            c.medium,
            0
        );

    const low =
        toNumber(
            c.low,
            0
        );

    const info =
        toNumber(
            c.info,
            0
        );

    const total =
        critical +
        high +
        medium +
        low +
        info;

    setText(
        "legendCritical",
        formatNumber(critical)
    );

    setText(
        "legendHigh",
        formatNumber(high)
    );

    setText(
        "legendMedium",
        formatNumber(medium)
    );

    setText(
        "legendLow",
        formatNumber(low)
    );

    setText(
        "donutTotal",
        formatNumber(total)
    );

    const chart = byId(
        "severityDonut"
    );

    if (!chart) {
        return;
    }

    if (total <= 0) {
        chart.style.background =
            "conic-gradient(#e7edf5 0deg 360deg)";

        return;
    }

    const criticalEnd =
        (
            critical /
            total
        ) * 360;

    const highEnd =
        criticalEnd +
        (
            high /
            total
        ) * 360;

    const mediumEnd =
        highEnd +
        (
            medium /
            total
        ) * 360;

    const lowEnd =
        mediumEnd +
        (
            low /
            total
        ) * 360;

    chart.style.background =
        "conic-gradient(" +

        "var(--critical) 0deg " +
        criticalEnd +
        "deg, " +

        "var(--high) " +
        criticalEnd +
        "deg " +
        highEnd +
        "deg, " +

        "var(--medium) " +
        highEnd +
        "deg " +
        mediumEnd +
        "deg, " +

        "var(--low) " +
        mediumEnd +
        "deg " +
        lowEnd +
        "deg, " +

        "var(--info) " +
        lowEnd +
        "deg 360deg)";
}


/* =========================================================
   Scan Type Bars
========================================================= */

function renderScanTypeBars(counts) {
    const c =
        counts &&
        typeof counts === "object"
            ? counts
            : {};

    const values = {
        url:
            toNumber(
                c.url,
                0
            ),

        code:
            toNumber(
                c.code,
                0
            ),

        dependencies:
            toNumber(
                c.dependencies,
                0
            ),

        project:
            toNumber(
                c.project,
                0
            )
    };
    const maximum =
        Math.max(
            1,
            values.url,
            values.code,
            values.dependencies,
            values.project
        );

    const mapping = {
        url: [
            "barUrl",
            "barUrlValue"
        ],

        code: [
            "barCode",
            "barCodeValue"
        ],

        dependencies: [
            "barDependencies",
            "barDependenciesValue"
        ],

        project: [
            "barProject",
            "barProjectValue"
        ]
    };

    Object.keys(
        values
    ).forEach(
        function (type) {
            const count =
                values[type];

            const bar =
                byId(
                    mapping[type][0]
                );

            const value =
                byId(
                    mapping[type][1]
                );

            const height =
                count <= 0
                    ? 2
                    : Math.max(
                        8,
                        (
                            count /
                            maximum
                        ) * 100
                    );

            if (bar) {
                bar.style.height =
                    height + "%";
            }

            if (value) {
                value.textContent =
                    formatNumber(
                        count
                    );
            }
        }
    );
}


/* =========================================================
   Recommendation
========================================================= */

function renderGeneralRecommendation(
    score,
    highestSeverity
) {
    const container = byId(
        "generalRecommendation"
    );

    if (!container) {
        return;
    }

    const severity =
        normalizeSeverity(
            highestSeverity
        );

    let text =
        "الوضع الأمني مستقر. استمر في الفحص الدوري ومراجعة الاعتماديات.";

    if (
        severity === "critical" ||
        score < 25
    ) {
        text =
            "توجد مخاطر حرجة. ابدأ بالنتائج الحرجة والمخاطر المترابطة، ثم طبّق الإصلاحات في بيئة اختبار وأعد الفحص.";
    }
    else if (
        severity === "high" ||
        score < 50
    ) {
        text =
            "الأولوية الحالية لمعالجة النتائج عالية الخطورة ومراجعة العلاقات بين النتائج قبل الانتقال للمخاطر الأقل.";
    }
    else if (
        severity === "medium" ||
        score < 80
    ) {
        text =
            "توجد مخاطر متوسطة تحتاج خطة معالجة منظمة، مع إعادة الفحص بعد كل مجموعة تغييرات.";
    }

    container.textContent = text;
}


/* =========================================================
   Recent Scans
========================================================= */

function renderRecentScans(scans) {
    const body = byId(
        "recentScansBody"
    );

    if (!body) {
        return;
    }

    const records =
        Array.isArray(scans)
            ? scans.map(
                normalizeScan
            )
            : [];

    if (!records.length) {
        body.innerHTML =
            '<tr>' +
            '<td colspan="6" class="empty-state-cell">' +
            "لا توجد فحوصات محفوظة بعد." +
            "</td>" +
            "</tr>";

        return;
    }

    body.innerHTML =
        records
            .slice(
                0,
                6
            )
            .map(
                function (scan) {
                    return (
                        "<tr>" +

                        '<td><div class="break-word">' +
                        escapeHtml(
                            safeText(
                                scan.target_name
                            )
                        ) +
                        "</div></td>" +

                        "<td>" +
                        scanTypeBadge(
                            scan.scan_type
                        ) +
                        "</td>" +
                        "<td>" +
                        scoreBadge(
                            scan.security_score
                        ) +
                        "</td>" +

                        "<td>" +
                        escapeHtml(
                            formatNumber(
                                scan.total_findings
                            )
                        ) +
                        "</td>" +

                        "<td>" +
                        severityBadge(
                            scan.highest_severity
                        ) +
                        "</td>" +
"<td>" +

'<div style="display:flex;gap:6px;flex-wrap:wrap;">' +

'<button class="action-link" type="button" data-scan-details-id="' +

escapeHtml(
    scan.id
) +

'">' +

"فتح" +

"</button>" +


'<a class="action-link" href="/api/scans/' +

encodeURIComponent(
    String(
        scan.id
    )
) +

'/report.pdf">' +

"PDF" +

"</a>" +

"</div>" +

"</td>" +
                        "</tr>"
                    );
                }
            )
            .join("");
}


/* =========================================================
   Load Scans
========================================================= */

async function loadScans() {
    try {
        const payload =
            await apiRequest(
                API.scans
            );

        const data =
            payloadData(
                payload,
                []
            );

        state.scans =
            (
                Array.isArray(data)
                    ? data
                    : []
            ).map(
                normalizeScan
            );

        state.filteredScans =
            state.scans.slice();

        renderHistoryTable();

        renderDependencyHistory();

        if (
            state.activePage ===
            "vulnerabilities"
        ) {
            renderVulnerabilities();
        }

        await loadLatestScanForAi();

        return state.scans;
    }
    catch (error) {
        showAlert(
            error.message,
            "error",
            6000
        );

        return [];
    }
}


/* =========================================================
   History Filtering
========================================================= */

function applyHistoryFilters() {
    const searchInput =
        byId(
            "historySearchInput"
        );

    const typeFilter =
        byId(
            "historyTypeFilter"
        );

    const search =
        String(
            (
                searchInput &&
                searchInput.value
            ) || ""
        )
            .trim()
            .toLowerCase();

    const type =
        String(
            (
                typeFilter &&
                typeFilter.value
            ) || ""
        )
            .trim()
            .toLowerCase();

    state.filteredScans =
        state.scans.filter(
            function (scan) {
                const target =
                    String(
                        scan.target_name ||
                        ""
                    ).toLowerCase();

                const scanType =
                    normalizeScanType(
                        scan.scan_type
                    );

                const searchMatch =
                    !search ||
                    target.includes(
                        search
                    ) ||
                    scanTypeLabel(
                        scanType
                    )
                        .toLowerCase()
                        .includes(
                            search
                        );

                const typeMatch =
                    !type ||
                    scanType === type;

                return (
                    searchMatch &&
                    typeMatch
                );
            }
        );

    renderHistoryTable();
}


/* =========================================================
   History Table
========================================================= */
function renderHistoryTable() {
    const body = byId(
        "scanHistoryBody"
    );

    if (!body) {
        return;
    }

    const searchInput =
        byId(
            "historySearchInput"
        );

    const typeFilter =
        byId(
            "historyTypeFilter"
        );

    const filtering =
        Boolean(
            searchInput &&
            String(
                searchInput.value ||
                ""
            ).trim()
        ) ||
        Boolean(
            typeFilter &&
            typeFilter.value
        );

    const scans =
        filtering
            ? state.filteredScans
            : state.scans;

    if (!scans.length) {
        body.innerHTML =
            '<tr>' +
            '<td colspan="8" class="empty-state-cell">' +
            "لا توجد نتائج مطابقة." +
            "</td>" +
            "</tr>";

        return;
    }

    body.innerHTML =
        scans
            .map(
                function (scan) {
                    return (
                        "<tr>" +

                        "<td>#" +
                        escapeHtml(
                            scan.id
                        ) +
                        "</td>" +

                        '<td><div class="break-word">' +
                        escapeHtml(
                            safeText(
                                scan.target_name
                            )
                        ) +
                        "</div></td>" +

                        "<td>" +
                        scanTypeBadge(
                            scan.scan_type
                        ) +
                        "</td>" +

                        "<td>" +
                        escapeHtml(
                            formatNumber(
                                scan.total_findings
                            )
                        ) +
                        "</td>" +

                        "<td>" +
                        scoreBadge(
                            scan.security_score
                        ) +
                        "</td>" +

                        "<td>" +
                        severityBadge(
                            scan.highest_severity
                        ) +
                        "</td>" +

                        "<td>" +
                        escapeHtml(
                            formatDate(
                                scan.created_at
                            )
                        ) +
                        "</td>" +

                        "<td>" +
                        '<div style="display:flex;gap:6px;flex-wrap:wrap;">' +
                        '<button class="action-link" type="button" data-scan-details-id="' +
                        escapeHtml(
                            scan.id
                        ) +
                        '">' +
                        "\u0641\u062a\u062d" +
                        "</button>" +
                        '<a class="action-link" href="/api/scans/' +
                        encodeURIComponent(
                            String(
                                scan.id
                            )
                        ) +
                        '/report/inline' +
                        '" target="_blank" rel="noopener">' +
                        "\u0639\u0631\u0636 PDF" +
                        "</a>" +
                        '<a class="action-link" href="/api/scans/' +
                        encodeURIComponent(
                            String(
                                scan.id
                            )
                        ) +
                        '/report.pdf' +
                        '">' +
                        "\u062a\u062d\u0645\u064a\u0644 PDF" +
                        "</a>" +
                        "</div>" +
                        "</td>" +

                        "</tr>"
                    );
                }
            )
            .join("");
}


/* =========================================================
   Dependency History
========================================================= */

function renderDependencyHistory() {
    const body = byId(
        "dependencyHistoryBody"
    );

    if (!body) {
        return;
    }

    const scans =
        state.scans.filter(
            function (scan) {
                return (
                    normalizeScanType(
                        scan.scan_type
                    ) ===
                    "dependencies"
                );
            }
        );

    if (!scans.length) {
        body.innerHTML =
            '<tr>' +
            '<td colspan="6" class="empty-state-cell">' +
            "لا توجد فحوصات مكتبات محفوظة." +
            "</td>" +
            "</tr>";

        return;
    }

    body.innerHTML =
        scans
            .map(
                function (scan) {
                    return (
                        "<tr>" +
                        "<td>" +
                        escapeHtml(
                            safeText(
                                scan.target_name
                            )
                        ) +
                        "</td>" +

                        "<td>" +
                        escapeHtml(
                            formatNumber(
                                scan.total_findings
                            )
                        ) +
                        "</td>" +

                        "<td>" +
                        scoreBadge(
                            scan.security_score
                        ) +
                        "</td>" +

                        "<td>" +
                        severityBadge(
                            scan.highest_severity
                        ) +
                        "</td>" +

                        "<td>" +
                        escapeHtml(
                            formatDate(
                                scan.created_at
                            )
                        ) +
                        "</td>" +

                        "<td>" +
                        '<button class="action-link" type="button" data-scan-details-id="' +
                        escapeHtml(
                            scan.id
                        ) +
                        '">' +
                        "التفاصيل" +
                        "</button>" +
                        "</td>" +

                        "</tr>"
                    );
                }
            )
            .join("");
}


/* =========================================================
   Scan Tabs
========================================================= */

function openScanTab(tabName) {
    const allowed = [
        "url",
        "code",
        "dependencies",
        "project"
    ];

    const tab =
        allowed.includes(tabName)
            ? tabName
            : "url";

    state.activeScanTab = tab;

    all(
        "[data-scan-tab]"
    ).forEach(
        function (button) {
            button.classList.toggle(
                "active",
                button.dataset.scanTab
                === tab
            );
        }
    );

    all(
        "[data-scan-panel]"
    ).forEach(
        function (panel) {
            const active =
                panel.dataset.scanPanel
                === tab;

            panel.hidden =
                !active;

            panel.classList.toggle(
                "active",
                active
            );
        }
    );
}


/* =========================================================
   Scanning State
========================================================= */

function setScanning(value) {
    state.isScanning =
        Boolean(value);

    const loading =
        byId(
            "scanLoading"
        );

    if (loading) {
        loading.hidden =
            !state.isScanning;
    }

    all(
        "#page-scanner button[type='submit']"
    ).forEach(
        function (button) {
            button.disabled =
                state.isScanning;
        }
    );
}


/* =========================================================
   URL Scan
========================================================= */

async function submitUrlScan(event) {
    event.preventDefault();

    const input =
        byId(
            "urlInput"
        );

    const url =
        String(
            (
                input &&
                input.value
            ) || ""
        ).trim();

    if (!url) {
        showAlert(
            "أدخل رابطًا للفحص.",
            "warning",
            4000
        );

        return;
    }

    await runScanRequest({
        endpoint:
            API.scanUrl,

        options: {
            method:
                "POST",

            headers: {
                "Content-Type":
                    "application/json"
            },

            body:
                JSON.stringify({
                    url: url
                })
        }
    });
}
/* =========================================================
   File Scan
========================================================= */

async function submitFileScan(config) {
    const input =
        byId(
            config.inputId
        );

    const file =
        input &&
        input.files
            ? input.files[0]
            : null;

    if (!file) {
        showAlert(
            config.emptyMessage,
            "warning",
            4000
        );

        return;
    }

    const formData =
        new FormData();

    formData.append(
        "file",
        file
    );

    await runScanRequest({
        endpoint:
            config.endpoint,

        options: {
            method:
                "POST",

            body:
                formData
        }
    });
}


/* =========================================================
   Scan Request Runner
========================================================= */

async function runScanRequest(config) {
    if (state.isScanning) {
        return;
    }

    hideAlert();

    setScanning(true);

    const resultContainer =
        byId(
            "scanResultContainer"
        );

    if (resultContainer) {
        resultContainer.hidden =
            true;

        resultContainer.innerHTML =
            "";
    }

    try {
        const payload =
            await apiRequest(
                config.endpoint,
                config.options
            );

        const result =
            payloadData(
                payload,
                {}
            ) || {};

        state.latestAiAnalysis =
            result.ai_analysis &&
            typeof result.ai_analysis
            === "object"
                ? result.ai_analysis
                : null;

        persistLatestAiAnalysis();

        renderScanResult(
            result
        );

        showAlert(
            (
                payload &&
                payload.message
            ) ||
            "اكتمل الفحص بنجاح.",
            "success",
            4000
        );

        await Promise.all([
            loadDashboard(false),
            loadScans()
        ]);

        renderAiPage();
    }
    catch (error) {
        showAlert(
            error.message,
            "error",
            7000
        );
    }
    finally {
        setScanning(false);
    }
}


/* =========================================================
   Scan Result Renderer
========================================================= */

function renderScanResult(result) {
    const container =
        byId(
            "scanResultContainer"
        );

    if (!container) {
        return;
    }

    const findings =
        Array.isArray(
            result.findings
        )
            ? result.findings
            : [];

    const ai =
        result.ai_analysis &&
        typeof result.ai_analysis
        === "object"
            ? result.ai_analysis
            : {};

    const correlations =
        Array.isArray(
            ai.correlations
        )
            ? ai.correlations
            : [];

    const score =
        toNumber(
            result.security_score,
            0
        );

    let correlationsHtml =
        "";

    if (correlations.length) {
        correlationsHtml =

            '<div class="result-section">' +

            "<h3>" +
            "المخاطر المترابطة" +
            "</h3>" +

            '<div class="correlations-list">' +

            correlations
                .map(
                    renderCorrelationCard
                )
                .join("") +

            "</div>" +

            "</div>";
    }

    let findingsHtml =

        '<div class="empty-panel">' +

        "لم يتم اكتشاف نتائج أمنية." +

        "</div>";

    if (findings.length) {
        findingsHtml =

            '<div class="findings-grid">' +

            findings
                .slice(
                    0,
                    40
                )
                .map(
                    renderFindingCard
                )
                .join("") +

            "</div>";
            if (
            findings.length > 40
        ) {
            findingsHtml +=

                '<div class="empty-panel" style="margin-top: 14px;">' +

                "تم عرض أول 40 نتيجة من " +

                escapeHtml(
                    findings.length
                ) +

                ". يمكن فتح تفاصيل الفحص من سجل الفحوصات." +

                "</div>";
        }
    }

    container.innerHTML =

        '<div class="result-overview">' +


        '<div class="result-stat">' +

        "<span>" +
        "درجة الأمان" +
        "</span>" +

        "<strong>" +

        escapeHtml(
            Math.round(
                score
            )
        ) +

        "</strong>" +

        "</div>" +


        '<div class="result-stat">' +

        "<span>" +
        "إجمالي النتائج" +
        "</span>" +

        "<strong>" +

        escapeHtml(
            formatNumber(
                result.total_findings
                !== undefined
                    ? result.total_findings
                    : findings.length
            )
        ) +

        "</strong>" +

        "</div>" +


        '<div class="result-stat">' +

        "<span>" +
        "أعلى خطورة" +
        "</span>" +

        '<strong class="' +

        escapeHtml(
            severityTextClass(
                result.highest_severity
            )
        ) +

        '">' +

        escapeHtml(
            severityLabel(
                result.highest_severity
            )
        ) +

        "</strong>" +

        "</div>" +


        '<div class="result-stat">' +

        "<span>" +
        "وضع الذكاء" +
        "</span>" +

        "<strong>" +

        escapeHtml(
            safeText(
                ai.mode,
                "local"
            )
        ) +

        "</strong>" +

        "</div>" +


        "</div>" +


        '<div class="result-section">' +

        "<h3>" +
        "ملخص التحليل الأمني" +
        "</h3>" +

        '<div class="ai-summary-card">' +

        escapeHtml(
            safeText(
                ai.summary,
                "اكتمل الفحص الأمني."
            )
        ) +

        "</div>" +

        "</div>" +


        correlationsHtml +


        '<div class="result-section">' +

        "<h3>" +
        "النتائج الأمنية" +
        "</h3>" +

        findingsHtml +

        "</div>";

    container.hidden =
        false;

    try {
        container.scrollIntoView({
            behavior:
                "smooth",

            block:
                "start"
        });
    }
    catch (error) {
        container.scrollIntoView();
    }
}


/* =========================================================
   Finding Card
========================================================= */

function renderFindingCard(finding) {
    const item =
        finding &&
        typeof finding === "object"
            ? finding
            : {};

    const severity =
        normalizeSeverity(
            item.severity
        );

    const metadata =
        item.metadata &&
        typeof item.metadata === "object"
            ? item.metadata
            : {};

    const chips = [];

    if (item.id) {
        chips.push(
            safeText(
                item.id
            )
        );
    }

    if (item.package) {
        chips.push(
            "Package: " +
            safeText(
                item.package
            )
        );
    }

    if (item.installed_version) {
        chips.push(
            "Installed: " +
            safeText(
                item.installed_version
            )
        );
    }

    if (item.fixed_version) {
        chips.push(
            "Fix: " +
            safeText(
                item.fixed_version
            )
        );
    }

    if (item.project_file) {
        chips.push(
            safeText(
                item.project_file
            )
        );
    }
    else if (
        metadata.project_file
    ) {
        chips.push(
            safeText(
                metadata.project_file
            )
        );
    }

    if (item.cvss_score) {
        chips.push(
            "CVSS: " +
            safeText(
                item.cvss_score
            )
        );
    }

    if (item.cwe) {
        chips.push(
            safeText(
                item.cwe
            )
        );
    }

    const recommendationHtml =
        item.recommendation
            ? (
                "<p>" +

                "<strong>" +
                "التوصية: " +
                "</strong>" +

                escapeHtml(
                    item.recommendation
                ) +

                "</p>"
            )
            : "";

    const chipsHtml =
        chips.length
            ? (
                '<div class="finding-meta">' +

                chips
                    .slice(
                        0,
                        6
                    )
                    .map(
                        function (chip) {
                            return (
                                '<span class="meta-chip">' +

                                escapeHtml(
                                    chip
                                ) +

                                "</span>"
                            );
                        }
                    )
                    .join("") +

                "</div>"
            )
            : "";

    const findingKey =
        safeText(
            item.finding_id || item.id,
            ""
        ) ||
        (
            "fk-" +
            Math.random()
                .toString(36)
                .slice(2)
        );

    const hasDeepAnalysis =
        item.ai_analysis &&
        typeof item.ai_analysis === "object";

    const expandButtonHtml =
        hasDeepAnalysis
            ? (
                '<button type="button" class="btn-expand" ' +
                'data-toggle-analysis="' +
                escapeHtml(findingKey) +
                '" aria-expanded="false">' +
                "عرض التحليل الكامل (AI) ▾" +
                "</button>"
            )
            : "";

    const deepAnalysisHtml =
        hasDeepAnalysis
            ? renderFindingDeepAnalysis(
                item.ai_analysis,
                findingKey,
                {
                    cvss_vector: item.cvss_vector,
                    cvss_score: item.cvss_score
                }
            )
            : "";

    return (
        '<article class="finding-card severity-' +

        escapeHtml(
            severity
        ) +

        '" id="finding-' +
        escapeHtml(findingKey) +
        '">' +


        '<div class="finding-card-head">' +

        "<h3>" +

        escapeHtml(
            safeText(
                item.title,
                "نتيجة أمنية"
            )
        ) +

        "</h3>" +

        '<div class="badge-group">' +

        severityBadge(
            severity
        ) +

        cvssBadge(
            item.cvss_score,
            item.cvss_vector
        ) +

        "</div>" +

        "</div>" +


        "<p>" +

        escapeHtml(
            safeText(
                item.description,
                "تحتاج هذه النتيجة إلى مراجعة أمنية."
            )
        ) +

        "</p>" +


        recommendationHtml +

        chipsHtml +

        expandButtonHtml +

        deepAnalysisHtml +

        "</article>"
    );
}


/* =========================================================
   Finding Deep Analysis (AI-powered, full academic breakdown)
========================================================= */

function analysisSection(labelAr, labelEn, value) {
    const text = safeText(value, "");

    if (!text) {
        return "";
    }

    return (
        '<div class="analysis-block">' +

        '<div class="analysis-label">' +
        escapeHtml(labelAr) +
        ' <span class="analysis-label-en">(' +
        escapeHtml(labelEn) +
        ')</span>' +
        "</div>" +

        "<p>" +
        escapeHtml(text) +
        "</p>" +

        "</div>"
    );
}


function renderFindingDeepAnalysis(ai, findingKey, cvssMeta) {
    const a =
        ai && typeof ai === "object"
            ? ai
            : {};

    const cvss =
        cvssMeta && typeof cvssMeta === "object"
            ? cvssMeta
            : {};

    const ciaHtml =
        (a.confidentiality_impact ||
            a.integrity_impact ||
            a.availability_impact)
            ? (
                '<div class="cia-grid">' +

                '<div class="cia-box cia-c">' +
                '<div class="cia-title">السرّية <span>(Confidentiality)</span></div>' +
                "<p>" + escapeHtml(safeText(a.confidentiality_impact, "غير موضّح")) + "</p>" +
                "</div>" +

                '<div class="cia-box cia-i">' +
                '<div class="cia-title">السلامة <span>(Integrity)</span></div>' +
                "<p>" + escapeHtml(safeText(a.integrity_impact, "غير موضّح")) + "</p>" +
                "</div>" +

                '<div class="cia-box cia-a">' +
                '<div class="cia-title">التوفر <span>(Availability)</span></div>' +
                "<p>" + escapeHtml(safeText(a.availability_impact, "غير موضّح")) + "</p>" +
                "</div>" +

                "</div>"
            )
            : "";

    const classificationChips = [];

    if (cvss.cvss_vector) {
        classificationChips.push(safeText(cvss.cvss_vector));
    }

    if (a.owasp) {
        classificationChips.push("OWASP: " + safeText(a.owasp));
    }

    if (a.cwe) {
        classificationChips.push(safeText(a.cwe));
    }

    const classificationHtml =
        classificationChips.length
            ? (
                '<div class="analysis-block">' +
                '<div class="analysis-label">التصنيف الأمني <span class="analysis-label-en">(Classification)</span></div>' +
                '<div class="finding-meta" style="margin-top:6px;">' +
                classificationChips
                    .map(function (chip) {
                        return (
                            '<span class="meta-chip meta-chip-classification">' +
                            escapeHtml(chip) +
                            "</span>"
                        );
                    })
                    .join("") +
                "</div>" +
                "</div>"
            )
            : "";

    return (
        '<div class="finding-deep-analysis" data-analysis-panel="' +
        escapeHtml(findingKey) +
        '" hidden>' +

        analysisSection("الملخص التنفيذي", "Executive Summary", a.executive_summary) +
        analysisSection("ما هي المشكلة", "What Is The Issue", a.what_is_the_issue) +
        analysisSection("سبب الاكتشاف", "Why Detected", a.why_detected) +
        analysisSection("السبب الجذري", "Root Cause", a.root_cause) +

        '<div class="analysis-block analysis-block-main">' +
        '<div class="analysis-label">التحليل التقني <span class="analysis-label-en">(Technical Analysis)</span></div>' +
        "<p>" + escapeHtml(safeText(a.technical_analysis, "")) + "</p>" +
        "</div>" +

        analysisSection("تفسير الدليل", "Evidence Interpretation", a.evidence_interpretation) +
        analysisSection("تقييم قابلية الاستغلال", "Exploitability Assessment", a.exploitability_assessment) +
        analysisSection("الأثر الأمني", "Security Impact", a.security_impact) +

        ciaHtml +

        analysisSection("الأثر الهندسي", "Engineering Impact", a.engineering_impact) +
        analysisSection("لماذا يهم", "Why It Matters", a.why_it_matters) +
        analysisSection("تبرير درجة الخطورة", "Risk Rationale", a.risk_rationale) +
        analysisSection("الإصلاح الموصى به", "Recommended Fix", a.recommended_fix) +
        analysisSection("طريقة التحقق", "Verification", a.verification) +
        analysisSection("ملاحظة False Positive", "False Positive Note", a.false_positive_note) +
        analysisSection("حدود التحليل", "Limitations", a.limitations) +

        classificationHtml +

        "</div>"
    );
}


/* =========================================================
   Correlation Card
========================================================= */

function renderCorrelationCard(correlation) {
    const item =
        correlation &&
        typeof correlation === "object"
            ? correlation
            : {};

    return (
        '<article class="correlation-card">' +

        '<div style="display:flex;align-items:flex-start;justify-content:space-between;gap:10px;">' +

        "<strong>" +

        escapeHtml(
            safeText(
                item.title,
                "خطر مترابط"
            )
        ) +

        "</strong>" +

        severityBadge(
            item.severity
        ) +

        "</div>" +

        "<p>" +

        escapeHtml(
            safeText(
                item.explanation ||
                item.description,
                "تم اكتشاف علاقة بين عدة نتائج أمنية."
            )
        ) +

        "</p>" +

        "</article>"
    );
}


/* =========================================================
   File Name Preview
========================================================= */

function bindFileNamePreview(
    inputId,
    labelId
) {
    const input =
        byId(inputId);

    const label =
        byId(labelId);

    if (
        !input ||
        !label
    ) {
        return;
    }

    input.addEventListener(
        "change",
        function () {
            const file =
                input.files &&
                input.files[0]
                    ? input.files[0]
                    : null;

            label.textContent =
                file
                    ? file.name
                    : "لم يتم اختيار ملف";
        }
    );
}


/* =========================================================
   Scan Details
========================================================= */

async function openScanDetails(scanId) {
    const drawer =
        byId(
            "scanDetailsDrawer"
        );

    const content =
        byId(
            "scanDetailsContent"
        );

    const title =
        byId(
            "detailsDrawerTitle"
        );

    if (
        !drawer ||
        !content
    ) {
        return;
    }

    drawer.classList.add(
        "open"
    );
    drawer.setAttribute(
        "aria-hidden",
        "false"
    );

    document.body.style.overflow =
        "hidden";

    content.innerHTML =

        '<div class="scan-loading">' +

        '<div class="loader"></div>' +

        "<div>" +

        "<strong>" +
        "جاري تحميل تفاصيل الفحص..." +
        "</strong>" +

        "</div>" +

        "</div>";

    try {
        const payload =
            await apiRequest(
                API.scanDetails(
                    scanId
                )
            );

        const raw =
            payloadData(
                payload,
                {}
            ) || {};

        const result =
            normalizeScan(
                raw
            );

        result.findings =
            Array.isArray(
                raw.findings
            )
                ? raw.findings
                : result.findings;

        result.metadata =
            raw.metadata &&
            typeof raw.metadata === "object"
                ? raw.metadata
                : result.metadata;

        if (title) {
            title.textContent =
                "تفاصيل الفحص #" +
                safeText(
                    result.id,
                    scanId
                );
        }

        renderScanDetails(
            result
        );
    }
    catch (error) {
        content.innerHTML =

            '<div class="empty-panel">' +

            escapeHtml(
                error.message
            ) +

            "</div>";
    }
}


function closeScanDetails() {
    const drawer =
        byId(
            "scanDetailsDrawer"
        );

    if (drawer) {
        drawer.classList.remove(
            "open"
        );

        drawer.setAttribute(
            "aria-hidden",
            "true"
        );
    }

    document.body.style.overflow =
        "";
}


/* =========================================================
   Render Scan Details
========================================================= */

function renderScanDetails(result) {
    const content =
        byId(
            "scanDetailsContent"
        );

    if (!content) {
        return;
    }

    const findings =
        Array.isArray(
            result.findings
        )
            ? result.findings
            : [];

    const metadata =
        result.metadata &&
        typeof result.metadata === "object"
            ? result.metadata
            : {};

    const metadataHtml =
        Object.keys(
            metadata
        ).length
            ? (
                '<div class="result-section">' +

                "<h3>" +
                "معلومات الفحص" +
                "</h3>" +

                renderMetadata(
                    metadata
                ) +

                "</div>"
            )
            : "";

    const findingsHtml =
        findings.length
            ? (
                '<div class="findings-grid">' +

                findings
                    .slice(
                        0,
                        60
                    )
                    .map(
                        renderFindingCard
                    )
                    .join("") +

                "</div>"
            )
            : (
                '<div class="empty-panel">' +

                "لا توجد نتائج." +

                "</div>"
            );

    content.innerHTML =

        '<div class="details-overview-grid">' +


        '<div class="details-stat">' +

        "<span>" +
        "نوع الفحص" +
        "</span>" +

        "<strong>" +

        escapeHtml(
            scanTypeLabel(
                result.scan_type
            )
        ) +

        "</strong>" +

        "</div>" +


        '<div class="details-stat">' +

        "<span>" +
        "درجة الأمان" +
        "</span>" +

        "<strong>" +

        escapeHtml(
            clampScore(
                result.security_score
            )
        ) +

        "</strong>" +

        "</div>" +


        '<div class="details-stat">' +

        "<span>" +
        "النتائج" +
        "</span>" +
        "<strong>" +

        escapeHtml(
            formatNumber(
                findings.length
            )
        ) +

        "</strong>" +

        "</div>" +


        "</div>" +


        '<div class="result-section">' +

        "<h3>" +
        "الهدف" +
        "</h3>" +

        '<div class="ai-summary-card break-word">' +

        escapeHtml(
            safeText(
                result.target_name
            )
        ) +

        "</div>" +

        "</div>" +


        metadataHtml +


        '<div class="result-section">' +

        "<h3>" +
        "النتائج الأمنية" +
        "</h3>" +

        findingsHtml +

        "</div>";
}


/* =========================================================
   Metadata
========================================================= */

function metadataLabel(key) {
    const labels = {
        ecosystem:
            "النظام البيئي",

        packages_scanned:
            "الحزم المفحوصة",

        files_discovered:
            "الملفات المكتشفة",

        code_files_scanned:
            "ملفات الكود",

        dependency_files_scanned:
            "ملفات المكتبات",

        total_errors:
            "أخطاء الفحص",

        archive_type:
            "نوع الأرشيف",

        engine:
            "محرك الفحص",

        osv_status:
            "حالة OSV",

        path_traversal_protection:
            "حماية المسارات",

        temporary_cleanup:
            "تنظيف الملفات المؤقتة"
    };

    return labels[key] || key;
}


function renderMetadata(metadata) {
    const preferredKeys = [
        "ecosystem",
        "packages_scanned",
        "files_discovered",
        "code_files_scanned",
        "dependency_files_scanned",
        "total_errors",
        "archive_type",
        "engine",
        "osv_status",
        "path_traversal_protection",
        "temporary_cleanup"
    ];

    const rows =
        preferredKeys
            .filter(
                function (key) {
                    return (
                        metadata[key]
                        !== undefined
                    );
                }
            )
            .map(
                function (key) {
                    return {
                        key: key,
                        value:
                            metadata[key]
                    };
                }
            );

    if (!rows.length) {
        return (
            '<div class="empty-panel">' +

            "توجد بيانات إضافية محفوظة لكنها غير مناسبة للعرض المختصر." +

            "</div>"
        );
    }

    return (
        '<div class="details-overview-grid">' +

        rows
            .map(
                function (row) {
                    return (
                        '<div class="details-stat">' +

                        "<span>" +

                        escapeHtml(
                            metadataLabel(
                                row.key
                            )
                        ) +

                        "</span>" +

                        '<strong class="break-word">' +

                        escapeHtml(
                            safeText(
                                row.value
                            )
                        ) +

                        "</strong>" +

                        "</div>"
                    );
                }
            )
            .join("") +

        "</div>"
    );
}


/* =========================================================
   Vulnerabilities
========================================================= */

async function renderVulnerabilities() {
    const container =
        byId(
            "vulnerabilitiesContainer"
        );

    if (!container) {
        return;
    }

    const candidates =
        state.scans
            .filter(
                function (scan) {
                    return (
                        toNumber(
                            scan.total_findings,
                            0
                        ) > 0
                    );
                }
            )
            .slice(
                0,
                5
            );

    if (!candidates.length) {
        container.innerHTML =

            '<div class="empty-panel">' +

            "لا توجد نتائج أمنية محفوظة بعد." +

            "</div>";

        return;
    }

    container.innerHTML =

        '<div class="empty-panel">' +

        "جاري تحميل أحدث النتائج..." +

        "</div>";

    const collected = [];

    for (
        const scan
        of candidates
    ) {
        try {
            const payload =
                await apiRequest(
                    API.scanDetails(
                        scan.id
                    )
                );

            const data =
                payloadData(
                    payload,
                    {}
                ) || {};

            const findings =
                Array.isArray(
                    data.findings
                )
                    ? data.findings
                    : [];

            collected.push.apply(
                collected,
                findings.slice(
                    0,
                    15
                )
            );

            if (
                collected.length >= 30
            ) {
                break;
            }
        }
        catch (error) {
            continue;
        }
    }

    if (!collected.length) {
        container.innerHTML =

            '<div class="empty-panel">' +

            "لم يتم العثور على نتائج قابلة للعرض." +

            "</div>";

        return;
    }

    collected.sort(
        function (a, b) {
            return (
                severityRank(
                    b && b.severity
                ) -
                severityRank(
                    a && a.severity
                )
            );
        }
    );

    container.innerHTML =
        collected
            .slice(
                0,
                30
            )
            .map(
                renderFindingCard
            )
            .join("");
}


/* =========================================================
   AI State
========================================================= */

async function loadLatestScanForAi() {
    const latest =
        state.scans[0];

    if (
        !latest ||
        !latest.id
    ) {
        return;
    }

    try {
        const payload =
            await apiRequest(
                API.scanDetails(
                    latest.id
                )
            );

        const data =
            payloadData(
                payload,
                null
            );

        state.latestScanDetails =
            data;

        if (
            data &&
            data.ai_analysis &&
            typeof data.ai_analysis
            === "object"
        ) {
            state.latestAiAnalysis =
                data.ai_analysis;

            persistLatestAiAnalysis();
        }
    }
    catch (error) {
        state.latestScanDetails =
            null;
    }
}


function restoreLatestAiAnalysis() {
    try {
        const raw =
            sessionStorage.getItem(
                "cyberlens_latest_ai"
            );

        if (!raw) {
            return;
        }

        const parsed =
            JSON.parse(raw);

        if (
            parsed &&
            typeof parsed === "object"
        ) {
            state.latestAiAnalysis =
                parsed;
        }
    }
    catch (error) {
        sessionStorage.removeItem(
            "cyberlens_latest_ai"
        );
    }
}


function persistLatestAiAnalysis() {
    if (
        !state.latestAiAnalysis
    ) {
        return;
    }
    try {
        sessionStorage.setItem(
            "cyberlens_latest_ai",
            JSON.stringify(
                state.latestAiAnalysis
            )
        );
    }
    catch (error) {
        return;
    }
}


/* =========================================================
   AI Page
========================================================= */

function renderAiDetailedAnalysisCard(detail) {
    const item =
        detail && typeof detail === "object"
            ? detail
            : {};

    const severity =
        normalizeSeverity(item.severity);

    const targetId =
        safeText(item.finding_id, "");

    return (
        '<article class="finding-card severity-' +
        escapeHtml(severity) +
        '">' +

        '<div class="finding-card-head">' +

        "<h3>" +
        escapeHtml(
            safeText(item.title, "نتيجة أمنية")
        ) +
        "</h3>" +

        severityBadge(severity) +

        "</div>" +

        (
            targetId
                ? (
                    '<button type="button" class="btn-expand" ' +
                    'data-jump-to-finding="' + escapeHtml(targetId) + '">' +
                    "عرض البطاقة الأصلية ↗" +
                    "</button>"
                )
                : ""
        ) +

        renderFindingDeepAnalysis(item, "ai-page-" + escapeHtml(targetId || Math.random())).replace(
            " hidden>",
            ">"
        ) +

        "</article>"
    );
}


function renderAiPage() {
    const analysis =
        byId(
            "latestAiAnalysis"
        );

    const correlationsBox =
        byId(
            "aiCorrelationsContainer"
        );

    const provider =
        byId(
            "aiProviderPill"
        );

    const ai =
        state.latestAiAnalysis;

    if (provider) {
        provider.textContent =
            (
                ai &&
                ai.provider
            ) ||
            "CyberLens Local Analyzer";
    }

    if (!ai) {
        if (analysis) {
            analysis.innerHTML =

                '<div class="empty-panel">' +

                "نفّذ فحصًا جديدًا لعرض التحليل الذكي هنا." +

                "</div>";
        }

        if (correlationsBox) {
            correlationsBox.innerHTML =

                '<div class="empty-panel">' +

                "لا توجد بيانات Correlation بعد." +

                "</div>";
        }

        return;
    }

    if (analysis) {
        const priorities =
            Array.isArray(
                ai.priority_order
            )
                ? ai.priority_order
                : [];

        let prioritiesHtml =
            "";

        if (priorities.length) {
            prioritiesHtml =

                '<div style="margin-top:14px;display:grid;gap:9px;">' +

                priorities
                    .slice(
                        0,
                        10
                    )
                    .map(
                        function (item) {
                            const targetId =
                                safeText(
                                    item.finding_id,
                                    ""
                                );

                            return (
                                '<div class="correlation-card priority-jump" ' +
                                (
                                    targetId
                                        ? 'data-jump-to-finding="' + escapeHtml(targetId) + '" role="button" tabindex="0"'
                                        : ""
                                ) +
                                '>' +

                                '<div style="display:flex;justify-content:space-between;gap:10px;">' +

                                "<strong>#" +

                                escapeHtml(
                                    item.priority ||
                                    ""
                                ) +

                                " " +

                                escapeHtml(
                                    safeText(
                                        item.title,
                                        "أولوية أمنية"
                                    )
                                ) +

                                "</strong>" +

                                severityBadge(
                                    item.severity
                                ) +

                                "</div>" +

                                "<p>" +

                                escapeHtml(
                                    safeText(
                                        item.reason,
                                        "تحتاج النتيجة إلى مراجعة."
                                    )
                                ) +

                                "</p>" +

                                (
                                    targetId
                                        ? '<span class="jump-hint">اذهب إلى الثغرة ↗</span>'
                                        : ""
                                ) +

                                "</div>"
                            );
                        }
                    )
                    .join("") +

                "</div>";
        }

        const detailedAnalysisList =
            Array.isArray(ai.detailed_analysis)
                ? ai.detailed_analysis
                : [];

        const detailedAnalysisHtml =
            detailedAnalysisList.length
                ? (
                    '<h3 class="ai-section-title">' +
                    'تحليل مفصّل لكل ثغرة ' +
                    '<span class="analysis-label-en">(Per-Finding Detailed Analysis)</span>' +
                    "</h3>" +

                    '<div style="display:grid;gap:14px;margin-top:10px;">' +
                    detailedAnalysisList
                        .map(renderAiDetailedAnalysisCard)
                        .join("") +
                    "</div>"
                )
                : "";

        analysis.innerHTML =

            '<div class="ai-summary-card">' +

            escapeHtml(
                safeText(
                    ai.summary,
                    "تم إنشاء التحليل الأمني."
                )
            ) +

            "</div>" +

            prioritiesHtml +

            detailedAnalysisHtml;
    }

    if (correlationsBox) {
        const correlations =
            Array.isArray(
                ai.correlations
            )
                ? ai.correlations
                : [];
                correlationsBox.innerHTML =
            correlations.length
                ? correlations
                    .map(
                        renderCorrelationCard
                    )
                    .join("")
                : (
                    '<div class="empty-panel">' +

                    "لم يتم اكتشاف مخاطر مترابطة." +

                    "</div>"
                );
    }
}


/* =========================================================
   Global Click Events
========================================================= */

function bindGlobalClicks() {
    document.addEventListener(
        "click",
        function (event) {
            const jumpButton =
                event.target.closest(
                    "[data-jump-to-finding]"
                );

            if (jumpButton) {
                const targetId =
                    jumpButton.dataset.jumpToFinding;

                openPage("vulnerabilities");

                window.setTimeout(
                    function () {
                        const target =
                            byId("finding-" + targetId);

                        if (target) {
                            target.scrollIntoView(
                                { behavior: "smooth", block: "center" }
                            );

                            target.classList.add("finding-highlight");

                            window.setTimeout(
                                function () {
                                    target.classList.remove("finding-highlight");
                                },
                                1800
                            );
                        }
                    },
                    150
                );

                return;
            }

            const analysisToggle =
                event.target.closest(
                    "[data-toggle-analysis]"
                );

            if (analysisToggle) {
                const key =
                    analysisToggle.dataset.toggleAnalysis;

                const panel =
                    document.querySelector(
                        '[data-analysis-panel="' +
                        key +
                        '"]'
                    );

                if (panel) {
                    const isHidden =
                        panel.hasAttribute("hidden");

                    if (isHidden) {
                        panel.removeAttribute("hidden");
                        analysisToggle.setAttribute("aria-expanded", "true");
                        analysisToggle.textContent =
                            "إخفاء التحليل الكامل (AI) ▴";
                    }
                    else {
                        panel.setAttribute("hidden", "");
                        analysisToggle.setAttribute("aria-expanded", "false");
                        analysisToggle.textContent =
                            "عرض التحليل الكامل (AI) ▾";
                    }
                }

                return;
            }

            const pageButton =
                event.target.closest(
                    "[data-page]"
                );

            if (pageButton) {
                openPage(
                    pageButton.dataset.page
                );

                return;
            }

            const openPageButton =
                event.target.closest(
                    "[data-open-page]"
                );

            if (openPageButton) {
                openPage(
                    openPageButton.dataset.openPage
                );

                return;
            }

            const scanTabButton =
                event.target.closest(
                    "[data-scan-tab]"
                );

            if (scanTabButton) {
                openScanTab(
                    scanTabButton.dataset.scanTab
                );

                return;
            }

            const openScanTabButton =
                event.target.closest(
                    "[data-open-scan-tab]"
                );

            if (openScanTabButton) {
                openPage(
                    "scanner"
                );

                openScanTab(
                    openScanTabButton.dataset.openScanTab
                );

                return;
            }

            const detailsButton =
                event.target.closest(
                    "[data-scan-details-id]"
                );

            if (detailsButton) {
                openScanDetails(
                    detailsButton.dataset.scanDetailsId
                );
            }
        }
    );
}


/* =========================================================
   Forms
========================================================= */

function bindForms() {
    const urlForm =
        byId(
            "urlScanForm"
        );

    const codeForm =
        byId(
            "codeScanForm"
        );

    const depForm =
        byId(
            "dependencyScanForm"
        );

    const projectForm =
        byId(
            "projectScanForm"
        );

    if (urlForm) {
        urlForm.addEventListener(
            "submit",
            submitUrlScan
        );
    }

    if (codeForm) {
        codeForm.addEventListener(
            "submit",
            function (event) {
                event.preventDefault();

                submitFileScan({
                    inputId:
                        "codeFileInput",

                    endpoint:
                        API.scanCode,

                    emptyMessage:
                        "اختر ملف كود أولًا."
                });
            }
        );
    }

    if (depForm) {
        depForm.addEventListener(
            "submit",
            function (event) {
                event.preventDefault();

                submitFileScan({
                    inputId:
                        "dependencyFileInput",

                    endpoint:
                        API.scanDependencies,

                    emptyMessage:
                        "اختر ملف اعتماديات أولًا."
                });
            }
        );
    }

    if (projectForm) {
        projectForm.addEventListener(
            "submit",
            function (event) {
                event.preventDefault();

                submitFileScan({
                    inputId:
                        "projectFileInput",

                    endpoint:
                        API.scanProject,
                        emptyMessage:
                        "اختر مشروع ZIP أولًا."
                });
            }
        );
    }
}


/* =========================================================
   History Events
========================================================= */

function bindHistoryFilters() {
    const search =
        byId(
            "historySearchInput"
        );

    const type =
        byId(
            "historyTypeFilter"
        );

    if (search) {
        search.addEventListener(
            "input",
            applyHistoryFilters
        );
    }

    if (type) {
        type.addEventListener(
            "change",
            applyHistoryFilters
        );
    }
}


/* =========================================================
   Header Events
========================================================= */

function bindHeaderEvents() {
    const refresh =
        byId(
            "refreshDashboardButton"
        );

    const mobileMenu =
        byId(
            "mobileMenuButton"
        );

    const overlay =
        byId(
            "mobileOverlay"
        );

    if (refresh) {
        refresh.addEventListener(
            "click",
            async function () {
                await Promise.all([
                    loadDashboard(true),
                    loadScans(),
                    checkHealth()
                ]);
            }
        );
    }

    if (mobileMenu) {
        mobileMenu.addEventListener(
            "click",
            openMobileSidebar
        );
    }

    if (overlay) {
        overlay.addEventListener(
            "click",
            closeMobileSidebar
        );
    }
}


/* =========================================================
   Drawer Events
========================================================= */

function bindDrawerEvents() {
    const closeButton =
        byId(
            "closeDetailsDrawer"
        );

    const drawer =
        byId(
            "scanDetailsDrawer"
        );

    if (closeButton) {
        closeButton.addEventListener(
            "click",
            closeScanDetails
        );
    }

    if (drawer) {
        drawer.addEventListener(
            "click",
            function (event) {
                if (
                    event.target.id ===
                    "scanDetailsDrawer"
                ) {
                    closeScanDetails();
                }
            }
        );
    }

    document.addEventListener(
        "keydown",
        function (event) {
            if (
                event.key ===
                "Escape"
            ) {
                closeScanDetails();

                closeMobileSidebar();
            }
        }
    );
}


/* =========================================================
   File Preview Events
========================================================= */

function bindFilePreviews() {
    bindFileNamePreview(
        "codeFileInput",
        "codeFileName"
    );

    bindFileNamePreview(
        "dependencyFileInput",
        "dependencyFileName"
    );

    bindFileNamePreview(
        "projectFileInput",
        "projectFileName"
    );
}


/* =========================================================
   Bootstrap
========================================================= */

async function bootstrap() {
    renderCurrentDate();

    restoreLatestAiAnalysis();

    bindGlobalClicks();

    bindForms();

    bindHistoryFilters();

    bindHeaderEvents();

    bindDrawerEvents();

    bindFilePreviews();

    openPage(
        "dashboard"
    );

    openScanTab(
        "url"
    );

    await Promise.all([
        checkHealth(),
        loadDashboard(false),
        loadScans()
    ]);

    renderAiPage();
}


/* =========================================================
   Start
========================================================= */
document.addEventListener(
    "DOMContentLoaded",
    function () {
        bootstrap().catch(
            function (error) {
                console.error(
                    "CyberLens bootstrap error:",
                    error
                );

                showAlert(
                    "حدث خطأ أثناء تشغيل واجهة CyberLens.",
                    "error",
                    0
                );
            }
        );
    }
);


(function () {
    if (window.CyberLensAuthUI) {
        return;
    }

    window.CyberLensAuthUI = true;

    function apiPost(url, data) {
        return fetch(url, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            credentials: "same-origin",
            body: JSON.stringify(data || {})
        }).then(function (response) {
            return response.json().then(function (payload) {
                return {
                    status: response.status,
                    payload: payload
                };
            });
        });
    }

    function showAuthScreen() {
        if (document.getElementById("cyberlens-auth-screen")) {
            return;
        }

        var screen = document.createElement("div");
        screen.id = "cyberlens-auth-screen";
        screen.dir = "rtl";

        screen.style.position = "fixed";
        screen.style.inset = "0";
        screen.style.zIndex = "99999";
        screen.style.direction = "rtl";
        screen.style.background = "linear-gradient(135deg,#020617,#0f172a)";
        screen.style.display = "flex";
        screen.style.alignItems = "center";
        screen.style.justifyContent = "center";
        screen.style.fontFamily = "Arial, sans-serif";

        screen.innerHTML =
            '<div style="width:380px;max-width:92%;background:#ffffff;border-radius:24px;padding:28px;box-shadow:0 25px 80px rgba(0,0,0,.35);">' +
            '<h2 style="margin:0 0 8px;color:#0f172a;text-align:center;">CyberLens</h2>' +
            '<p style="margin:0 0 20px;color:#64748b;text-align:center;">سجّل الدخول للوصول إلى منصة الفحص</p>' +
            '<label style="display:block;margin-bottom:6px;color:#334155;">اسم المستخدم</label>' +
            '<input id="auth-username" style="width:100%;box-sizing:border-box;padding:12px;border:1px solid #cbd5e1;border-radius:12px;margin-bottom:14px;" autocomplete="username">' +
            '<label style="display:block;margin-bottom:6px;color:#334155;">كلمة المرور</label>' +
            '<input id="auth-password" type="password" style="width:100%;box-sizing:border-box;padding:12px;border:1px solid #cbd5e1;border-radius:12px;margin-bottom:16px;" autocomplete="current-password">' +
            '<button id="auth-login" style="width:100%;padding:12px;border:0;border-radius:12px;background:#2563eb;color:white;font-weight:bold;cursor:pointer;margin-bottom:10px;">تسجيل الدخول</button>' +
            '<button id="auth-register" style="width:100%;padding:12px;border:1px solid #2563eb;border-radius:12px;background:white;color:#2563eb;font-weight:bold;cursor:pointer;">إنشاء حساب جديد</button>' +
            '<p id="auth-message" style="min-height:22px;margin:14px 0 0;text-align:center;color:#dc2626;"></p>' +
            '</div>';

        document.body.appendChild(screen);

        function values() {
            return {
                username: document.getElementById("auth-username").value.trim(),
                password: document.getElementById("auth-password").value
            };
        }

        function setMessage(message) {
            document.getElementById("auth-message").textContent = message || "";
        }

        document.getElementById("auth-login").addEventListener("click", function () {
            setMessage("");

            apiPost("/api/auth/login", values()).then(function (result) {
                if (result.status === 200 && result.payload.success) {
                    location.reload();
                    return;
                }

                setMessage(result.payload.message || "تعذّر إتمام العملية");
            }).catch(function () {
                setMessage("تعذّر الاتصال بالخادم");
            });
        });

        var registerBtn = document.getElementById("auth-register");
        if (registerBtn) { registerBtn.style.display = "none"; }

        /* disabled public register */
        if (false) document.getElementById("auth-register").addEventListener("click", function () {
            setMessage("");apiPost("/api/auth/register", values()).then(function (result) {
                if (result.status === 200 && result.payload.success) {
                    location.reload();
                    return;
                }

                setMessage(result.payload.message || "تعذّر إتمام العملية");
            }).catch(function () {
                setMessage("تعذّر الاتصال بالخادم");
            });
        });
    }

    function addLogoutButton(user) {
        if (document.getElementById("cyberlens-logout-button")) {
            return;
        }

        var button = document.createElement("button");
        button.id = "cyberlens-logout-button";
        button.textContent = "خروج — " + (user && user.username ? user.username : "");
        button.style.position = "fixed";
        button.style.left = "18px";
        button.style.bottom = "18px";
        button.style.zIndex = "9999";
        button.style.padding = "10px 14px";
        button.style.border = "0";
        button.style.borderRadius = "12px";
        button.style.background = "#ef4444";
        button.style.color = "white";
        button.style.fontWeight = "bold";
        button.style.cursor = "pointer";

        button.addEventListener("click", function () {
            apiPost("/api/auth/logout", {}).then(function () {
                location.reload();
            });
        });

        document.body.appendChild(button);
    }

    function checkAuth() {
        fetch("/api/auth/me", {
            credentials: "same-origin"
        }).then(function (response) {
            return response.json();
        }).then(function (payload) {
            var data = payload.data || {};

            if (data.authenticated) {
                addLogoutButton(data.user);
            } else {
                showAuthScreen();
            }
        }).catch(function () {
            showAuthScreen();
        });
    }

    document.addEventListener("DOMContentLoaded", checkAuth);
})();


(function () {
    if (window.CyberLensAuthTextFix) {
        return;
    }

    window.CyberLensAuthTextFix = true;

    function fixAuthText() {
        var screen = document.getElementById("cyberlens-auth-screen");

        if (!screen) {
            return;
        }

        var card = screen.firstElementChild;

        if (!card) {
            return;
        }

        var paragraph = card.querySelector("p");
        var labels = card.querySelectorAll("label");
        var login = document.getElementById("auth-login");
        var register = document.getElementById("auth-register");

        if (paragraph) {
            paragraph.textContent = "\u0627\u062f\u062e\u0644 \u0628\u0627\u0644\u062d\u0633\u0627\u0628 \u0627\u0644\u0630\u064a \u0623\u0639\u0637\u0627\u0643 \u0625\u064a\u0627\u0647 \u0627\u0644\u0645\u062f\u064a\u0631";
        }

        if (labels[0]) {
            labels[0].textContent = "\u0627\u0633\u0645 \u0627\u0644\u0645\u0633\u062a\u062e\u062f\u0645";
        }

        if (labels[1]) {
            labels[1].textContent = "\u0643\u0644\u0645\u0629 \u0627\u0644\u0645\u0631\u0648\u0631";
        }

        if (login) {
            login.textContent = "\u062f\u062e\u0648\u0644";
        }

        if (register) {
            register.textContent = "\u0625\u0646\u0634\u0627\u0621 \u062d\u0633\u0627\u0628";
        }
    }

    document.addEventListener("DOMContentLoaded", function () {
        fixAuthText();

        var tries = 0;

        var timer = setInterval(function () {
            fixAuthText();
            tries += 1;

            if (tries > 20) {
                clearInterval(timer);
            }
        }, 200);
    });
})();


(function () {
    if (window.CyberLensLogoutTextFix) {
        return;
    }

    window.CyberLensLogoutTextFix = true;

    function fixLogoutButton() {
        var btn = document.getElementById("cyberlens-logout-button");

        if (!btn) {
            return;
        }

        var text = btn.textContent || "";
        var username = text.split("-")[0].trim();

        if (!username) {
            username = "user";
        }

        btn.textContent = "\u062e\u0631\u0648\u062c - " + username;
        btn.dir = "rtl";
        btn.style.left = "18px";
        btn.style.bottom = "18px";
        btn.style.fontSize = "13px";
        btn.style.padding = "9px 12px";
        btn.style.borderRadius = "12px";
        btn.style.boxShadow = "0 10px 25px rgba(0,0,0,.25)";
    }

    document.addEventListener("DOMContentLoaded", function () {
        fixLogoutButton();

        var tries = 0;

        var timer = setInterval(function () {
            fixLogoutButton();
            tries += 1;

            if (tries > 20) {
                clearInterval(timer);
            }
        }, 200);
    });
})();


(function () {
    if (window.CyberLensLogoutFinalFix) {
        return;
    }

    window.CyberLensLogoutFinalFix = true;

    function finalFixLogoutButton() {
        var btn = document.getElementById("cyberlens-logout-button");

        if (!btn) {
            return;
        }

        btn.textContent = "\u062e\u0631\u0648\u062c";
        btn.dir = "rtl";
        btn.style.fontSize = "14px";
        btn.style.padding = "10px 16px";
        btn.style.minWidth = "70px";
        btn.style.textAlign = "center";
    }

    document.addEventListener("DOMContentLoaded", function () {
        finalFixLogoutButton();

        var tries = 0;

        var timer = setInterval(function () {
            finalFixLogoutButton();
            tries += 1;

            if (tries > 30) {
                clearInterval(timer);
            }
        }, 200);
    });
})();
