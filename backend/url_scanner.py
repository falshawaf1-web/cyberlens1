from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse


# =========================================================
# إعدادات عامة
# =========================================================

ALLOWED_SCHEMES = {
    "http",
    "https",
}

STANDARD_PORTS = {
    80,
    443,
}

SUSPICIOUS_KEYWORDS = {
    "login",
    "signin",
    "sign-in",
    "verify",
    "verification",
    "account",
    "secure",
    "security",
    "update",
    "confirm",
    "password",
    "passwd",
    "credential",
    "wallet",
    "bank",
    "payment",
    "invoice",
    "recover",
    "recovery",
    "unlock",
    "suspend",
    "suspended",
    "urgent",
    "gift",
    "bonus",
    "free",
    "crypto",
}

EXECUTABLE_EXTENSIONS = {
    ".exe",
    ".scr",
    ".bat",
    ".cmd",
    ".com",
    ".msi",
    ".ps1",
    ".vbs",
    ".jar",
    ".apk",
}

REDIRECT_PARAMETERS = {
    "url",
    "uri",
    "redirect",
    "redirect_url",
    "redirect_uri",
    "return",
    "return_url",
    "returnurl",
    "next",
    "continue",
    "destination",
    "dest",
    "target",
    "goto",
}


# =========================================================
# أداة لإنشاء Finding
# =========================================================

def make_finding(
    finding_id: str,
    title: str,
    severity: str,
    description: str,
    recommendation: str,
    confidence: str = "medium",
    metadata: dict[str, Any] | None = None,
    evidence: str = "",
    impact: str = "",
    why_detected: str = "",
    remediation_steps: list[str] | None = None,
    secure_example: str = "",
    verification: str = "",
    owasp: str = "",
    cwe: str = "",
) -> dict[str, Any]:
    """
    يبني قاموس finding موحّد الشكل لبقية المشروع.
    """

    return {
        "id": finding_id,
        "title": title,
        "severity": severity,
        "description": description,
        "recommendation": recommendation,
        "source": "CyberLens URL Analysis",
        "confidence": confidence,
        "evidence": evidence,
        "impact": impact,
        "why_detected": why_detected,
        "remediation_steps": remediation_steps or [],
        "secure_example": secure_example,
        "verification": verification,
        "owasp": owasp,
        "cwe": cwe,
        "metadata": metadata or {},
    }

def normalize_url(
    raw_url: str,
) -> tuple[str, bool]:
    """
    تنظيف الرابط.

    يعيد:
        normalized_url
        scheme_was_missing
    """

    value = str(
        raw_url or ""
    ).strip()

    if not value:
        raise ValueError(
            "الرابط فارغ."
        )

    if len(value) > 4096:
        raise ValueError(
            "الرابط طويل جدًا ولا يمكن تحليله بأمان."
        )

    had_missing_scheme = False

    if "://" not in value:
        value = (
            "https://"
            + value
        )

        had_missing_scheme = True

    return (
        value,
        had_missing_scheme,
    )


# =========================================================
# فحص هل Host عبارة عن IP
# =========================================================

def parse_ip_address(
    hostname: str,
) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """
    محاولة تحويل Host إلى IP.
    """

    try:
        return ipaddress.ip_address(
            hostname
        )

    except ValueError:
        return None


# =========================================================
# حساب عدد Subdomains
# =========================================================

def estimate_subdomain_count(
    hostname: str,
) -> int:
    """
    تقدير عدد النطاقات الفرعية.

    مثال:
        a.b.example.com
    يعتبر تقريبًا:
        2 subdomains
    """

    if not hostname:
        return 0

    if parse_ip_address(hostname):
        return 0

    labels = [
        part
        for part in hostname.split(".")
        if part
    ]

    if len(labels) <= 2:
        return 0

    return max(
        0,
        len(labels) - 2,
    )


# =========================================================
# البحث عن كلمات حساسة
# =========================================================

def find_suspicious_keywords(
    url: str,
) -> list[str]:
    """
    البحث عن كلمات قد تظهر بكثرة
    في روابط التصيد والهندسة الاجتماعية.

    وجود الكلمة وحده لا يعني أن الرابط خبيث.
    """
    lowered = unquote(
        url
    ).lower()

    found = []

    for keyword in sorted(
        SUSPICIOUS_KEYWORDS
    ):
        if keyword in lowered:
            found.append(keyword)

    return found


# =========================================================
# اكتشاف امتداد تنزيل تنفيذي
# =========================================================

def detect_executable_extension(
    path: str,
) -> str | None:
    """
    اكتشاف امتداد ملف تنفيذي أو Script
    داخل مسار الرابط.
    """

    suffix = Path(
        path.lower()
    ).suffix

    if suffix in EXECUTABLE_EXTENSIONS:
        return suffix

    return None


# =========================================================
# فحص Redirect Parameters
# =========================================================

def detect_nested_redirects(
    query: str,
) -> list[dict[str, str]]:
    """
    البحث عن معاملات Redirect
    تحتوي رابطًا آخر بداخلها.
    """

    results: list[
        dict[str, str]
    ] = []

    parameters = parse_qs(
        query,
        keep_blank_values=True,
    )

    for key, values in parameters.items():

        clean_key = key.lower().strip()

        if clean_key not in REDIRECT_PARAMETERS:
            continue

        for value in values:

            decoded = unquote(
                value
            ).strip()

            lowered = decoded.lower()

            if (
                lowered.startswith(
                    "http://"
                )
                or lowered.startswith(
                    "https://"
                )
            ):
                results.append(
                    {
                        "parameter": key,
                        "target": decoded[:250],
                    }
                )

    return results


# =========================================================
# إزالة النتائج المكررة
# =========================================================

def deduplicate_findings(
    findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    منع تكرار نفس Finding ID.
    """

    unique: list[
        dict[str, Any]
    ] = []

    seen_ids: set[str] = set()

    for finding in findings:

        finding_id = str(
            finding.get("id", "")
        )

        if finding_id in seen_ids:
            continue

        seen_ids.add(
            finding_id
        )

        unique.append(
            finding
        )

    return unique


# =========================================================
# ترتيب النتائج
# =========================================================

def sort_findings(
    findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    ترتيب:
    Critical
    High
    Medium
    Low
    Info
    """

    ranks = {
        "critical": 5,
        "high": 4,
        "medium": 3,
        "low": 2,
        "info": 1,
    }

    return sorted(
        findings,
        key=lambda item: -ranks.get(
            str(
                item.get(
                    "severity",
                    "low",
                )
            ).lower(),
            0,
        ),
    )


# =========================================================
# المحرك الرئيسي
# =========================================================

def _scan_url_static(
    raw_url: str,
) -> dict[str, Any]:
    """
    تحليل URL محليًا.

    مهم:
    هذه الدالة لا تزور الرابط
    ولا تنفذ HTTP Request للهدف.
    """

    normalized_url, missing_scheme = normalize_url(
        raw_url
    )

    parsed = urlparse(
        normalized_url
    )

    scheme = (
        parsed.scheme
        or ""
    ).lower()

    if scheme not in ALLOWED_SCHEMES:
        raise ValueError(
            "يدعم CyberLens حاليًا روابط HTTP وHTTPS فقط."
        )

    hostname = (
        parsed.hostname
        or ""
    ).strip().lower()

    if not hostname:
        raise ValueError(
            "تعذر استخراج اسم النطاق من الرابط."
        )

    findings: list[
        dict[str, Any]
    ] = []

    risk_indicators: list[str] = []
    # =====================================================
    # 1. Scheme كان مفقودًا
    # =====================================================

    if missing_scheme:
        risk_indicators.append(
            "missing_scheme"
        )

        findings.append(
            make_finding(
                finding_id="CL-URL-001",
                title="لم يتم تحديد بروتوكول الرابط",
                severity="info",
                description=(
                    "تم إدخال الرابط بدون HTTP أو HTTPS، "
                    "وقام CyberLens بإضافة HTTPS لأغراض التحليل."
                ),
                recommendation=(
                    "تحقق من الرابط الأصلي وتأكد من البروتوكول "
                    "المستخدم فعليًا قبل فتحه."
                ),
                confidence="high",
            )
        )

    # =====================================================
    # 2. HTTP بدون TLS
    # =====================================================

    if scheme == "http":
        risk_indicators.append(
            "plain_http"
        )

        findings.append(
            make_finding(
                finding_id="CL-URL-002",
                title="الرابط يستخدم HTTP غير المشفر",
                severity="medium",
                description=(
                    "الاتصال عبر HTTP لا يوفر حماية TLS "
                    "للبيانات أثناء النقل."
                ),
                recommendation=(
                    "استخدم HTTPS بشهادة صحيحة، خصوصًا "
                    "للصفحات التي تتعامل مع تسجيل الدخول "
                    "أو البيانات الحساسة."
                ),
                confidence="high",
            )
        )

    # =====================================================
    # 3. وجود User Info أو @
    # =====================================================

    if parsed.username is not None or "@" in parsed.netloc:
        risk_indicators.append(
            "userinfo_at_symbol"
        )

        findings.append(
            make_finding(
                finding_id="CL-URL-003",
                title="وجود علامة @ أو User Info داخل الرابط",
                severity="high",
                description=(
                    "قد تستخدم بعض الروابط علامة @ لإخفاء "
                    "الوجهة الحقيقية عن المستخدم."
                ),
                recommendation=(
                    "راجع اسم النطاق الفعلي بعناية ولا تعتمد "
                    "على النص الذي يسبق علامة @."
                ),
                confidence="high",
            )
        )

    # =====================================================
    # 4. Host عبارة عن IP
    # =====================================================

    ip_object = parse_ip_address(
        hostname
    )

    if ip_object is not None:
        risk_indicators.append(
            "ip_literal_host"
        )

        findings.append(
            make_finding(
                finding_id="CL-URL-004",
                title="استخدام عنوان IP بدل اسم نطاق",
                severity="high",
                description=(
                    "الرابط يستخدم عنوان IP مباشرة بدل اسم نطاق. "
                    "هذا قد يكون طبيعيًا في بعض البيئات، "
                    "لكنه مؤشر يستحق التحقق."
                ),
                recommendation=(
                    "تحقق من ملكية عنوان IP والغرض من الخدمة "
                    "قبل إدخال أي بيانات حساسة."
                ),
                confidence="medium",
                metadata={
                    "ip": str(ip_object),
                },
            )
        )

        if (
            ip_object.is_private
            or ip_object.is_loopback
            or ip_object.is_link_local
        ):
            risk_indicators.append(
                "private_or_local_ip"
            )

            findings.append(
                make_finding(
                    finding_id="CL-URL-005",
                    title="الرابط يشير إلى عنوان محلي أو خاص",
                    severity="low",
                    description=(
                        "تم اكتشاف عنوان IP داخلي أو Loopback "
                        "أو Link-Local."
                    ),
                    recommendation=(
                        "تحقق أن الرابط مقصود للاستخدام داخل "
                        "الشبكة المحلية وليس رابطًا عامًا."
                    ),
                    confidence="high",
                )
            )

    # =====================================================
    # 5. Punycode
    # =====================================================

    if "xn--" in hostname:
        risk_indicators.append(
            "punycode_domain"
        )

        findings.append(
            make_finding(
                finding_id="CL-URL-006",
                title="اسم نطاق يستخدم Punycode",
                severity="medium",
                description=(
                    "تم اكتشاف xn-- داخل اسم النطاق. "
                    "قد يكون الاستخدام شرعيًا، لكنه يستحق "
                    "مراجعة بسبب احتمال تشابه بصري في أسماء النطاقات."
                ),
                recommendation=(
                    "تحقق من النطاق الحقيقي والحروف المستخدمة "
                    "قبل تسجيل الدخول أو إدخال بيانات حساسة."
                ),
                confidence="high",
            )
        )

    # =====================================================
    # 6. طول الرابط
    # =====================================================

    url_length = len(
        normalized_url
    )

    if url_length >= 200:
        risk_indicators.append(
            "very_long_url"
        )

        findings.append(
            make_finding(
                finding_id="CL-URL-007",
                title="رابط طويل بشكل غير معتاد",
                severity="medium",
                description=(
                    f"طول الرابط الحالي هو {url_length} حرفًا. "
                    "الروابط الطويلة قد تخفي معاملات أو وجهات معقدة."
                ),
                recommendation=(
                    "راجع النطاق والمسار والمعاملات قبل فتح الرابط."
                ),
                confidence="medium",
                metadata={
                    "url_length": url_length,
                },
            )
        )

    # =====================================================
    # 7. Subdomains كثيرة
    # =====================================================

    subdomain_count = estimate_subdomain_count(
        hostname
    )

    if subdomain_count >= 3:
        risk_indicators.append(
            "many_subdomains"
        )

        findings.append(
            make_finding(
                finding_id="CL-URL-008",
                title="عدد كبير من النطاقات الفرعية",
                severity="medium",
                description=(
                    f"تم تقدير {subdomain_count} نطاقات فرعية. "
                    "قد تستخدم بعض الروابط أسماء طويلة "
                    "لإرباك المستخدم حول النطاق الحقيقي."
                ),
                recommendation=(
                    "حدد النطاق الأساسي الفعلي وتحقق منه "
                    "قبل الوثوق بالرابط."
                ),
                confidence="medium",
                metadata={
                    "subdomain_count": subdomain_count,
                },
            )
        )

    # =====================================================
    # 8. Port غير اعتيادي
    # =====================================================

    try:
        port = parsed.port

    except ValueError as exc:
        raise ValueError(
            "رقم المنفذ داخل الرابط غير صالح."
        ) from exc

    if (
        port is not None
        and port not in STANDARD_PORTS
    ):
        risk_indicators.append(
            "non_standard_port"
        )
        findings.append(
            make_finding(
                finding_id="CL-URL-009",
                title="استخدام منفذ غير اعتيادي",
                severity="medium",
                description=(
                    f"الرابط يستخدم المنفذ {port} بدل "
                    "المنافذ الشائعة لخدمات الويب."
                ),
                recommendation=(
                    "تحقق من الخدمة التي تعمل على هذا المنفذ "
                    "ومن شرعية الجهة المشغلة."
                ),
                confidence="medium",
                metadata={
                    "port": port,
                },
            )
        )

    # =====================================================
    # 9. كلمات حساسة كثيرة
    # =====================================================

    suspicious_keywords = find_suspicious_keywords(
        normalized_url
    )

    if len(suspicious_keywords) >= 3:
        risk_indicators.append(
            "suspicious_keyword_cluster"
        )

        findings.append(
            make_finding(
                finding_id="CL-URL-010",
                title="تجمع كلمات حساسة داخل الرابط",
                severity="medium",
                description=(
                    "تم اكتشاف مجموعة كلمات مرتبطة "
                    "بالتسجيل أو التحقق أو الحسابات الحساسة."
                ),
                recommendation=(
                    "لا تدخل بيانات اعتماد قبل التحقق "
                    "من اسم النطاق والجهة المالكة للرابط."
                ),
                confidence="medium",
                metadata={
                    "keywords": suspicious_keywords[:15],
                },
            )
        )

    # =====================================================
    # 10. كثرة Percent Encoding
    # =====================================================

    encoded_sequences = len(
        re.findall(
            r"%[0-9A-Fa-f]{2}",
            normalized_url,
        )
    )

    if encoded_sequences >= 5:
        risk_indicators.append(
            "heavy_percent_encoding"
        )

        findings.append(
            make_finding(
                finding_id="CL-URL-011",
                title="استخدام كثيف للترميز داخل الرابط",
                severity="low",
                description=(
                    f"تم اكتشاف {encoded_sequences} مقاطع "
                    "Percent-Encoding داخل الرابط."
                ),
                recommendation=(
                    "قم بفك ترميز الرابط ومراجعة مكوناته "
                    "قبل الوثوق به."
                ),
                confidence="medium",
                metadata={
                    "encoded_sequences": encoded_sequences,
                },
            )
        )

    # =====================================================
    # 11. شرطات كثيرة في Host
    # =====================================================

    hyphen_count = hostname.count(
        "-"
    )

    if hyphen_count >= 4:
        risk_indicators.append(
            "many_hyphens"
        )

        findings.append(
            make_finding(
                finding_id="CL-URL-012",
                title="عدد كبير من الشرطات في اسم النطاق",
                severity="low",
                description=(
                    f"تم اكتشاف {hyphen_count} شرطات "
                    "داخل اسم النطاق."
                ),
                recommendation=(
                    "راجع اسم النطاق بعناية وتأكد من أنه "
                    "يتبع الجهة المقصودة فعلًا."
                ),
                confidence="low",
                metadata={
                    "hyphen_count": hyphen_count,
                },
            )
        )

    # =====================================================
    # 12. تنزيل ملف تنفيذي
    # =====================================================

    executable_extension = detect_executable_extension(
        parsed.path
    )

    if executable_extension:
        risk_indicators.append(
            "executable_download"
        )
        findings.append(
            make_finding(
                finding_id="CL-URL-013",
                title="الرابط يشير إلى ملف قابل للتنفيذ",
                severity="high",
                description=(
                    f"مسار الرابط ينتهي بالامتداد "
                    f"{executable_extension}."
                ),
                recommendation=(
                    "لا تشغل الملف قبل التحقق من المصدر "
                    "والتوقيع الرقمي وفحصه بأدوات الحماية."
                ),
                confidence="high",
                metadata={
                    "extension": executable_extension,
                },
            )
        )

    # =====================================================
    # 13. Nested Redirect
    # =====================================================

    nested_redirects = detect_nested_redirects(
        parsed.query
    )

    if nested_redirects:
        risk_indicators.append(
            "nested_redirect"
        )

        findings.append(
            make_finding(
                finding_id="CL-URL-014",
                title="تم اكتشاف رابط آخر داخل معامل Redirect",
                severity="medium",
                description=(
                    "يحتوي الرابط على معامل إعادة توجيه "
                    "يتضمن عنوان URL آخر."
                ),
                recommendation=(
                    "تحقق من الوجهة النهائية قبل فتح الرابط، "
                    "خصوصًا عند الانتقال بين نطاقات مختلفة."
                ),
                confidence="medium",
                metadata={
                    "redirects": nested_redirects[:5],
                },
            )
        )

    # =====================================================
    # ترتيب وتنظيف
    # =====================================================

    findings = deduplicate_findings(
        findings
    )

    findings = sort_findings(
        findings
    )

    return {
        "original_url": raw_url,
        "normalized_url": normalized_url,
        "scheme": scheme,
        "domain": hostname,
        "port": port,
        "path": parsed.path,
        "url_length": url_length,
        "subdomain_count": subdomain_count,
        "risk_indicators": risk_indicators,
        "findings": findings,
        "total_findings": len(
            findings
        ),
        "engine": "CyberLens URL Risk Analysis",
        "network_request_performed": False,
    }


# =========================================================
# اختبار مباشر
# =========================================================

if __name__ == "main":

    print("=" * 60)
    print("CyberLens URL Scanner")
    print("=" * 60)
    print(
        "Local heuristic analysis engine ready."
    )
    print(
        "Passive header checks run through passive_web_scanner."
    )
    print("=" * 60)

# =========================================================
# Enhanced URL Scan Wrapper
# =========================================================

def scan_url(raw_url: str) -> dict[str, Any]:
    result = _scan_url_static(
        raw_url
    )

    try:
        try:
            from .passive_web_scanner import run_passive_web_checks
        except Exception:
            from passive_web_scanner import run_passive_web_checks

        passive_findings, passive_indicators, passive_info = run_passive_web_checks(
            result.get("normalized_url") or raw_url,
            make_finding,
        )

        all_findings = (
            result.get("findings") or []
        ) + passive_findings

        result["findings"] = sort_findings(
            deduplicate_findings(
                all_findings
            )
        )

        indicators = set(
            result.get("risk_indicators") or []
        )

        indicators.update(
            passive_indicators
        )

        result["risk_indicators"] = sorted(
            indicators
        )

        result["total_findings"] = len(
            result["findings"]
        )

        result["network_request_performed"] = True
        result["passive_web_metadata"] = passive_info

    except Exception as exc:
        result["network_request_performed"] = False
        result["passive_web_error"] = str(exc)

    return result
