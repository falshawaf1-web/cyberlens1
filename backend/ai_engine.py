from __future__ import annotations

import json
import os
import re
import time
from typing import Any


# =========================================================
# إعدادات عامة
# =========================================================

SUPPORTED_SCAN_TYPES = {
    "code",
    "url",
    "dependencies",
    "project",
    "general",
}


SEVERITY_RANK = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
}


SEVERITY_AR = {
    "critical": "حرجة",
    "high": "عالية",
    "medium": "متوسطة",
    "low": "منخفضة",
    "info": "معلوماتية",
}


MAX_EXTERNAL_FINDINGS = 1000
MAX_LOCAL_DETAILS = 1000
MAX_TEXT_LENGTH = 3000

MAX_SNIPPET_LENGTH = 700


# =========================================================
# أدوات مساعدة
# =========================================================

def normalize_scan_type(
    scan_type: str | None,
) -> str:
    value = str(
        scan_type or "general"
    ).strip().lower()

    if value not in SUPPORTED_SCAN_TYPES:
        return "general"

    return value


def normalize_severity(
    value: Any,
) -> str:
    text = str(
        value or "info"
    ).strip().lower()

    mapping = {
        "critical": "critical",
        "crit": "critical",
        "حرج": "critical",
        "حرجة": "critical",

        "high": "high",
        "عالي": "high",
        "عالية": "high",

        "medium": "medium",
        "moderate": "medium",
        "متوسط": "medium",
        "متوسطة": "medium",

        "low": "low",
        "منخفض": "low",
        "منخفضة": "low",

        "info": "info",
        "informational": "info",
        "معلوماتي": "info",
        "معلوماتية": "info",
    }

    return mapping.get(
        text,
        "info",
    )


def scan_type_label(
    scan_type: str,
) -> str:
    labels = {
        "code": "فحص كود برمجي",
        "url": "فحص رابط",
        "dependencies": "فحص مكتبات واعتماديات",
        "project": "فحص مشروع برمجي كامل",
        "general": "فحص أمني عام",
    }

    return labels.get(
        normalize_scan_type(
            scan_type
        ),
        "فحص أمني عام",
    )


def safe_text(
    value: Any,
    max_length: int = MAX_TEXT_LENGTH,
) -> str:
    text = str(
        value or ""
    )

    text = text.replace(
        "\x00",
        "",
    )

    text = text.strip()

    if len(text) > max_length:
        return (
            text[: max_length - 3]
            + "..."
        )

    return text


# =========================================================
# إخفاء الأسرار
# =========================================================

SECRET_ASSIGNMENT_PATTERN = re.compile(
    r"""
    (?ix)
    \b
    (
        password
        |
        passwd
        |
        pwd
        |
        api[_-]?key
        |
        access[_-]?token
        |
        auth[_-]?token
        |
        secret
        |
        client[_-]?secret
        |
        private[_-]?key
    )
    \b
    \s*
    [:=]
    \s*
    (
        ["']
        [^"']{4,}
        ["']
        |
        [^\s,;]{4,}
    )
    """,
    re.VERBOSE,
)


BEARER_PATTERN = re.compile(
    r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}"
)


LONG_TOKEN_PATTERN = re.compile(
    r"\b[A-Za-z0-9_-]{40,}\b"
)


def redact_secrets(
    text: Any,
) -> str:
    value = safe_text(
        text,
        max_length=MAX_TEXT_LENGTH,
    )

    value = SECRET_ASSIGNMENT_PATTERN.sub(
        lambda match: (
            f"{match.group(1)}=[REDACTED]"
        ),
        value,
    )

    value = BEARER_PATTERN.sub(
        "Bearer [REDACTED]",
        value,
    )

    value = LONG_TOKEN_PATTERN.sub(
        "[REDACTED_LONG_TOKEN]",
        value,
    )

    return value


# =========================================================
# تنظيف Finding قبل استخدامه
# =========================================================

def sanitize_finding(
    finding: dict[str, Any],
) -> dict[str, Any]:
    clean: dict[str, Any] = {}
    allowed_fields = {
        "id",
        "title",
        "severity",
        "description",
        "recommendation",
        "source",
        "confidence",
        "file",
        "file_name",
        "line",
        "line_number",
        "rule",
        "category",
        "package",
        "installed_version",
        "fixed_version",
        "cve",
        "domain",
        "url",
        "indicator",
        "snippet",
        "code_snippet",
        "metadata",

        # =====================================================
        # حقول التصنيف المعياري
        # =====================================================
        #
        # كانت هذه الحقول مفقودة من القائمة المسموحة، فتُحذف قبل
        # وصولها إلى محرك التحليل. والأثر أن بطاقة الثغرة تظهر بلا
        # تصنيف CWE ولا فئة OWASP ولا درجة CVSS — رغم أن المابر
        # أضافها بنجاح في مرحلة سابقة.
        #
        # هذه الحقول ضرورية لسببين: عرضها للمستخدم، ومنع الذكاء
        # الاصطناعي من اختراع تصنيف حين لا يجد واحدًا.
        "cwe",
        "owasp",
        "cvss_score",
        "cvss_vector",
        "cvss_source",
        "cvss_rationale",
        "project_file",
        "ecosystem",
    }

    for key in allowed_fields:
        if key not in finding:
            continue

        value = finding.get(
            key
        )

        if key == "severity":
            clean[key] = normalize_severity(
                value
            )

            continue

        if key in {
            "snippet",
            "code_snippet",
        }:
            clean[key] = redact_secrets(
                safe_text(
                    value,
                    max_length=MAX_SNIPPET_LENGTH,
                )
            )

            continue

        if key == "metadata":
            if isinstance(
                value,
                dict,
            ):
                clean_metadata: dict[
                    str,
                    Any,
                ] = {}

                for meta_key, meta_value in list(
                    value.items()
                )[:25]:
                    if isinstance(
                        meta_value,
                        (
                            str,
                            int,
                            float,
                            bool,
                        ),
                    ) or meta_value is None:
                        clean_metadata[
                            str(meta_key)
                        ] = redact_secrets(
                            meta_value
                        )

        elif isinstance(
            value,
            (
                int,
                float,
                bool,
            ),
        ) or value is None:
            clean[key] = value

        else:
            clean[key] = safe_text(
                value
            )

    clean.setdefault(
        "id",
        "UNKNOWN-FINDING",
    )

    clean.setdefault(
        "title",
        "نتيجة أمنية",
    )

    clean["severity"] = normalize_severity(
        clean.get(
            "severity"
        )
    )

    return clean


def sanitize_findings(
    findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    clean: list[
        dict[str, Any]
    ] = []

    for finding in findings:
        if not isinstance(
            finding,
            dict,
        ):
            continue

        clean.append(
            sanitize_finding(
                finding
            )
        )

    return clean

# =========================================================
# إحصاءات الخطورة
# =========================================================

def severity_counts(
    findings: list[dict[str, Any]],
) -> dict[str, int]:
    counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }

    for finding in findings:
        severity = normalize_severity(
            finding.get(
                "severity"
            )
        )
        counts[
            severity
        ] += 1

    return counts


def highest_severity(
    findings: list[dict[str, Any]],
) -> str | None:
    if not findings:
        return None

    return max(
        (
            normalize_severity(
                finding.get(
                    "severity"
                )
            )
            for finding in findings
        ),
        key=lambda severity: (
            SEVERITY_RANK.get(
                severity,
                0,
            )
        ),
    )


# =========================================================
# ترتيب الأولويات
# =========================================================

def build_priority_order(
    findings: list[dict[str, Any]],
    limit: int = 10,
) -> list[dict[str, Any]]:
    ordered = sorted(
        findings,
        key=lambda finding: (
            -SEVERITY_RANK.get(
                normalize_severity(
                    finding.get(
                        "severity"
                    )
                ),
                0,
            ),
            safe_text(
                finding.get(
                    "title"
                )
            ).lower(),
            safe_text(
                finding.get(
                    "id"
                )
            ),
        ),
    )

    priorities: list[
        dict[str, Any]
    ] = []

    for index, finding in enumerate(
        ordered[:limit],
        start=1,
    ):
        severity = normalize_severity(
            finding.get(
                "severity"
            )
        )

        reason = (
            "تحتاج معالجة مبكرة بسبب مستوى الخطورة."
        )

        if severity == "critical":
            reason = (
                "أولوية قصوى بسبب تصنيف النتيجة كحرجة."
            )

        elif severity == "high":
            reason = (
                "أولوية مرتفعة بسبب احتمال أثر أمني كبير."
            )

        elif severity == "medium":
            reason = (
                "تحتاج معالجة منظمة بعد النتائج الأعلى خطورة."
            )

        priorities.append(
            {
                "priority": index,

                "finding_id": safe_text(
                    finding.get(
                        "id"
                    )
                ),

                "title": safe_text(
                    finding.get(
                        "title"
                    )
                ),

                "severity": severity,

                "reason": reason,

                "package": finding.get(
                    "package"
                ),

                "installed_version": finding.get(
                    "installed_version"
                ),

                "fixed_version": finding.get(
                    "fixed_version"
                ),
            }
        )

    return priorities


# =========================================================
# Correlation Engine
# =========================================================

# =========================================================
# Correlation Engine
# =========================================================

def detect_correlations(
    findings: list[dict[str, Any]],
    scan_type: str,
) -> list[dict[str, Any]]:
    """
    محرك Correlation حسب نوع الفحص.

    لا نطبق علاقات فحص الكود على نتائج المكتبات،
    ولا نطبق علاقات المكتبات على فحص الروابط.
    """

    correlations: list[
        dict[str, Any]
    ] = []

    clean_scan_type = normalize_scan_type(
        scan_type
    )

    clean_findings = [
        finding
        for finding in findings
        if isinstance(
            finding,
            dict,
        )
    ]

    # =====================================================
    # فحص الكود / المشروع
    # =====================================================

    if clean_scan_type in {
        "code",
        "project",
    }:

        def finding_identity(
            finding: dict[str, Any],
        ) -> str:
            """
            استخدام ID + Title بدل وصف طويل
            حتى لا نلتقط كلمات عرضية من Description.
            """

            finding_id = safe_text(
                finding.get(
                    "id"
                )
            ).upper()

            title = safe_text(
                finding.get(
                    "title"
                )
            ).lower()

            return (
                finding_id
                + " "
                + title
            )

        identities = [
            finding_identity(
                finding
            )
            for finding in clean_findings
        ]

        # -------------------------------------------------
        # Secrets
        # -------------------------------------------------

        has_secret = any(
            (
                "CL-SECRET-" in identity
                or "كلمة مرور ثابتة" in identity
                or "مفتاح api محتمل" in identity
                or "token محتمل" in identity
                or "hardcoded secret" in identity
                or "hardcoded password" in identity
            )
            for identity in identities
        )

        # -------------------------------------------------
        # TLS Weakness
        # -------------------------------------------------

        has_tls_weakness = any(
            (
                "CL-PY-005" in identity
                or "CL-GEN-001" in identity
                or "إلغاء التحقق من شهادة tls" in identity
                or "تعطيل التحقق من tls" in identity
            )
            for identity in identities
        )

        # -------------------------------------------------
        # Debug
        # -------------------------------------------------

        has_debug = any(
            (
                "CL-PY-007" in identity
                or "وضع debug" in identity
                or "تشغيل وضع debug" in identity
            )
            for identity in identities
        )

        # -------------------------------------------------
        # Dynamic / Command Execution
        # -------------------------------------------------

        execution_rule_ids = {
            "CL-PY-001",
            "CL-PY-002",
            "CL-PY-003",
            "CL-PY-004",
            "CL-JS-001",
            "CL-JS-003",
            "CL-PHP-001",
        }

        has_code_execution = any(
            (
                any(
                    rule_id in identity
                    for rule_id in execution_rule_ids
                )
                or "استخدام eval()" in identity
                or "استخدام exec()" in identity
                or "تنفيذ أوامر نظام" in identity
            )
            for identity in identities
        )

        # -------------------------------------------------
        # Secret + TLS
        # -------------------------------------------------

        if (
            has_secret
            and has_tls_weakness
        ):
            correlations.append(
                {
                    "id": "CL-CORR-CODE-001",

                    "severity": "high",

                    "title": (
                        "اجتماع أسرار ثابتة "
                        "مع ضعف في حماية الاتصال"
                    ),

                    "explanation": (
                        "وجود أسرار محتملة داخل الكود "
                        "بالتزامن مع ضعف في التحقق من TLS "
                        "قد يزيد أثر كشف بيانات الاعتماد "
                        "أو إساءة استخدامها."
                    ),
                }
            )

        # -------------------------------------------------
        # Secret + Debug
        # -------------------------------------------------

        if (
            has_secret
            and has_debug
        ):
            correlations.append(
                {
                    "id": "CL-CORR-CODE-002",

                    "severity": "high",

                    "title": (
                        "اجتماع أسرار ثابتة مع وضع Debug"
                    ),

                    "explanation": (
                        "وجود أسرار محتملة مع وضع Debug "
                        "قد يزيد احتمال ظهور معلومات حساسة "
                        "ضمن الأخطاء أو سجلات التطبيق."
                    ),
                }
            )

        # -------------------------------------------------
        # Execution + Secret
        # -------------------------------------------------

        if (
            has_code_execution
            and has_secret
        ):
            correlations.append(
                {
                    "id": "CL-CORR-CODE-003",

                    "severity": "critical",

                    "title": (
                        "خطر مركب بين تنفيذ كود "
                        "وأسرار محتملة"
                    ),

                    "explanation": (
                        "اجتماع مؤشرات تنفيذ ديناميكي "
                        "أو أوامر نظام مع أسرار ثابتة "
                        "قد يرفع أثر أي استغلال ناجح "
                        "بصورة كبيرة."
                    ),
                }
            )

    # =====================================================
    # فحص الروابط
    # =====================================================

    if clean_scan_type == "url":

        if len(
            clean_findings
        ) >= 3:
            correlations.append(
                {
                    "id": "CL-CORR-URL-001",

                    "severity": "high",

                    "title": (
                        "تجمع عدة مؤشرات خطر في الرابط"
                    ),

                    "explanation": (
                        "وجود عدة مؤشرات متزامنة أقوى "
                        "من الاعتماد على مؤشر واحد منفرد. "
                        "يجب التحقق من الرابط والجهة "
                        "المالكة قبل إدخال بيانات حساسة."
                    ),
                }
            )

    # =====================================================
    # فحص المكتبات / المشروع الكامل
    # =====================================================

    if clean_scan_type in {
        "dependencies",
        "project",
    }:

        severe_dependency_findings = [
            finding
            for finding in clean_findings
            if (
                normalize_severity(
                    finding.get(
                        "severity"
                    )
                )
                in {
                    "critical",
                    "high",
                }
                and safe_text(
                    finding.get(
                        "package"
                    )
                )
            )
        ]

        severe_packages = {
            safe_text(
                finding.get(
                    "package"
                )
            ).lower()
            for finding in severe_dependency_findings
            if safe_text(
                finding.get(
                    "package"
                )
            )
        }

        # -------------------------------------------------
        # أكثر من اعتمادية خطيرة
        # -------------------------------------------------

        if len(
            severe_packages
        ) >= 2:
            correlations.append(
                {
                    "id": "CL-CORR-DEP-001",

                    "severity": "high",

                    "title": (
                        "تعدد اعتماديات عالية الخطورة"
                    ),

                    "explanation": (
                        "تم اكتشاف مخاطر مرتفعة في أكثر "
                        "من اعتمادية برمجية، مما قد يزيد "
                        "سطح الهجوم ويستدعي خطة تحديث "
                        "مرتبة حسب التعرض والأثر."
                    ),
                }
            )

        # -------------------------------------------------
        # اعتمادية واحدة عليها عدة Advisories شديدة
        # -------------------------------------------------

        elif (
            len(
                severe_packages
            ) == 1
            and len(
                severe_dependency_findings
            ) >= 2
        ):

            package_name = next(
                (
                    safe_text(
                        finding.get(
                            "package"
                        )
                    )
                    for finding
                    in severe_dependency_findings
                    if safe_text(
                        finding.get(
                            "package"
                        )
                    )
                ),
                "Unknown Package",
            )

            critical_count = sum(
                1
                for finding
                in severe_dependency_findings
                if normalize_severity(
                    finding.get(
                        "severity"
                    )
                )
                == "critical"
            )

            correlation_severity = (
                "critical"
                if critical_count >= 2
                else "high"
            )

            correlations.append(
                {
                    "id": "CL-CORR-DEP-002",

                    "severity":
                        correlation_severity,

                    "title": (
                        "تراكم ثغرات شديدة في "
                        f"الاعتمادية {package_name}"
                    ),

                    "explanation": (
                        "تم اكتشاف عدة تنبيهات أمنية "
                        "حرجة أو عالية مرتبطة بنفس "
                        "الاعتمادية. هذا لا يعني وجود "
                        "عدة مكتبات ضعيفة، بل يشير إلى "
                        "تراكم مخاطر معروفة في الإصدار "
                        "المثبت ويستدعي مراجعة خطة "
                        "التحديث بأولوية مرتفعة."
                    ),
                }
            )

    # =====================================================
    # إزالة Correlations المكررة
    # =====================================================

    unique: list[
        dict[str, Any]
    ] = []

    seen_ids: set[str] = set()

    for correlation in correlations:
        correlation_id = safe_text(
            correlation.get(
                "id"
            )
        )

        if not correlation_id:
            continue

        if correlation_id in seen_ids:
            continue

        seen_ids.add(
            correlation_id
        )

        unique.append(
            correlation
        )

    return unique

# =========================================================
# شرح أثر النتيجة محليًا
# =========================================================

def local_impact_text(
    severity: str,
    scan_type: str,
) -> str:
    severity = normalize_severity(
        severity
    )

    clean_scan_type = normalize_scan_type(
        scan_type
    )

    if severity == "critical":
        base = (
            "النتيجة مصنفة حرجة وقد يكون لها أثر "
            "كبير على سرية النظام أو سلامته أو توافره."
        )

    elif severity == "high":
        base = (
            "النتيجة عالية الخطورة وقد تؤدي إلى أثر "
            "أمني مهم عند توفر ظروف الاستغلال المناسبة."
        )

    elif severity == "medium":
        base = (
            "النتيجة متوسطة الخطورة وتحتاج مراجعة "
            "ومعالجة ضمن خطة أمنية منظمة."
        )

    elif severity == "low":
        base = (
            "النتيجة منخفضة الخطورة لكنها قد تزيد "
            "سطح الهجوم أو تضعف الضوابط الدفاعية."
        )

    else:
        base = (
            "النتيجة معلوماتية وتحتاج تحققًا سياقيًا "
            "قبل اتخاذ قرار المعالجة."
        )

    context = {
        "code": (
            " يجب التحقق من مسار التنفيذ الفعلي "
            "وإمكانية وصول مدخلات غير موثوقة."
        ),

        "url": (
            " يجب التحقق من ملكية النطاق وسياق الرابط "
            "قبل إدخال أي بيانات حساسة."
        ),

        "dependencies": (
            " يجب مراجعة الإصدار المثبت والتنبيه الأمني "
            "واختبار التحديث في بيئة آمنة."
        ),
        "project": (
            " يجب تقييم العلاقة بين هذه النتيجة "
            "وبقية مكونات المشروع."
        ),

        "general": (
            " يجب تأكيد النتيجة ضمن سياق النظام."
        ),
    }

    return (
        base
        + context.get(
            clean_scan_type,
            context["general"],
        )
    )


# =========================================================
# التحقق بعد الإصلاح
# =========================================================

def local_verification_text(
    finding: dict[str, Any],
    scan_type: str,
) -> str:
    clean_scan_type = normalize_scan_type(
        scan_type
    )

    if clean_scan_type == "dependencies":
        fixed_version = finding.get(
            "fixed_version"
        )

        if fixed_version:
            return (
                "حدّث الاعتمادية بعد اختبار التوافق، "
                f"ثم تأكد من أن الإصدار الفعلي أصبح "
                f"{fixed_version} أو إصدارًا غير متأثر "
                "وفق التنبيه الأمني، وبعدها أعد الفحص."
            )

        return (
            "راجع التنبيه الأمني الرسمي، اختر إصدارًا "
            "غير متأثر بعد اختبار التوافق، ثم أعد فحص "
            "ملف الاعتماديات."
        )

    if clean_scan_type == "code":
        return (
            "عدّل الكود، شغّل اختبارات الوحدة والتكامل، "
            "ثم أعد فحص الملف وتأكد من اختفاء النتيجة "
            "دون كسر السلوك المتوقع."
        )

    if clean_scan_type == "url":
        return (
            "تحقق من النطاق والوجهة النهائية للرابط "
            "وسياق الاستخدام، ثم أعد الفحص بعد إزالة "
            "المؤشرات المشبوهة أو تصحيح الرابط."
        )

    if clean_scan_type == "project":
        return (
            "طبّق الإصلاح في بيئة اختبار، شغّل اختبارات "
            "المشروع، ثم أعد الفحص الكامل وقارن النتائج."
        )

    return (
        "طبّق الإصلاح في بيئة اختبار ثم أعد الفحص "
        "وتأكد من اختفاء النتيجة."
    )


# =========================================================
# ملاحظة False Positive
# =========================================================

def local_false_positive_note(
    finding: dict[str, Any],
    scan_type: str,
) -> str:
    clean_scan_type = normalize_scan_type(
        scan_type
    )

    if clean_scan_type == "dependencies":
        return (
            "قد تختلف قابلية الاستغلال حسب كيفية استخدام "
            "الاعتمادية والوظائف المتأثرة، لكن وجود إصدار "
            "مطابق لتنبيه معروف يستدعي المراجعة ولا ينبغي "
            "تجاهله تلقائيًا."
        )

    if clean_scan_type == "code":
        return (
            "الماسح يعتمد جزئيًا على تحليل ثابت وأنماط "
            "Heuristic؛ لذلك يجب مراجعة السياق ومسار "
            "التنفيذ لتأكيد قابلية الاستغلال."
        )

    if clean_scan_type == "url":
        return (
            "قد يكون بعض المؤشرات مشروعًا في سياق معين؛ "
            "لذلك يجب تأكيد ملكية النطاق والوجهة والسياق "
            "قبل تصنيف الرابط نهائيًا."
        )

    if clean_scan_type == "project":
        return (
            "بعض النتائج قد تعتمد على سياق التنفيذ "
            "أو ملفات غير مستخدمة فعليًا؛ راجع النتيجة "
            "ضمن بنية المشروع قبل اعتماد القرار النهائي."
        )

    return (
        "يجب التحقق يدويًا من السياق قبل اعتماد "
        "النتيجة كإصابة مؤكدة."
    )


# =========================================================
# التحليل التفصيلي المحلي
# =========================================================
def build_local_detailed_analysis(
    findings: list[dict[str, Any]],
    scan_type: str,
    limit: int | None = None,
) -> list[dict[str, Any]]:
    """
    Local Security Analyst.

    يبني تحليلًا تفصيليًا deterministic لكل Finding
    اعتمادًا على بيانات الفحص الفعلية فقط.
    لا يخترع CVE أو CWE أو OWASP غير الموجودة.
    """

    clean_scan_type = normalize_scan_type(
        scan_type
    )

    ordered = sorted(
        findings,
        key=lambda finding: (
            -SEVERITY_RANK.get(
                normalize_severity(
                    finding.get(
                        "severity"
                    )
                ),
                0,
            ),
            safe_text(
                finding.get(
                    "id"
                )
                or finding.get(
                    "finding_id"
                )
            ),
        ),
    )

    selected = (
        ordered
        if limit is None
        else ordered[:limit]
    )

    details: list[
        dict[str, Any]
    ] = []

    for finding in selected:

        if not isinstance(
            finding,
            dict,
        ):
            continue

        severity = normalize_severity(
            finding.get(
                "severity"
            )
        )

        severity_ar = SEVERITY_AR.get(
            severity,
            "معلوماتية",
        )

        finding_id = safe_text(
            finding.get(
                "id"
            )
            or finding.get(
                "finding_id"
            )
        )

        if not finding_id:
            finding_id = "UNKNOWN-FINDING"

        title = safe_text(
            finding.get(
                "title"
            )
        )

        if not title:
            title = "نتيجة أمنية"

        description = safe_text(
            finding.get(
                "description"
            )
            or finding.get(
                "message"
            )
            or finding.get(
                "title"
            )
        )

        if not description:
            description = (
                "تم اكتشاف نتيجة أمنية "
                "تحتاج إلى مراجعة."
            )

        recommendation = safe_text(
            finding.get(
                "recommendation"
            )
            or finding.get(
                "recommended_fix"
            )
        )

        if not recommendation:
            recommendation = (
                "راجع سبب النتيجة، طبّق "
                "المعالجة المناسبة في بيئة "
                "اختبار، ثم أعد الفحص للتحقق "
                "من زوالها."
            )

        package = safe_text(
            finding.get(
                "package"
            )
        )

        installed_version = safe_text(
            finding.get(
                "installed_version"
            )
        )

        fixed_version = safe_text(
            finding.get(
                "fixed_version"
            )
        )

        file_name = safe_text(
            finding.get(
                "file"
            )
            or finding.get(
                "filename"
            )
            or finding.get(
                "project_file"
            )
        )

        snippet = safe_text(
            finding.get(
                "snippet"
            )
            or finding.get(
                "code_snippet"
            ),
            max_length=1200,
        )

        metadata = (
            finding.get(
                "metadata"
            )
            if isinstance(
                finding.get(
                    "metadata"
                ),
                dict,
            )
            else {}
        )

        title_lower = title.lower()

        description_lower = (
            description.lower()
        )

        evidence_text = (
            title_lower
            + " "
            + description_lower
        )

        # =====================================================
        # Evidence Interpretation
        # =====================================================

        if clean_scan_type == "dependencies":

            evidence_interpretation = (
                "تشير نتيجة الفحص إلى وجود اعتماد "
                f"برمجي مرتبط بالنتيجة {finding_id}. "
                "وجود إصدار متأثر أو Advisory معروف "
                "يُعد دليلًا على حالة تستحق المعالجة، "
                "لكنه لا يثبت وحده نجاح استغلال فعلي "
                "داخل التطبيق."
            )

            if package:
                evidence_interpretation += (
                    f" الاعتمادية المحددة هي "
                    f"{package}."
                )

            if installed_version:
                evidence_interpretation += (
                    f" الإصدار المثبت هو "
                    f"{installed_version}."
                )

            if fixed_version:
                evidence_interpretation += (
                    f" الإصدار المرتبط بالمعالجة "
                    f"هو {fixed_version}."
                )

        elif clean_scan_type == "code":

            evidence_interpretation = (
                "الدليل يعتمد على النمط البرمجي "
                "الذي اكتشفه المحرك التحليلي. "
                "وجود النمط يثبت وجود مؤشر أمني "
                "في الكود، بينما تعتمد قابلية "
                "الاستغلال الفعلية على مسار التنفيذ "
                "ومصدر المدخلات والسياق التشغيلي."
            )

            if file_name:
                evidence_interpretation += (
                    f" تم ربط النتيجة بالملف "
                    f"{file_name}."
                )

            if snippet:
                evidence_interpretation += (
                    " يوجد مقطع أو دليل برمجي "
                    "مرتبط بالنتيجة يمكن مراجعته."
                )

        elif clean_scan_type == "url":

            evidence_interpretation = (
                "الدليل ناتج عن فحص خصائص الرابط "
                "أو استجابة HTTP/HTTPS والمؤشرات "
                "الأمنية المرتبطة بها. "
                "النتيجة تمثل حالة رصدها الفاحص "
                "في وقت الفحص ولا تعني وحدها "
                "وجود استغلال ناجح."
            )

        elif clean_scan_type == "project":

            evidence_interpretation = (
                "الدليل ناتج عن تحليل أحد مكونات "
                "المشروع، ولذلك يجب تفسيره ضمن "
                "العلاقة بين الملف أو الاعتمادية "
                "أو الإعداد المكتشف وباقي مكونات النظام."
            )

        else:

            evidence_interpretation = (
                "الدليل المتاح يثبت وجود مؤشر "
                "أمني التقطه الفاحص، ويجب ربطه "
                "بسياق التطبيق قبل اعتباره إثباتًا "
                "لقابلية الاستغلال."
            )

        # =====================================================
        # Root Cause
        # =====================================================

        if clean_scan_type == "dependencies":

            root_cause = (
                "السبب الجذري يرتبط باستخدام "
                "اعتمادية أو إصدار يحتاج إلى "
                "معالجة أمنية وفق البيانات المسجلة."
            )

            if package:
                root_cause = (
                    f"السبب الجذري يرتبط بالاعتمادية "
                    f"{package}"
                    + (
                        f" المستخدمة بالإصدار "
                        f"{installed_version}"
                        if installed_version
                        else ""
                    )
                    + "."
                )

        elif clean_scan_type == "url":

            root_cause = (
                "السبب الجذري هو غياب أو ضعف "
                "إعداد أمني في طبقة HTTP/HTTPS "
                "أو في سلوك الوجهة الذي اكتشفه الفاحص."
            )

            if (
                "content-security-policy"
                in evidence_text
                or "csp"
                in evidence_text
            ):
                root_cause = (
                    "السبب الجذري هو عدم وجود "
                    "أو عدم كفاية سياسة "
                    "Content-Security-Policy "
                    "في الاستجابة."
                )

            elif (
                "strict-transport-security"
                in evidence_text
                or "hsts"
                in evidence_text
            ):
                root_cause = (
                    "السبب الجذري هو غياب أو ضعف "
                    "Strict-Transport-Security (HSTS) "
                    "ضمن استجابة الموقع."
                )

            elif (
                "x-frame-options"
                in evidence_text
                or "clickjacking"
                in evidence_text
            ):
                root_cause = (
                    "السبب الجذري هو ضعف الحماية "
                    "المرتبطة بإمكانية تضمين الصفحة "
                    "ضمن سياقات الإطارات."
                )

            elif (
                "x-content-type-options"
                in evidence_text
            ):
                root_cause = (
                    "السبب الجذري هو غياب أو ضعف "
                    "X-Content-Type-Options "
                    "ضمن استجابة الموقع."
                )

            elif (
                "referrer-policy"
                in evidence_text
            ):
                root_cause = (
                    "السبب الجذري هو غياب أو ضعف "
                    "Referrer-Policy في الاستجابة."
                )

            elif (
                "permissions-policy"
                in evidence_text
            ):
                root_cause = (
                    "السبب الجذري هو غياب أو ضعف "
                    "Permissions-Policy في الاستجابة."
                )

        elif clean_scan_type == "code":

            root_cause = (
                "السبب الجذري يرتبط بالنمط البرمجي "
                "الذي اكتشفه الفاحص وطريقة معالجة "
                "المدخلات أو البيانات."
            )

            if "eval" in evidence_text:

                root_cause = (
                    "السبب الجذري هو استخدام تنفيذ "
                    "ديناميكي مثل eval، بما قد يحول "
                    "بيانات غير موثوقة إلى تعليمات "
                    "قابلة للتنفيذ حسب السياق."
                )

            elif (
                "secret"
                in evidence_text
                or "password"
                in evidence_text
                or "token"
                in evidence_text
                or "api key"
                in evidence_text
            ):

                root_cause = (
                    "السبب الجذري هو وجود قيمة حساسة "
                    "محتملة ضمن الكود بدل استخدام "
                    "آلية آمنة لإدارة الأسرار."
                )

            elif (
                "sql"
                in evidence_text
                or "query"
                in evidence_text
                or "injection"
                in evidence_text
            ):

                root_cause = (
                    "السبب الجذري يرتبط ببناء استعلام "
                    "أو تنفيذ عملية اعتمادًا على "
                    "بيانات إدخال دون ضوابط كافية."
                )

        elif clean_scan_type == "project":

            root_cause = (
                "السبب الجذري يرتبط بالمكون أو "
                "الاعتمادية أو الإعداد الذي اكتشفه "
                "الفاحص ضمن المشروع."
            )

        else:

            root_cause = (
                "السبب الجذري هو الحالة الأمنية "
                "التي التقطها الفاحص ضمن البيانات "
                "المتاحة، مع ضرورة مراجعة السياق."
            )

        # =====================================================
        # Technical Analysis
        # =====================================================

        technical_analysis = (
            f"النتيجة {finding_id} مصنفة بدرجة "
            f"خطورة {severity_ar}. "
            "يشير الدليل المتاح إلى وجود حالة أمنية "
            "رصدها الفاحص، ويجب الفصل بين إثبات "
            "وجود الحالة وإثبات قابلية استغلالها فعليًا. "
        )

        if clean_scan_type == "dependencies":

            technical_analysis += (
                "في فحص الاعتماديات، وجود إصدار متأثر "
                "أو Advisory معروف يعني أن المكون يحتاج "
                "إلى مراجعة ومعالجة، لكنه لا يثبت وحده "
                "أن التطبيق يستخدم المسار المتأثر "
                "بطريقة قابلة للاستغلال."
            )

        elif clean_scan_type == "code":

            technical_analysis += (
                "في تحليل الكود، يعتمد الأثر الفعلي "
                "على مسار البيانات والتنفيذ، ومصدر "
                "المدخلات، وحدود الثقة، وآلية التحقق "
                "أو التطهير، والمكون الذي يستهلك القيمة."
            )

        elif clean_scan_type == "url":

            technical_analysis += (
                "في فحص الرابط، تعكس النتيجة إعدادًا "
                "أو سلوكًا أمنيًا رصده الفاحص في "
                "HTTP/HTTPS."
            )

            if (
                "content-security-policy"
                in evidence_text
                or "csp"
                in evidence_text
            ):
                technical_analysis += (
                    " Content-Security-Policy توفر "
                    "طبقة تحكم في مصادر المحتوى التي "
                    "يسمح للمتصفح بتحميلها أو تنفيذها."
                )

            elif (
                "strict-transport-security"
                in evidence_text
                or "hsts"
                in evidence_text
            ):
                technical_analysis += (
                    " Strict-Transport-Security تساعد "
                    "المتصفح على فرض استخدام HTTPS "
                    "وفق السياسة المطبقة."
                )

            elif (
                "x-frame-options"
                in evidence_text
                or "clickjacking"
                in evidence_text
            ):
                technical_analysis += (
                    " X-Frame-Options تتحكم في إمكانية "
                    "تضمين الصفحة داخل frame أو iframe "
                    "ضمن السيناريوهات المدعومة."
                )

            elif (
                "x-content-type-options"
                in evidence_text
            ):
                technical_analysis += (
                    " X-Content-Type-Options تساعد "
                    "المتصفح على الالتزام بنوع المحتوى "
                    "المعلن وعدم التخمين في بعض السياقات."
                )

            elif (
                "referrer-policy"
                in evidence_text
            ):
                technical_analysis += (
                    " Referrer-Policy تتحكم في مقدار "
                    "معلومات المرجع التي يمكن إرسالها."
                )

            elif (
                "permissions-policy"
                in evidence_text
            ):
                technical_analysis += (
                    " Permissions-Policy تساعد في "
                    "التحكم باستخدام بعض قدرات المتصفح."
                )

        else:

            technical_analysis += (
                "يجب تفسير الحالة ضمن سياق النظام "
                "والمكونات الفعلية قبل اعتماد حكم نهائي."
            )

        # =====================================================
        # Exploitability
        # =====================================================

        if severity in {
            "critical",
            "high",
        }:

            exploitability_assessment = (
                "درجة الخطورة مرتفعة وفق تصنيف الفاحص، "
                "لكن النتيجة وحدها لا تثبت نجاح استغلال فعلي. "
                "يلزم التحقق من شروط الوصول ومسار التنفيذ "
                "والوظيفة المتأثرة."
            )

        elif severity == "medium":

            exploitability_assessment = (
                "توجد قابلية تأثير أمنية محتملة تستدعي "
                "التحقق، لكن إثبات الاستغلال يتطلب "
                "سياقًا إضافيًا."
            )

        else:

            exploitability_assessment = (
                "لم يثبت الفحص وحده وجود استغلال فعلي. "
                "ينبغي مراجعة النتيجة ضمن سياق التطبيق."
            )

        # =====================================================
        # Security Impact
        # =====================================================

        if clean_scan_type == "dependencies":

            security_impact = (
                "الأثر الأمني المحتمل مرتبط بالوظيفة "
                "المتأثرة في الاعتمادية، وبما إذا كان "
                "التطبيق يستخدم المسار المتأثر."
            )

        elif clean_scan_type == "url":

            security_impact = (
                "الأثر الأمني يتمثل في تقليل طبقة دفاعية "
                "في المتصفح أو الاتصال أو سياسة الموقع "
                "بحسب نوع المؤشر."
            )

        elif clean_scan_type in {
            "code",
            "project",
        }:

            security_impact = (
                "الأثر الأمني المحتمل يعتمد على البيانات "
                "التي تصل إلى المسار المتأثر وعلى قدرة "
                "جهة غير موثوقة على التحكم بها."
            )

        else:

            security_impact = (
                "الأثر الأمني المحتمل يجب تحديده "
                "وفق طبيعة النتيجة وسياق النظام."
            )

        # =====================================================
        # CIA
        # =====================================================

        confidentiality_impact = (
            "قد تتأثر السرية إذا كانت الحالة تسمح "
            "بوصول غير مقصود إلى بيانات محمية."
            if severity in {
                "critical",
                "high",
                "medium",
            }
            else
            "لم يثبت الفحص وحده أثرًا مباشرًا على السرية."
        )

        integrity_impact = (
            "قد تتأثر سلامة البيانات أو منطق التطبيق "
            "إذا كان المسار المتأثر يسمح بتفسير مدخلات "
            "غير موثوقة بصورة تؤثر في حالة النظام."
            if clean_scan_type in {
                "code",
                "project",
            }
            else
            "لم يثبت الفحص وحده أثرًا مباشرًا على سلامة البيانات."
        )

        availability_impact = (
            "قد يظهر أثر على التوافر إذا كانت الحالة "
            "قابلة للتحول إلى تعطيل أو استهلاك غير مناسب "
            "للموارد."
            if severity == "critical"
            else
            "لم يثبت الفحص وحده أثرًا مباشرًا على التوافر."
        )

        # =====================================================
        # Engineering Impact
        # =====================================================

        engineering_impact = (
            f"من منظور هندسي، تتطلب النتيجة {finding_id} "
            "مراجعة المكون المتأثر وتقييم نطاق التغيير "
            "وتطبيق المعالجة بطريقة لا تكسر السلوك الوظيفي."
        )

        if package:

            engineering_impact += (
                f" يجب تقييم توافق الاعتمادية "
                f"{package} مع بقية الاعتماديات."
            )

        # =====================================================
        # Risk Rationale
        # =====================================================

        risk_rationale = (
            f"تم اعتماد مستوى الخطورة {severity_ar} "
            "وفق تصنيف الفاحص. التحليل المحلي لا يرفع "
            "أو يخفض الشدة اعتمادًا على تخمين غير مدعوم."
        )

        severity_score = {
            "critical": 95,
            "high": 80,
            "medium": 60,
            "low": 30,
            "info": 10,
        }.get(
            severity,
            0,
        )

        # =====================================================
        # Why it matters
        # =====================================================

        why_it_matters = (
            f"أهمية النتيجة ناتجة عن كونها تمثل "
            f"حالة أمنية رصدها الفاحص بدرجة "
            f"{severity_ar}. معالجتها تقلل المخاطر "
            "وتدعم إعادة التحقق الأمني."
        )

        # =====================================================
        # Verification
        # =====================================================

        verification = local_verification_text(
            finding=finding,
            scan_type=clean_scan_type,
        )

        # =====================================================
        # False Positive
        # =====================================================

        false_positive_note = (
            local_false_positive_note(
                finding=finding,
                scan_type=clean_scan_type,
            )
        )

        # =====================================================
        # OWASP / CWE
        # لا نخترع تصنيفًا غير موجود.
        # =====================================================

        owasp = safe_text(
            finding.get(
                "owasp"
            )
            or metadata.get(
                "owasp"
            )
        )

        cwe = safe_text(
            finding.get(
                "cwe"
            )
            or metadata.get(
                "cwe"
            )
        )

        # =====================================================
        # Limitations
        # =====================================================

        limitations = (
            "هذا تحليل محلي deterministic يعتمد "
            "فقط على بيانات الفاحص والحقائق المتاحة "
            "داخل Finding. لا يثبت الاستغلال الفعلي "
            "ولا يستبدل اختبار الاختراق أو المراجعة اليدوية."
        )

        # =====================================================
        # Executive Summary
        # =====================================================

        executive_summary = (
            f"{title}: النتيجة مصنفة {severity_ar}. "
            f"{description} "
            f"{why_it_matters}"
        )

        # =====================================================
        # Final Detail Object
        # =====================================================

        details.append(
            {
                "finding_id":
                    finding_id,

                "title":
                    title,

                "severity":
                    severity,

                "severity_score":
                    severity_score,

                "executive_summary":
                    executive_summary,

                "what_is_the_issue":
                    description,

                "why_detected":
                    (
                        "تم اكتشاف النتيجة بواسطة محرك "
                        f"CyberLens ضمن "
                        f"{scan_type_label(clean_scan_type)}، "
                        "ويعتمد سبب الاكتشاف على المؤشرات "
                        "والأدلة المسجلة مع Finding."
                    ),

                "root_cause":
                    root_cause,

                "technical_analysis":
                    technical_analysis,

                "evidence_interpretation":
                    evidence_interpretation,

                "exploitability_assessment":
                    exploitability_assessment,

                "security_impact":
                    security_impact,

                "confidentiality_impact":
                    confidentiality_impact,

                "integrity_impact":
                    integrity_impact,

                "availability_impact":
                    availability_impact,

                "engineering_impact":
                    engineering_impact,

                "why_it_matters":
                    why_it_matters,

                "risk_rationale":
                    risk_rationale,

                "recommended_fix":
                    recommendation,

                "verification":
                    verification,

                "false_positive_note":
                    false_positive_note,

                "limitations":
                    limitations,

                "owasp":
                    owasp,

                "cwe":
                    cwe,

                "package":
                    finding.get(
                        "package"
                    ),

                "installed_version":
                    finding.get(
                        "installed_version"
                    ),

                "fixed_version":
                    finding.get(
                        "fixed_version"
                    ),

                "file":
                    finding.get(
                        "file"
                    ),

                "project_file":
                    finding.get(
                        "project_file"
                    ),
            }
        )

    return details
# =========================================================
# Summary محلي
# =========================================================

def build_local_summary(
    findings: list[dict[str, Any]],
    target_name: str,
    scan_type: str,
) -> str:
    total = len(
        findings
    )

    highest = highest_severity(
        findings
    )

    highest_ar = (
        SEVERITY_AR.get(
            highest,
            "لا توجد",
        )
        if highest
        else "لا توجد"
    )

    return (
        f"تم تحليل {total} نتيجة أمنية "
        f"للهدف {safe_text(target_name) or 'غير محدد'} "
        f"ضمن {scan_type_label(scan_type)}. "
        f"أعلى مستوى خطورة هو {highest_ar}."
    )


# =========================================================
# بناء التحليل المحلي الكامل
# =========================================================

def build_local_analysis(
    findings: list[dict[str, Any]],
    target_name: str,
    scan_type: str,
) -> dict[str, Any]:
    clean_scan_type = normalize_scan_type(
        scan_type
    )

    clean_findings = sanitize_findings(
        findings
    )

    return {
        "mode": "local",

        "provider": "CyberLens Local Analyzer",

        "scan_type": clean_scan_type,

        "target_name": safe_text(
            target_name
        ),

        "summary": build_local_summary(
            findings=clean_findings,
            target_name=target_name,
            scan_type=clean_scan_type,
        ),

        "severity_counts": severity_counts(
            clean_findings
        ),

        "highest_severity": highest_severity(
            clean_findings
        ),

        "priority_order": build_priority_order(
            clean_findings
        ),

        "correlations": detect_correlations(
            findings=clean_findings,
            scan_type=clean_scan_type,
        ),

        "detailed_analysis": (
            build_local_detailed_analysis(
                findings=clean_findings,
                scan_type=clean_scan_type,
            )
        ),
    }
# =========================================================
# Payload آمن للذكاء الاصطناعي الخارجي
# =========================================================
def build_ai_payload(
    findings: list[dict[str, Any]],
    target_name: str,
    scan_type: str,
) -> dict[str, Any]:

    clean_scan_type = normalize_scan_type(
        scan_type
    )

    clean_findings = sanitize_findings(
        findings
    )

    return {
        "system": "CyberLens",
        "task": (
            "Defensive security analysis only"
        ),
        "language": "Arabic",

        "scan_type": clean_scan_type,

        "scan_type_label": scan_type_label(
            clean_scan_type
        ),

        "target_name": safe_text(
            target_name
        ),

        "total_findings": len(
            clean_findings
        ),

        "findings_sent": len(
            clean_findings
        ),

        "severity_counts": severity_counts(
            clean_findings
        ),

        "highest_severity": highest_severity(
            clean_findings
        ),

        "deterministic_correlations": (
            detect_correlations(
                findings=clean_findings,
                scan_type=clean_scan_type,
            )
        ),

        "findings": clean_findings,
    }

# =========================================================
# استخراج JSON من رد AI
# =========================================================


   
def extract_json_object(
    text: str,
) -> dict[str, Any] | None:
    value = safe_text(
        text,
        max_length=100000,
    ).strip()

    if not value:
        return None

    # -----------------------------------------------------
    # إزالة Markdown fences إن وجدت
    # -----------------------------------------------------

    markdown_fence = "`" * 3

    if value.startswith(
        markdown_fence
    ):
        first_line_end = value.find(
            "\n"
        )

        if first_line_end != -1:
            first_line = value[
                :first_line_end
            ].strip().lower()

            if first_line in {
                markdown_fence,
                markdown_fence + "json",
            }:
                value = value[
                    first_line_end + 1:
                ]

        else:
            value = value[
                len(markdown_fence):
            ]

        value = value.strip()

        if value.endswith(
            markdown_fence
        ):
            value = value[
                :-len(markdown_fence)
            ].strip()

    # -----------------------------------------------------
    # محاولة مباشرة
    # -----------------------------------------------------

    try:
        parsed = json.loads(
            value
        )

        if isinstance(
            parsed,
            dict,
        ):
            return parsed

    except json.JSONDecodeError:
        pass

    # -----------------------------------------------------
    # البحث عن أول Object JSON
    # -----------------------------------------------------

    start = value.find(
        "{"
    )

    end = value.rfind(
        "}"
    )

    if (
        start == -1
        or end == -1
        or end <= start
    ):
        return None

    candidate = value[
        start:
        end + 1
    ]

    try:
        parsed = json.loads(
            candidate
        )

        if isinstance(
            parsed,
            dict,
        ):
            return parsed

    except json.JSONDecodeError:
        return None

    return None


# =========================================================
# استخراج نص Responses API
# =========================================================

def extract_openai_response_text(
    response: Any,
) -> str:
    direct = getattr(
        response,
        "output_text",
        None,
    )

    if direct:
        return str(
            direct
        )

    output = getattr(
        response,
        "output",
        None,
    )

    if not output:
        return ""

    collected: list[
        str
    ] = []

    try:
        for item in output:
            content = getattr(
                item,
                "content",
                None,
            )

            if not content:
                continue

            for content_item in content:
                text_value = getattr(
                    content_item,
                    "text",
                    None,
                )
                if text_value:
                    collected.append(
                        str(
                            text_value
                        )
                    )

    except Exception:
        return ""

    return "\n".join(
        collected
    )


# =========================================================
# Prompt خارجي
# =========================================================
def build_external_instructions() -> str:
    return (
        "أنت محلل أمن سيبراني دفاعي متقدم يعمل داخل منصة CyberLens. "

        "مهمتك تحليل نتائج الفحص الفعلية التي يرسلها النظام فقط، "
        "وإنتاج تحليل أمني وتقني وأكاديمي عالي الجودة، "
        "واضح ومفهوم للطالب والمطور والمهندس الأمني، "
        "ومناسب للأرشفة الرسمية والتقارير المهنية. "

        "قاعدة أساسية: البيانات الأمنية الموثوقة تأتي من نتائج "
        "الفحص ومصادر الـAdvisory المرفقة في المدخلات. "
        "دورك هو تفسير هذه البيانات وربطها بالسياق، وليس اختراع "
        "حقائق جديدة. "

        "ممنوع اختراع أو تغيير CVE أو GHSA أو CVSS أو CVSS Vector "
        "أو CWE أو OWASP أو Severity أو Confidence أو Installed Version "
        "أو Fixed Version أو Evidence أو Detection Source. "
        "إذا كانت قيمة غير موجودة، أعد قيمة فارغة أو صرّح بأنها "
        "غير متوفرة، ولا تستنتجها على أنها حقيقة مؤكدة. "

        "فرّق دائمًا بين ثلاثة مستويات: "
        "1) ما أثبته الفحص بشكل مباشر، "
        "2) ما يمكن استنتاجه تقنيًا من البيانات المتوفرة، "
        "3) ما يحتاج إلى تحقق إضافي داخل التطبيق أو البيئة. "

        "يجب ألا تعتبر وجود إصدار متأثر دليلًا على exploitability "
        "مؤكدة. استخدم دائمًا التمييز بين "
        "vulnerable condition detected "
        "و exploitability confirmed. "

        "لكل Finding أنشئ تحليلًا مستقلًا ومخصصًا لطبيعتها. "
        "لا تستخدم نصًا عامًا متكررًا بين Findings المختلفة. "
        "يجب أن يعتمد التحليل على العنوان والوصف والدليل "
        "والـmetadata ونوع الفحص والـAdvisory المتوفر. "

        # --------------------------------------------------
        # Executive explanation
        # --------------------------------------------------

        "في executive_summary اكتب خلاصة قصيرة لكنها قوية، "
        "توضح المشكلة وأهم أثر محتمل والسبب الذي يجعلها مهمة، "
        "بحيث يستطيع المهندس فهم الحالة بسرعة دون فقدان الدقة. "

        "في what_is_the_issue اشرح ما هي المشكلة فعليًا، "
        "وما المكوّن أو الوظيفة أو البروتوكول أو الاعتمادية "
        "المتأثرة، عندما تكون هذه المعلومة مدعومة. "

        # --------------------------------------------------
        # Detection
        # --------------------------------------------------

        "في why_detected اشرح بالتحديد لماذا أنشأ CyberLens "
        "هذا Finding وما الدليل الذي أدى إليه. "
        "بالنسبة للاعتماديات، وضّح مطابقة اسم الحزمة والإصدار "
        "مع نطاق الإصدارات المتأثرة. "
        "بالنسبة للكود، اربط التحليل بالنمط البرمجي الفعلي. "
        "بالنسبة للـURL، اربط التحليل بالإشارة أو الـheader "
        "أو السلوك الذي اكتشفه الماسح. "

        # --------------------------------------------------
        # Root cause
        # --------------------------------------------------

        "في root_cause وضح السبب الجذري للضعف عندما يمكن دعمه "
        "من البيانات. لا تساوِ بين 'الإصدار قديم' وبين "
        "'السبب الجذري للثغرة'. قدم السبب البرمجي أو المنطقي "
        "أو المعماري الحقيقي عندما يكون معروفًا. "

        # --------------------------------------------------
        # Technical analysis
        # --------------------------------------------------

        "في technical_analysis اكتب تحليلًا تقنيًا عميقًا "
        "يشرح آلية الضعف خطوةً بمستوى مناسب للمهندس، "
        "لكن دون تقديم تعليمات هجومية عملية أو خطوات استغلال. "

        "وضح المكوّن المتأثر، مسار المعالجة، نوع المدخلات "
        "ذات العلاقة، السبب الذي يجعل هذا السلوك خطرًا، "
        "وما الذي قد يحدث في الظروف المناسبة. "

        "إذا كانت التفاصيل التقنية غير موجودة في المصدر، "
        "لا تخترعها؛ اشرح حدود ما يمكن إثباته من البيانات. "

        # --------------------------------------------------
        # Evidence
        # --------------------------------------------------

        "في evidence_interpretation فسّر ماذا يثبت الدليل "
        "الموجود بالضبط وماذا لا يثبت. "
        "لا تعتبر وجود package في requirements.txt دليلًا "
        "على وصول runtime إلى الوظيفة الضعيفة، "
        "ولا تعتبر وجود pattern في الكود دليلًا على exploit "
        "ناجح ما لم يثبت ذلك الفحص. "

        # --------------------------------------------------
        # Exploitability
        # --------------------------------------------------

        "في exploitability_assessment قيّم قابلية الاستغلال "
        "بشكل تحليلي ومحافظ. "
        "وضح الشروط اللازمة إن كانت معروفة، "
        "ووضح إن كانت البيانات تثبت vulnerable version فقط "
        "أو تثبت مسارًا قابلًا للوصول أو سلوكًا قابلًا للتحقق. "

        # --------------------------------------------------
        # Security impact
        # --------------------------------------------------

        "في security_impact اشرح الأثر الأمني الفعلي المحتمل "
        "بحسب طبيعة Finding. "

        "يجب تحليل Confidentiality وIntegrity وAvailability "
        "كلٌ على حدة، وعدم افتراض تأثرها جميعًا. "

        "استخدم الحقول التالية عند الحاجة: "
        "confidentiality_impact, integrity_impact, "
        "availability_impact. "

        # --------------------------------------------------
        # Why it matters
        # --------------------------------------------------

        "في why_it_matters وضح لماذا تستحق النتيجة المعالجة "
        "من منظور أمني وهندسي وعملي، "
        "وليس بعبارات عامة مثل 'تقليل مستوى الحماية'. "

        # --------------------------------------------------
        # Risk
        # --------------------------------------------------

        "في risk_rationale اشرح معنى Severity وCVSS "
        "في سياق النتيجة، لكن لا تعيد حساب CVSS "
        "ولا تغير القيمة المصدرية. "

        "إذا كان CVSS Vector متوفرًا، استخدمه لتفسير "
        "خصائص الاستغلال والأثر فقط. "

        # --------------------------------------------------
        # Engineering
        # --------------------------------------------------

        "في engineering_impact وضح الآثار الهندسية مثل "
        "التوافق، regression risk، dependency resolution، "
        "deployment impact، testing requirements، "
        "configuration impact، reproducibility، "
        "أو تأثير التغيير على CI/CD عندما يكون ذلك مناسبًا. "

        # --------------------------------------------------
        # Remediation
        # --------------------------------------------------

        "في recommended_fix قدم معالجة تقنية دفاعية قابلة للتنفيذ. "
        "لا تكتفِ بعبارة 'حدّث المكتبة'. "
        "اذكر النسخة غير المتأثرة إذا كانت موثقة في المدخلات، "
        "واذكر ما يجب اختباره بعد التحديث. "

        # --------------------------------------------------
        # Verification
        # --------------------------------------------------

        "في verification وضح طريقة إثبات نجاح الإصلاح. "
        "يجب أن تشمل التحقق من الحالة الجديدة ثم إعادة الفحص "
        "والاختبارات المناسبة، وليس مجرد القول 'أعد الفحص'. "

        # --------------------------------------------------
        # False positive / limitations
        # --------------------------------------------------

        "في false_positive_note وضح متى يمكن أن تختلف "
        "قابلية الاستغلال الفعلية عن نتيجة الكشف. "

        "في limitations وضح حدود الاستنتاج من البيانات المتوفرة "
        "والأمور التي تحتاج تحققًا إضافيًا. "

        # --------------------------------------------------
        # Classification
        # --------------------------------------------------

        "استخدم CWE وOWASP فقط إذا كان الربط مدعومًا بالبيانات. "
        "لا تخترع تصنيفًا لمجرد ملء الحقل. "

        "إذا لم يتوفر CWE أو OWASP بشكل موثوق، أعد قيمة فارغة "
        "بدل اختراع تصنيف غير مناسب. "

        # --------------------------------------------------
        # Scan-type specific rules
        # --------------------------------------------------

        "في dependencies: "
        "فرّق بين Vulnerable Dependency وDependency Hygiene. "
        "عدم تثبيت الإصدار ليس CVE بحد ذاته. "
        "وجود إصدار متأثر لا يساوي exploitability confirmed. "

        "في code: "
        "اربط التحليل بالـpattern البرمجي ومكانه ومسار البيانات "
        "وطريقة التنفيذ عندما تكون هذه المعلومات متوفرة. "

        "في URL: "
        "فرّق بين CSP وHSTS وX-Frame-Options و"
        "X-Content-Type-Options وReferrer-Policy و"
        "Permissions-Policy وغيرها. "
        "اشرح وظيفة كل header وفق طبيعة النتيجة نفسها، "
        "ولا تستخدم شرحًا عامًا موحدًا لكل headers. "

        "في project: "
        "اربط النتيجة بالمكوّن والملف والعلاقة بين المكونات "
        "عندما تكون البيانات متوفرة، ولا تعامل كل Finding "
        "كحالة معزولة إذا كان هناك دليل على ترابط فعلي. "

        # --------------------------------------------------
        # Language quality
        # --------------------------------------------------

        "اكتب باللغة العربية الفصحى الواضحة والمهنية. "
        "يمكن استخدام المصطلح الإنجليزي بين قوسين عند الحاجة "
        "حتى يبقى المصطلح التقني معروفًا للمهندس. "

        "تجنب الحشو والتكرار والجمل العامة. "
        "كل فقرة يجب أن تضيف معلومة جديدة. "

        "اجعل الأسلوب مفهومًا للطالب، "
        "لكن بالمستوى الذي يمكن لمهندس أمن سيبراني "
        "قراءته والاعتماد عليه كتفسير مهني. "

        # --------------------------------------------------
        # Output contract
        # --------------------------------------------------
        # --------------------------------------------------
        # DEPTH AND QUALITY REQUIREMENTS
        # --------------------------------------------------

        "مهم جدًا: لا تكتب إجابات مختصرة أو عامة. "
        "كل Finding يجب أن يحصل على تحليل أمني مستقل وعميق. "

        "يجب أن يكون executive_summary من 3 إلى 5 جمل "
        "تلخص المشكلة والسبب والأثر والأولوية. "

        "يجب أن يكون what_is_the_issue من 4 إلى 6 جمل "
        "تشرح المشكلة بلغة واضحة وتقنية، وليس مجرد إعادة عنوان الثغرة. "

        "يجب أن يكون why_detected من 3 إلى 5 جمل "
        "تشرح بالتحديد كيف أدت بيانات الفحص إلى إنشاء Finding. "

        "يجب أن يكون root_cause من 3 إلى 6 جمل "
        "تشرح السبب الجذري الحقيقي عندما يكون مدعومًا، "
        "ولا تستخدم عبارة 'الإصدار قديم' كسبب جذري لثغرة برمجية. "

        "يجب أن يكون technical_analysis من 8 إلى 14 جملة مترابطة "
        "وتشمل المكوّن المتأثر، مسار المعالجة، نوع البيانات "
        "أو المدخلات ذات الصلة، آلية الضعف، سبب حدوثه، "
        "النتيجة التقنية المحتملة، وشروط الوصول إلى المسار "
        "عندما تدعم البيانات ذلك. "

        "technical_analysis هو أهم جزء في التحليل ويجب أن يكون "
        "أكثر قسم تفصيلاً. لا تختصره في جملة أو جملتين. "

        "يجب أن يكون evidence_interpretation من 3 إلى 6 جمل "
        "تشرح ماذا يثبت الدليل فعليًا وماذا لا يثبت. "

        "يجب أن يكون exploitability_assessment من 4 إلى 7 جمل "
        "ويجب أن يفرق بوضوح بين وجود حالة ضعيفة وبين إثبات "
        "قابلية الاستغلال داخل التطبيق. "

        "يجب أن يكون security_impact من 4 إلى 7 جمل "
        "تشرح الأثر الأمني الحقيقي حسب طبيعة النتيجة. "

        "يجب أن تكون confidentiality_impact و"
        "integrity_impact وavailability_impact "
        "تحليلات منفصلة وليست نسخًا من نفس الجملة. "

        "يجب أن يكون engineering_impact من 4 إلى 7 جمل "
        "ويشرح أثر الإصلاح على التوافق والاختبارات والبناء "
        "والنشر والاعتماديات عندما يكون ذلك مناسبًا. "

        "يجب أن يكون why_it_matters من 4 إلى 6 جمل "
        "تشرح لماذا يجب على الفريق معالجة النتيجة. "

        "يجب أن يكون risk_rationale من 3 إلى 6 جمل "
        "تشرح معنى مستوى الخطورة في سياق النتيجة دون إعادة "
        "حساب أو تغيير Severity أو CVSS. "

        "يجب أن يكون recommended_fix من 4 إلى 8 جمل "
        "ويشرح الإجراء الدفاعي، والإصدار المستهدف عند توفره، "
        "واختبارات التوافق وما يجب فعله بعد التغيير. "

        "يجب أن يكون verification من 4 إلى 7 جمل "
        "ويصف طريقة عملية لإثبات أن المشكلة اختفت بعد الإصلاح. "

        "يجب أن يكون false_positive_note من 2 إلى 5 جمل "
        "ولا تستخدم 'لا يوجد' إلا إذا لم توجد أي حالة منطقية "
        "يمكن أن تغير تفسير النتيجة. "

        "يجب أن يكون limitations من 2 إلى 5 جمل "
        "وتوضح بدقة حدود ما يمكن إثباته من البيانات الحالية. "

        "ممنوع استخدام عبارات عامة مثل: "
        "'تؤثر على الأمان'، "
        "'قد تسبب مشاكل'، "
        "'يجب تحديث المكتبة'، "
        "'تقلل مستوى الحماية' "
        "من دون شرح تقني يوضح لماذا وكيف. "

        "لا تكرر نفس الفقرة بين Findings. "
        "إذا كانت الثغرتان مختلفتين تقنيًا، فيجب أن يكون "
        "التحليل مختلفًا تقنيًا أيضًا. "

        "في dependency vulnerabilities، اشرح طبيعة الـAdvisory "
        "والآلية الأمنية الخاصة بها عندما تكون مدعومة بالبيانات، "
        "ولا تكتفِ بقول إن الإصدار متأثر. "

        "عند توفر CVE أو GHSA أو وصف Advisory، "
        "استخدمه لتحليل طبيعة المشكلة وحدودها التقنية. "

        "لا تملأ الحقول بالكلام لمجرد زيادة الطول؛ "
        "كل جملة يجب أن تضيف معلومة تقنية أو أمنية مفيدة. "

        "أعد JSON object فقط دون Markdown ودون أي نص خارج JSON. "

        "يجب أن يحتوي JSON على: "
        "summary, priority_order, detailed_analysis. "

        "priority_order يجب أن يحتوي على النتائج الأعلى أولوية "
        "ويُسمح بحد أقصى 10 عناصر، "
        "وكل عنصر يحتوي على: "
        "priority, finding_id, title, severity, reason. "

        "detailed_analysis يجب أن يحتوي على تحليل لكل Finding "
        "تم إرساله في الدفعة الحالية، دون حذف النتائج بسبب عددها. "

        "كل عنصر في detailed_analysis يجب أن يحتوي على: "
        "finding_id, title, severity, "
        "executive_summary, "
        "what_is_the_issue, "
        "why_detected, "
        "root_cause, "
        "technical_analysis, "
        "evidence_interpretation, "
        "exploitability_assessment, "
        "security_impact, "
        "confidentiality_impact, "
        "integrity_impact, "
        "availability_impact, "
        "engineering_impact, "
        "why_it_matters, "
        "risk_rationale, "
        "recommended_fix, "
        "verification, "
        "false_positive_note, "
        "limitations, "
        "owasp, "
        "cwe. "

        "يجب أن يكون تحليل كل Finding مختلفًا ومبنيًا على "
        "بياناته الفعلية. "
    )

# =========================================================
# التحقق من قوائم AI
# =========================================================

def clean_external_priority_order(
    value: Any,
) -> list[dict[str, Any]]:
    if not isinstance(
        value,
        list,
    ):
        return []

    result: list[
        dict[str, Any]
    ] = []

    for index, item in enumerate(
        value[:10],
        start=1,
    ):
        if not isinstance(
            item,
            dict,
        ):
            continue

        result.append(
            {
                "priority": item.get(
                    "priority",
                    index,
                ),

                "finding_id": safe_text(
                    item.get(
                        "finding_id"
                    )
                ),

                "title": safe_text(
                    item.get(
                        "title"
                    )
                ),

                "severity": normalize_severity(
                    item.get(
                        "severity"
                    )
                ),

                "reason": safe_text(
                    item.get(
                        "reason"
                    )
                ),
            }
        )

    return result


def clean_external_detailed_analysis(
    value: Any,
) -> list[dict[str, Any]]:
    """
    تنظيف قائمة التحليل التفصيلي القادمة من الذكاء الاصطناعي.

    ملاحظة على خلل أُصلح هنا:

        كان هذا التعريف مكرّرًا ومتداخلًا — دالة معرَّفة داخل دالة
        تحمل الاسم نفسه. فأصبح جسم الدالة الخارجية مجرد تعريف للدالة
        الداخلية دون استدعائها، وتُرجع None دائمًا.

        الأثر: حتى عند نجاح الذكاء الخارجي وإرجاعه تحليلًا صحيحًا،
        كانت النتيجة تُعتبر فارغة فيسقط النظام للتحليل المحلي —
        ويظهر "local" في الواجهة رغم أن Groq عمل فعلًا.

        وهذا يفسّر السطرين المتناقضين في السجل:
            [CyberLens AI] External AI used: Groq
            mode: local
    """
    if not isinstance(
        value,
        list,
    ):
        return []

    result: list[dict[str, Any]] = []

    for item in value:
        if not isinstance(
            item,
            dict,
        ):
            continue

        result.append(
            {
                "finding_id": safe_text(
                    item.get(
                        "finding_id"
                    )
                ),

                "title": safe_text(
                    item.get(
                        "title"
                    )
                ),

                "severity": normalize_severity(
                    item.get(
                        "severity"
                    )
                ),

                "what_is_the_issue": safe_text(
                    item.get(
                        "what_is_the_issue"
                    )
                ),

                "why_detected": safe_text(
                    item.get(
                        "why_detected"
                    )
                ),

                "technical_analysis": safe_text(
                    item.get(
                        "technical_analysis"
                    )
                ),
                "executive_summary": safe_text(
    item.get(
        "executive_summary"
    )
),

"root_cause": safe_text(
    item.get(
        "root_cause"
    )
),

"evidence_interpretation": safe_text(
    item.get(
        "evidence_interpretation"
    )
),

"exploitability_assessment": safe_text(
    item.get(
        "exploitability_assessment"
    )
),

"confidentiality_impact": safe_text(
    item.get(
        "confidentiality_impact"
    )
),

"integrity_impact": safe_text(
    item.get(
        "integrity_impact"
    )
),

"availability_impact": safe_text(
    item.get(
        "availability_impact"
    )
),

"engineering_impact": safe_text(
    item.get(
        "engineering_impact"
    )
),

"risk_rationale": safe_text(
    item.get(
        "risk_rationale"
    )
),

"limitations": safe_text(
    item.get(
        "limitations"
    )
),

                "security_impact": safe_text(
                    item.get(
                        "security_impact"
                    )
                ),

                "why_it_matters": safe_text(
                    item.get(
                        "why_it_matters"
                    )
                ),

                "recommended_fix": safe_text(
                    item.get(
                        "recommended_fix"
                    )
                ),

                "verification": safe_text(
                    item.get(
                        "verification"
                    )
                ),

                "false_positive_note": safe_text(
                    item.get(
                        "false_positive_note"
                    )
                ),

                "owasp": safe_text(
                    item.get(
                        "owasp"
                    )
                ),

                "cwe": safe_text(
                    item.get(
                        "cwe"
                    )
                ),
            }
        )

    return result

# =# =========================================================
# تشغيل AI خارجي اختياريًا
# =========================================================

def _batch_delay() -> float:
    """
    التأخير بين دفعات التحليل بالثواني.

    الافتراضي 4 ثوانٍ يوزّع الاستهلاك ضمن نافذة الدقيقة في الخطة
    المجانية. يمكن خفضه إلى صفر عند الترقية لخطة أعلى.
    """
    try:
        return max(0.0, min(float(os.environ.get("CYBERLENS_AI_BATCH_DELAY", "1")), 15.0))
    except (ValueError, TypeError):
        return 4.0


def try_external_ai(
    findings: list[dict[str, Any]],
    target_name: str,
    scan_type: str,
) -> dict[str, Any] | None:

    if not findings:
        return None

    # =====================================================
    # حدود الموارد
    # =====================================================
    #
    # المشكلة التي تعالجها هذه الحدود:
    #
    #   الشيفرة السابقة كانت تقسّم كل النتائج إلى دفعات بلا سقف، ثم
    #   تجمّع استجابات الذكاء الاصطناعي كلها في الذاكرة. فحص ملف
    #   اعتماديات بأربعين مكتبة يُنتج نحو ستين ثغرة، أي خمس عشرة دفعة
    #   بحجم 1400 توكن لكل واحدة — وهو ما يستنزف ذاكرة الخادم على
    #   الخطط محدودة الموارد (512 ميجابايت) فيُقتَل المعالج بإشارة
    #   SIGKILL ويعود الطلب بخطأ 500 بلا تفسير.
    #
    # الحل: سقف صريح على عدد النتائج المُرسَلة للتحليل الخارجي.
    #
    # اختيار النتائج ليس عشوائيًا: تُرتَّب حسب الخطورة أولًا، فتُحلَّل
    # الثغرات الحرجة والعالية بالذكاء الاصطناعي، بينما تُعرَض البقية
    # بالتحليل المحلي. وهذا هو الترتيب الصحيح للأولويات أصلًا.

    max_ai_findings = 20

    try:
        max_ai_findings = int(
            os.environ.get("CYBERLENS_AI_MAX_FINDINGS", "6")
        )
    except (ValueError, TypeError):
        max_ai_findings = 20

    severity_rank = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
        "info": 4,
    }

    ordered_findings = sorted(
        findings,
        key=lambda item: severity_rank.get(
            str(item.get("severity", "info")).lower(),
            5,
        ),
    )

    truncated = len(ordered_findings) > max_ai_findings

    if truncated:
        print(
            "[CyberLens AI] عدد النتائج",
            len(ordered_findings),
            "يتجاوز الحد",
            max_ai_findings,
            "— سيُحلَّل الأخطر فقط بالذكاء الخارجي.",
        )

    selected_findings = ordered_findings[:max_ai_findings]

    # =====================================================
    # حجم الدفعة
    # =====================================================
    #
    # المشكلة التي عالجها خفض هذا الرقم:
    #
    #   يُطلَب من النموذج نحو 22 حقلًا نصيًا لكل نتيجة. وبدفعة من أربع
    #   نتائج يصبح المطلوب 88 حقلًا في استجابة واحدة — وهو ما يتجاوز
    #   ميزانية المخرجات بعد خصم ما يستهلكه النموذج في تفكيره الداخلي.
    #
    #   والأثر أن النموذج يملأ الحقول الأولى ويترك الباقية فارغة، فتظهر
    #   بطاقة الثغرة مختلطة: جزء بصياغة الذكاء الخارجي وجزء بالقوالب
    #   المحلية.
    #
    # الحل: دفعة من نتيجتين، فتتضاعف الميزانية المتاحة لكل نتيجة.
    # الأثر على الزمن محدود لأن الدفعات تُنفَّذ ضمن ميزانية زمنية كلية.

    try:
        batch_size = int(os.environ.get("CYBERLENS_AI_BATCH_SIZE", "2"))
    except (ValueError, TypeError):
        batch_size = 2

    batch_size = max(1, min(batch_size, 4))

    batches = [
        selected_findings[index:index + batch_size]
        for index in range(
            0,
            len(selected_findings),
            batch_size,
        )
    ]

    merged_details: list[
        dict[str, Any]
    ] = []

    merged_priorities: list[
        dict[str, Any]
    ] = []

    summaries: list[str] = []

    provider_name = "External AI"

    # =====================================================
    # ميزانية زمنية كلية
    # =====================================================
    #
    # المهلة على كل استدعاء وحده لا تكفي: خمس دفعات × عشرين ثانية
    # تساوي مئة ثانية، وقد تتجاوز مهلة Gunicorn إن أضيف إليها زمن
    # الفحص نفسه. لذلك تُفرض ميزانية كلية: عند تجاوزها تتوقف الدفعات
    # المتبقية ويكمل التحليل المحلي عملها.
    #
    # المبدأ: استجابة جزئية سريعة أفضل من انهيار العامل بالكامل.

    try:
        ai_time_budget = float(
            os.environ.get("CYBERLENS_AI_TIME_BUDGET", "45")
        )
    except (ValueError, TypeError):
        ai_time_budget = 60.0

    started_at = time.monotonic()

    for batch_index, batch in enumerate(
        batches,
        start=1,
    ):
        elapsed = time.monotonic() - started_at

        if elapsed > ai_time_budget:
            print(
                "[CyberLens AI] تجاوز الميزانية الزمنية",
                f"({elapsed:.0f}ث من {ai_time_budget:.0f}ث)",
                "— إيقاف الدفعات المتبقية:",
                len(batches) - batch_index + 1,
            )
            break

        # =====================================================
        # تباعد بين الدفعات
        # =====================================================
        #
        # حد Groq المجاني يُحسب على نافذة دقيقة واحدة. وإرسال الدفعات
        # متتالية بلا تباعد يستنفد الحد فتُرفض البقية بالرمز 413.
        #
        # تأخير قصير بين الدفعات يوزّع الاستهلاك على النافذة الزمنية
        # فتنجح أغلب الدفعات بدل أن تفشل معًا.
        if batch_index > 1:
            time.sleep(_batch_delay())

        batch_result = None

        # =====================================================
        # Groq
        # =====================================================
        try:
            try:
                from .groq_ai_provider import try_groq_ai
            except Exception:
                from groq_ai_provider import try_groq_ai

            batch_result = try_groq_ai(
                findings=batch,
                target_name=target_name,
                scan_type=scan_type,
                build_ai_payload=build_ai_payload,
                build_external_instructions=build_external_instructions,
                extract_json_object=extract_json_object,
            )

            if batch_result:
                provider_name = "Groq"

        except Exception as exc:
            error_text = str(exc)

            print(
                "[CyberLens AI] Groq batch failed:",
                batch_index,
                str(type(exc)),
                error_text[:300],
            )

            # عند Rate Limit لا نحاول إرسال
            # دفعات Groq إضافية.
            if (
                "429" in error_text
                or "rate_limit" in error_text.lower()
                or "rate limit" in error_text.lower()
                or "tokens per day" in error_text.lower()
            ):
                print(
                    "[CyberLens AI] Groq rate limit detected. "
                    "Stopping external analysis."
                )
                return None

        # =====================================================
        # Gemini fallback
        # =====================================================
        if not batch_result:
            try:
                try:
                    from .gemini_ai_provider import try_gemini_ai
                except Exception:
                    from gemini_ai_provider import try_gemini_ai

                batch_result = try_gemini_ai(
                    findings=batch,
                    target_name=target_name,
                    scan_type=scan_type,
                    build_ai_payload=build_ai_payload,
                    build_external_instructions=build_external_instructions,
                    extract_json_object=extract_json_object,
                )

                if batch_result:
                    provider_name = "Gemini"

            except Exception as exc:
                print(
                    "[CyberLens AI] Gemini batch failed:",
                    batch_index,
                    str(type(exc)),
                    str(exc)[:300],
                )

        # =====================================================
        # Merge this batch
        # =====================================================
        if not batch_result:
            print(
                "[CyberLens AI] Batch failed:",
                batch_index,
                "/",
                len(batches),
            )
            continue

        summary = safe_text(
            batch_result.get(
                "summary"
            )
        )

        if summary:
            summaries.append(
                summary
            )

        batch_priorities = (
            clean_external_priority_order(
                batch_result.get(
                    "priority_order"
                )
            )
        )

        if batch_priorities:
            merged_priorities.extend(
                batch_priorities
            )

        batch_details = (
            clean_external_detailed_analysis(
                batch_result.get(
                    "detailed_analysis"
                )
            )
        )

        if batch_details:
            merged_details.extend(
                batch_details
            )

    # =====================================================
    # لا يوجد تحليل خارجي صالح
    # =====================================================
    if not merged_details:
        return None

    # =====================================================
    # De-duplicate detailed analysis
    # =====================================================
    unique_details: list[
        dict[str, Any]
    ] = []

    seen_ids: set[str] = set()

    for item in merged_details:
        finding_id = safe_text(
            item.get(
                "finding_id"
            )
        )

        if not finding_id:
            continue

        if finding_id in seen_ids:
            continue

        seen_ids.add(
            finding_id
        )

        unique_details.append(
            item
        )

    # =====================================================
    # De-duplicate priorities
    # =====================================================
    unique_priorities: list[
        dict[str, Any]
    ] = []

    seen_priority_ids: set[str] = set()

    for item in merged_priorities:
        finding_id = safe_text(
            item.get(
                "finding_id"
            )
        )

        if not finding_id:
            continue

        if finding_id in seen_priority_ids:
            continue

        seen_priority_ids.add(
            finding_id
        )

        unique_priorities.append(
            item
        )

    unique_priorities = (
        unique_priorities[:10]
    )

    return {
        "mode": "external",
        "provider": provider_name,
        "summary": (
            "تم تحليل النتائج الخارجية "
            f"باستخدام {provider_name} "
            "مع ربط التحليل بمعرف كل نتيجة."
            + (
                " "
                + summaries[0]
                if summaries
                else ""
            )
        ),
        "priority_order":
            unique_priorities,
        "detailed_analysis":
            unique_details,
    }
# =========================================================
# الدالة الرئيسية
# =========================================================

def merge_external_analysis(
    local_analysis: dict[str, Any],
    external_analysis: dict[str, Any],
) -> dict[str, Any]:
    """
    دمج التحليل المحلي مع التحليل الخارجي.

    مبدأ الدمج: التحليل الخارجي يُثري ولا يستبدل.

        الحقول الإحصائية — عدد النتائج وتوزيع الخطورة وأعلى مستوى —
        تبقى من التحليل المحلي دائمًا، لأنها محسوبة من نتائج الفحص
        نفسها لا مستنتجة من نموذج لغوي. أي خطأ فيها ينعكس مباشرة على
        درجة الأمان.

        أما الحقول الوصفية — الملخص والشرح والتوصيات — فتُؤخذ من
        التحليل الخارجي عند توفرها، لأن صياغته أوضح وأكثر ارتباطًا
        بالسياق.

    ملاحظة: كانت هذه الدالة مستدعاة في نهاية explain_findings_with_ai
    دون أن تُكتب. ولم يظهر الخطأ سابقًا لأن المسار كان يتوقف قبلها عند
    شرط فشل التحليل الخارجي — فبقي عطلًا كامنًا حتى نجح الاستدعاء فعلًا.
    """
    merged = dict(local_analysis)

    merged["mode"] = "external"
    merged["provider"] = external_analysis.get(
        "provider",
        "External AI",
    )

    if external_analysis.get("model"):
        merged["model"] = external_analysis["model"]

    # الملخص: يُقدَّم الخارجي عند وجوده
    external_summary = safe_text(
        external_analysis.get("summary")
    )
    if external_summary:
        merged["summary"] = external_summary

    # =====================================================
    # التحليل التفصيلي: دمج على مستوى كل نتيجة
    # =====================================================
    #
    # المشكلة التي يعالجها هذا الدمج:
    #
    #   الاستبدال الكامل كان يُفقد ستة حقول ينتجها التحليل المحلي ولا
    #   يُرجعها الذكاء الخارجي: درجة الخطورة الرقمية، واسم الملف،
    #   ورقم السطر، واسم الحزمة وإصدارها المثبّت والمُصلَح.
    #
    #   والأثر أن بطاقة الثغرة تظهر أقل اكتمالًا في الوضع الخارجي منها
    #   في الوضع المحلي — رغم أن الخارجي يُفترض أن يكون أغنى.
    #
    # الحل: لكل نتيجة، تُؤخذ الحقول الوصفية من الخارجي عند وجودها،
    # وتبقى الحقول الواقعية (الملف، السطر، الحزمة) من المحلي دائمًا
    # لأنها مستخرجة من الفحص لا مستنتجة من نموذج لغوي.

    external_details = external_analysis.get("detailed_analysis")

    if isinstance(external_details, list) and external_details:
        local_details = merged.get("detailed_analysis") or []

        # فهرسة النتائج المحلية بمعرّفها لسرعة المطابقة
        local_by_id: dict[str, dict[str, Any]] = {}
        for item in local_details:
            if isinstance(item, dict):
                key = safe_text(item.get("finding_id"))
                if key:
                    local_by_id[key] = item

        # الحقول الواقعية التي لا يجوز أن يمسّها النموذج
        factual_fields = (
            "severity_score",
            "package",
            "installed_version",
            "fixed_version",
            "file",
            "project_file",
            "line",
            "snippet",
        )

        combined: list[dict[str, Any]] = []

        for external_item in external_details:
            if not isinstance(external_item, dict):
                continue

            finding_id = safe_text(external_item.get("finding_id"))
            local_item = local_by_id.get(finding_id, {})

            entry = dict(local_item)

            # الحقول الوصفية من الخارجي عند وجود قيمة فعلية
            for key, value in external_item.items():
                if key in factual_fields:
                    continue
                if value not in (None, "", [], {}):
                    entry[key] = value

            # استرجاع الحقول الواقعية من المحلي
            for key in factual_fields:
                if key in local_item and local_item[key] not in (None, ""):
                    entry[key] = local_item[key]

            combined.append(entry)

        # إلحاق النتائج المحلية التي لم يحلّلها الخارجي — قد يكون
        # تجاوزها بسبب سقف عدد النتائج أو الميزانية الزمنية.
        analyzed_ids = {
            safe_text(item.get("finding_id"))
            for item in combined
        }

        for item in local_details:
            if not isinstance(item, dict):
                continue
            if safe_text(item.get("finding_id")) not in analyzed_ids:
                combined.append(item)

        if combined:
            merged["detailed_analysis"] = combined

    # ترتيب الأولويات: يُقدَّم الخارجي عند وجوده
    external_priorities = external_analysis.get("priority_order")
    if isinstance(external_priorities, list) and external_priorities:
        merged["priority_order"] = external_priorities

    # الارتباطات: تُدمَج بدل الاستبدال لأن المحلي يكتشف أنماطًا
    # تعتمد على تكرار النتائج، والخارجي يكتشف علاقات سياقية.
    external_correlations = external_analysis.get("correlations")
    if isinstance(external_correlations, list) and external_correlations:
        local_correlations = merged.get("correlations") or []
        merged["correlations"] = (
            list(local_correlations) + list(external_correlations)
        )[:10]

    return merged


def explain_findings_with_ai(
    findings: list[dict[str, Any]],
    target_name: str = "Unknown Target",
    scan_type: str = "general",
) -> dict[str, Any]:
    """
    تحليل نتائج الفحص.

    المسار:
    1. تحليل محلي دائمًا.
    2. محاولة AI خارجي فقط عند وجود:
       OPENAI_API_KEY
       OPENAI_MODEL
    3. في أي فشل نعود للتحليل المحلي.
    """

    if not isinstance(
        findings,
        list,
    ):
        findings = []

    clean_scan_type = normalize_scan_type(
        scan_type
    )

    local_analysis = build_local_analysis(
        findings=findings,
        target_name=target_name,
        scan_type=clean_scan_type,
    )
    external_analysis = try_external_ai(
        findings=findings,
        target_name=target_name,
        scan_type=clean_scan_type,
    )

    if not external_analysis:
        return local_analysis

    return merge_external_analysis(
        local_analysis=local_analysis,
        external_analysis=external_analysis,
    )


# =========================================================
# اختبار مباشر
# =========================================================

if __name__ == "main":
    demo_findings = [
        {
            "id": "CL-PY-001",
            "title": "استخدام eval()",
            "severity": "high",
            "description": (
                "تم اكتشاف استخدام eval في الكود."
            ),
            "recommendation": (
                "استبدل التنفيذ الديناميكي "
                "بمنطق صريح وآمن."
            ),
        },
        {
            "id": "CL-SECRET-001",
            "title": "كلمة مرور ثابتة داخل الكود",
            "severity": "high",
            "description": (
                "تم اكتشاف قيمة حساسة محتملة."
            ),
            "recommendation": (
                "انقل السر إلى متغيرات البيئة "
                "وقم بتدويره عند الحاجة."
            ),
        },
    ]

    result = explain_findings_with_ai(
        findings=demo_findings,
        target_name="demo.py",
        scan_type="code",
    )

    print(
        json.dumps(
            result,
            ensure_ascii=False,
            indent=2,
        )
    )
