from __future__ import annotations

from typing import Any


# =========================================================
# أوزان مستويات الخطورة
# =========================================================
#
# كل ثغرة تخصم نقاطًا من درجة الأمان.
#
# Critical = أخطر مستوى
# High     = خطورة عالية
# Medium   = خطورة متوسطة
# Low      = خطورة منخفضة
# Info     = ملاحظة فقط
#
# =========================================================

SEVERITY_WEIGHTS: dict[str, float] = {
    "critical": 30.0,
    "high": 15.0,
    "medium": 7.0,
    "low": 3.0,
    "info": 0.5,
}


# =========================================================
# ترتيب مستويات الخطورة
# =========================================================

SEVERITY_RANK: dict[str, int] = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
    "none": 0,
}


# =========================================================
# أسماء عربية
# =========================================================

SEVERITY_ARABIC: dict[str, str] = {
    "critical": "حرجة",
    "high": "عالية",
    "medium": "متوسطة",
    "low": "منخفضة",
    "info": "معلوماتية",
    "none": "آمن",
}


# =========================================================
# تنظيف مستوى الخطورة
# =========================================================

def normalize_severity(value: Any) -> str:
    """
    توحيد قيمة مستوى الخطورة.

    مثال:
        HIGH  -> high
        High  -> high
        حرج   -> critical
    """

    if value is None:
        return "low"

    severity = str(value).strip().lower()

    aliases = {
        "critical": "critical",
        "crit": "critical",
        "حرجة": "critical",
        "حرج": "critical",

        "high": "high",
        "عالية": "high",
        "عالي": "high",

        "medium": "medium",
        "moderate": "medium",
        "متوسطة": "medium",
        "متوسط": "medium",

        "low": "low",
        "منخفضة": "low",
        "منخفض": "low",

        "info": "info",
        "informational": "info",
        "معلوماتية": "info",
        "معلومة": "info",
    }

    return aliases.get(severity, "low")


# =========================================================
# إنشاء عدادات الخطورة
# =========================================================

def empty_severity_counts() -> dict[str, int]:
    """
    إنشاء عدادات فارغة لمستويات الخطورة.
    """

    return {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }


# =========================================================
# حساب أعداد الثغرات
# =========================================================

def count_severities(
    findings: list[dict[str, Any]],
) -> dict[str, int]:
    """
    حساب عدد النتائج في كل مستوى خطورة.
    """

    counts = empty_severity_counts()

    for finding in findings:
        severity = normalize_severity(
            finding.get("severity")
        )

        counts[severity] += 1

    return counts


# =========================================================
# تحديد أعلى مستوى خطورة
# =========================================================

def get_highest_severity(
    severity_counts: dict[str, int],
) -> str:
    """
    إرجاع أعلى مستوى خطورة موجود فعليًا.
    """

    order = [
        "critical",
        "high",
        "medium",
        "low",
        "info",
    ]

    for severity in order:
        if severity_counts.get(severity, 0) > 0:
            return severity

    return "none"


# =========================================================
# حساب الخصم الأساسي
# =========================================================

def calculate_base_penalty(
    severity_counts: dict[str, int],
) -> float:
    """
    حساب مجموع نقاط الخصم الأساسية.
    """

    penalty = 0.0

    for severity, count in severity_counts.items():
        weight = SEVERITY_WEIGHTS.get(severity, 0.0)

        penalty += count * weight

    return penalty


# =========================================================
# تطبيق عقوبة إضافية للمخاطر المركبة
# =========================================================
def calculate_compound_risk_penalty(
    severity_counts: dict[str, int],
) -> float:
    """
    إضافة خصم إضافي عندما تجتمع مخاطر خطيرة متعددة.

    الهدف:
    عدم التعامل مع مجموعة ثغرات حرجة وعالية
    وكأنها مجرد مجموع بسيط فقط.
    """

    extra_penalty = 0.0

    critical_count = severity_counts.get("critical", 0)
    high_count = severity_counts.get("high", 0)
    medium_count = severity_counts.get("medium", 0)

    # وجود أكثر من ثغرة حرجة
    if critical_count >= 2:
        extra_penalty += 10.0

    # اجتماع Critical مع High
    if critical_count >= 1 and high_count >= 1:
        extra_penalty += 7.0

    # وجود عدد كبير من High
    if high_count >= 3:
        extra_penalty += 7.0

    # وجود عدد كبير من Medium
    if medium_count >= 5:
        extra_penalty += 5.0

    return extra_penalty


# =========================================================
# حساب درجة الأمان
# =========================================================

def calculate_raw_score(
    severity_counts: dict[str, int],
) -> int:
    """
    حساب Security Score من 0 إلى 100.
    """

    base_penalty = calculate_base_penalty(
        severity_counts
    )

    compound_penalty = calculate_compound_risk_penalty(
        severity_counts
    )

    total_penalty = base_penalty + compound_penalty

    score = 100.0 - total_penalty

    # منع النتيجة من تجاوز الحدود
    score = max(0.0, min(100.0, score))

    return round(score)


# =========================================================
# تحديد مستوى الخطر
# =========================================================

def get_risk_level(
    score: int,
    highest_severity: str,
) -> str:
    """
    تحديد مستوى الخطر العام.

    يتم الاعتماد على:
    1. Security Score
    2. أعلى ثغرة موجودة
    """

    if highest_severity == "critical":
        return "critical"

    if score <= 39:
        return "critical"

    if highest_severity == "high":
        return "high"

    if score <= 59:
        return "high"

    if highest_severity == "medium":
        return "medium"

    if score <= 79:
        return "medium"

    if highest_severity == "low":
        return "low"

    if score <= 94:
        return "low"

    return "safe"


# =========================================================
# وصف عربي لمستوى الخطر
# =========================================================

def get_risk_label_arabic(
    risk_level: str,
) -> str:
    """
    تحويل مستوى الخطر إلى نص عربي.
    """

    labels = {
        "critical": "حرج",
        "high": "عالي",
        "medium": "متوسط",
        "low": "منخفض",
        "safe": "آمن",
    }

    return labels.get(risk_level, "غير معروف")


# =========================================================
# وصف حالة درجة الأمان
# =========================================================

def get_score_status(
    score: int,
) -> str:
    """
    إرجاع وصف مختصر للدرجة.
    """

    if score >= 95:
        return "ممتاز"

    if score >= 80:
        return "جيد"

    if score >= 60:
        return "متوسط"

    if score >= 40:
        return "ضعيف"

    return "خطر"


# =========================================================
# إنشاء توصية عامة
# =========================================================

def generate_general_recommendation(
    severity_counts: dict[str, int],
    highest_severity: str,
) -> str:
    """
    إنشاء توصية عامة تظهر في Dashboard.
    """

    critical_count = severity_counts.get("critical", 0)
    high_count = severity_counts.get("high", 0)
    medium_count = severity_counts.get("medium", 0)
    low_count = severity_counts.get("low", 0)

    if critical_count > 0:
        return (
            "تم اكتشاف ثغرات حرجة تتطلب معالجة فورية. "
            "ينصح بإيقاف نشر المكون المتأثر مؤقتًا، "
            "مراجعة تفاصيل النتائج، تطبيق الإصلاحات الأمنية، "
            "ثم إعادة الفحص للتحقق من نجاح المعالجة."
        )
    if high_count > 0:
        return (
            "تم اكتشاف مخاطر عالية الخطورة. "
            "ينصح بمعالجتها بأولوية مرتفعة، "
            "وتحديث المكونات المتأثرة أو تعديل الكود غير الآمن، "
            "ثم إجراء فحص جديد بعد الإصلاح."
        )

    if medium_count > 0:
        return (
            "توجد مخاطر متوسطة تحتاج إلى مراجعة ومعالجة منظمة. "
            "ينصح بترتيب النتائج حسب التأثير، "
            "وتطبيق التوصيات الأمنية قبل الانتقال إلى بيئة الإنتاج."
        )

    if low_count > 0:
        return (
            "الوضع الأمني جيد بشكل عام، "
            "مع وجود ملاحظات منخفضة الخطورة. "
            "ينصح بمعالجتها ضمن دورة الصيانة القادمة "
            "واتباع أفضل ممارسات التطوير الآمن."
        )

    return (
        "لم يتم اكتشاف مخاطر أمنية واضحة في نطاق الفحص الحالي. "
        "استمر في تحديث المكونات، مراجعة الإعدادات، "
        "وإجراء فحوصات أمنية دورية."
    )


# =========================================================
# الدالة الرئيسية
# =========================================================

def calculate_security_score(
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    """
    الدالة الرئيسية التي يستخدمها app.py.

    تستقبل:
        قائمة النتائج الأمنية

    وتعيد:
        score
        highest_severity
        severity_counts
        risk_level
        risk_label_ar
        status
        recommendation
    """

    if not isinstance(findings, list):
        findings = []

    severity_counts = count_severities(findings)

    highest_severity = get_highest_severity(
        severity_counts
    )

    score = calculate_raw_score(
        severity_counts
    )

    risk_level = get_risk_level(
        score=score,
        highest_severity=highest_severity,
    )

    recommendation = generate_general_recommendation(
        severity_counts=severity_counts,
        highest_severity=highest_severity,
    )

    return {
        "score": score,

        "highest_severity": highest_severity,

        "highest_severity_ar": SEVERITY_ARABIC.get(
            highest_severity,
            "غير معروف",
        ),

        "severity_counts": severity_counts,

        "risk_level": risk_level,

        "risk_label_ar": get_risk_label_arabic(
            risk_level
        ),

        "status": get_score_status(
            score
        ),

        "recommendation": recommendation,

        "total_findings": sum(
            severity_counts.values()
        ),
    }


# =========================================================
# اختبار سريع عند تشغيل الملف مباشرة
# =========================================================

if __name__ == "main":
    demo_findings = [
        {
            "severity": "high",
            "title": "مثال High",
        },
        {
            "severity": "medium",
            "title": "مثال Medium",
        },
        {
            "severity": "low",
            "title": "مثال Low",
        },
    ]

    result = calculate_security_score(
        demo_findings
    )

    print("=" * 50)
    print("CyberLens Security Score Test")
    print("=" * 50)
    print(f"Score: {result['score']}/100")
    print(
        f"Highest Severity: "
        f"{result['highest_severity']}"
    )
    print(
        f"Risk Level: "
        f"{result['risk_level']}"
    )
    print(
        f"Total Findings: "
        f"{result['total_findings']}"
    )
    print("=" * 50)