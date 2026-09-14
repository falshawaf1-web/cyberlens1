"""
offline_vuln_db.py
=========================================================
قاعدة ثغرات محلية احتياطية لفحص المكتبات.

المشكلة التي يحلّها هذا الملف:
    ماسح المكتبات كان يعتمد 100% على api.osv.dev. عند فشل
    الاتصال — حجب شبكة، تجاوز حد الطلبات، مهلة على Render،
    جدار ناري جامعي — كان يرجع:

        success: True, findings: []

    أي أن الأداة تعلن "لا توجد ثغرات" بينما الحقيقة "لم أستطع
    الفحص". هذا أخطر من الفشل الصريح، لأن المستخدم يبني قرارًا
    على معلومة كاذبة.

الحل المطبَّق هنا مبدأ أمني أساسي: **الفشل الآمن (Fail Safe)**.
    1. قاعدة محلية مختصرة تغطي أشهر الثغرات في مكتبات شائعة.
    2. عند فشل OSV: يعمل الفحص المحلي ويُعلَن الفشل صراحةً.
    3. لا يُقال أبدًا "نظيف" ما لم يكتمل الفحص فعلًا.

حدود هذه القاعدة — تُذكر صراحةً للأمانة العلمية:
    هذه ليست بديلًا عن OSV. عيّنة تعليمية محدودة تغطي أشهر
    الثغرات في أكثر المكتبات استخدامًا. تُستخدم كشبكة أمان عند
    تعذّر الوصول للمصدر الرسمي، ويجب أن يُعلَم المستخدم بذلك.

مصدر البيانات: استشارات GitHub Advisory و NVD العلنية.
"""

from __future__ import annotations

from typing import Any


# =========================================================
# قاعدة الثغرات المحلية
# =========================================================
#
# البنية: اسم الحزمة -> قائمة ثغرات
#   introduced : أول إصدار مصاب (شامل)
#   fixed      : أول إصدار سليم (غير شامل)
#   المدى المصاب: introduced <= version < fixed

OFFLINE_VULN_DB: dict[str, list[dict[str, Any]]] = {

    # ------------------------------------------------ Python
    "requests": [
        {
            "id": "GHSA-j8r2-6x86-q33q", "cve": "CVE-2023-32681",
            "introduced": "2.3.0", "fixed": "2.31.0", "severity": "medium",
            "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "summary": "تسريب ترويسة Proxy-Authorization عند إعادة التوجيه إلى مضيف آخر.",
        },
        {
            "id": "GHSA-9wx4-h78v-vm56", "cve": "CVE-2024-35195",
            "introduced": "2.0.0", "fixed": "2.32.0", "severity": "medium",
            "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N",
            "summary": "تعطيل التحقق من الشهادة يبقى ساريًا على الطلبات اللاحقة في نفس الجلسة.",
        },
    ],

    "urllib3": [
        {
            "id": "GHSA-g4mx-q9vg-27p4", "cve": "CVE-2023-45803",
            "introduced": "1.26.0", "fixed": "1.26.18", "severity": "medium",
            "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "summary": "الإبقاء على جسم الطلب عند إعادة التوجيه بتغيير الطريقة إلى GET.",
        },
        {
            "id": "GHSA-v845-jxx5-vc9f", "cve": "CVE-2023-43804",
            "introduced": "1.0.0", "fixed": "1.26.17", "severity": "high",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "summary": "تسريب ملف ارتباط Cookie عبر إعادة التوجيه لنطاق مختلف.",
        },
    ],

    "flask": [
        {
            "id": "GHSA-m2qf-hxjv-5gpq", "cve": "CVE-2023-30861",
            "introduced": "0.1", "fixed": "2.2.5", "severity": "high",
            "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "summary": "تسريب ملف ارتباط الجلسة عبر التخزين المؤقت للوكيل (Proxy Cache).",
        },
    ],

    "django": [
        {
            "id": "GHSA-qmf9-6jqf-j8fq", "cve": "CVE-2023-31047",
            "introduced": "3.2.0", "fixed": "3.2.19", "severity": "high",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
            "summary": "تجاوز التحقق من رفع الملفات المتعددة.",
        },
        {
            "id": "GHSA-9jmf-237g-qf46", "cve": "CVE-2024-27351",
            "introduced": "4.2.0", "fixed": "4.2.11", "severity": "medium",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
            "summary": "حرمان من الخدمة عبر تعبير نمطي في دالة truncatewords_html.",
        },
    ],

    "jinja2": [
        {
            "id": "GHSA-h5c8-rqwp-cp95", "cve": "CVE-2024-22195",
            "introduced": "2.0", "fixed": "3.1.3", "severity": "medium",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
            "summary": "حقن HTML عبر سمة xmlattr غير المعقّمة.",
        },
    ],

    "pyyaml": [
        {
            "id": "GHSA-8q59-q68h-6hv4", "cve": "CVE-2020-14343",
            "introduced": "0.0", "fixed": "5.4", "severity": "critical",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "summary": "تنفيذ كود عشوائي عبر yaml.load بدون محمّل آمن.",
        },
    ],

    "cryptography": [
        {
            "id": "GHSA-v8gr-m533-ghj9", "cve": "CVE-2023-49083",
            "introduced": "3.1", "fixed": "41.0.6", "severity": "high",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
            "summary": "انهيار العملية عند تحميل شهادة PKCS7 تالفة.",
        },
    ],

    "werkzeug": [
        {
            "id": "GHSA-2g68-c3qc-8985", "cve": "CVE-2023-25577",
            "introduced": "0.1", "fixed": "2.2.3", "severity": "high",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
            "summary": "استنزاف الموارد عبر طلب متعدد الأجزاء بعدد حقول ضخم.",
        },
    ],

    "pillow": [
        {
            "id": "GHSA-3f63-hfp8-52jq", "cve": "CVE-2023-50447",
            "introduced": "0.0", "fixed": "10.2.0", "severity": "high",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
            "summary": "تنفيذ كود عشوائي عبر وسم ImageMath.eval.",
        },
    ],

    "sqlalchemy": [
        {
            "id": "GHSA-3jvg-9v3v-6cwv", "cve": "CVE-2019-7548",
            "introduced": "0.0", "fixed": "1.3.0", "severity": "high",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            "summary": "حقن SQL عبر معامل order_by غير المعقّم.",
        },
    ],

    # ------------------------------------------------ JavaScript
    "lodash": [
        {
            "id": "GHSA-p6mc-m468-83gg", "cve": "CVE-2020-8203",
            "introduced": "0.0.0", "fixed": "4.17.20", "severity": "high",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H",
            "summary": "تلويث النموذج الأولي (Prototype Pollution) في دالة zipObjectDeep.",
        },
    ],

    "axios": [
        {
            "id": "GHSA-wf5p-g6vw-rhxx", "cve": "CVE-2023-45857",
            "introduced": "0.8.1", "fixed": "1.6.0", "severity": "medium",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "summary": "تسريب رمز CSRF إلى مضيفين خارجيين.",
        },
    ],

    "express": [
        {
            "id": "GHSA-rv95-896h-c2vc", "cve": "CVE-2024-29041",
            "introduced": "0.0.0", "fixed": "4.19.2", "severity": "medium",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
            "summary": "إعادة توجيه مفتوحة عبر دالة response.location.",
        },
    ],

    "minimist": [
        {
            "id": "GHSA-xvch-5gv4-984h", "cve": "CVE-2021-44906",
            "introduced": "0.0.0", "fixed": "1.2.6", "severity": "critical",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "summary": "تلويث النموذج الأولي يؤدي لتنفيذ كود.",
        },
    ],

    "jsonwebtoken": [
        {
            "id": "GHSA-27h2-hvpr-p74q", "cve": "CVE-2022-23540",
            "introduced": "0.0.0", "fixed": "9.0.0", "severity": "high",
            "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
            "summary": "تجاوز التحقق من التوقيع عند إعدادات افتراضية ضعيفة.",
        },
    ],
}


# =========================================================
# مقارنة الإصدارات
# =========================================================

def _parse_version(version: str) -> tuple:
    """
    تحويل نص الإصدار إلى صف قابل للمقارنة.

    تنفيذ مبسّط ومقصود: يتجاهل لواحق ما قبل الإصدار (rc، beta) ويقارن
    الأجزاء الرقمية فقط. كافٍ لغرض المقارنة هنا، ومكتوب صراحةً بدل
    استيراد packaging لتفادي اعتمادية إضافية قد لا تكون مثبّتة.
    """
    cleaned = str(version).strip().lstrip("vV")

    for separator in ("-", "+", "rc", "a", "b"):
        if separator in cleaned:
            cleaned = cleaned.split(separator)[0]

    parts = []
    for chunk in cleaned.split("."):
        digits = "".join(ch for ch in chunk if ch.isdigit())
        parts.append(int(digits) if digits else 0)

    while len(parts) < 4:
        parts.append(0)

    return tuple(parts[:4])


def _in_range(version: str, introduced: str, fixed: str) -> bool:
    """هل الإصدار ضمن المدى المصاب [introduced, fixed) ؟"""
    try:
        current = _parse_version(version)
        return _parse_version(introduced) <= current < _parse_version(fixed)
    except Exception:
        return False


# =========================================================
# الفحص المحلي
# =========================================================

def scan_packages_offline(packages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    فحص قائمة حزم مقابل القاعدة المحلية.

    تُرجع نتائج بنفس بنية نتائج OSV حتى تندمج في الواجهة دون تعديل،
    مع تعليم المصدر بوضوح في حقل metadata.source.
    """
    findings: list[dict[str, Any]] = []

    for package in packages:
        if not isinstance(package, dict):
            continue

        name = str(package.get("name") or "").strip().lower()
        version = str(package.get("version") or "").strip()

        if not name or not version:
            continue

        for vulnerability in OFFLINE_VULN_DB.get(name, []):
            if not _in_range(version, vulnerability["introduced"], vulnerability["fixed"]):
                continue

            findings.append(
                {
                    "id": f"CL-DEP-VULN-{name}-{vulnerability['cve']}",
                    "title": f"{name} {version} — {vulnerability['cve']}",
                    "severity": vulnerability["severity"],
                    "description": vulnerability["summary"],
                    "recommendation": (
                        f"حدّث {name} إلى الإصدار {vulnerability['fixed']} أو أحدث."
                    ),
                    "package": name,
                    "installed_version": version,
                    "fixed_version": vulnerability["fixed"],
                    "cve": vulnerability["cve"],
                    "cvss_vector": vulnerability["cvss_vector"],
                    "ecosystem": package.get("ecosystem", "PyPI"),
                    "source": "CyberLens Offline DB",
                    "metadata": {
                        "advisory_id": vulnerability["id"],
                        "source": "offline_db",
                        "note": (
                            "من القاعدة المحلية الاحتياطية — تعذّر الوصول إلى OSV. "
                            "التغطية محدودة؛ أعد الفحص عند توفر الاتصال."
                        ),
                    },
                }
            )

    return findings


def build_unavailable_notice(reason: str, packages_count: int) -> dict[str, Any]:
    """
    بناء تحذير صريح عند تعذّر الوصول إلى OSV.

    هذا التحذير هو جوهر الإصلاح: بدونه يظهر الفحص الفاشل كفحص ناجح
    بلا ثغرات. وجوده يحوّل "نتيجة كاذبة" إلى "معلومة صادقة عن حدود
    الفحص" — وهو فرق جوهري في أداة أمنية.
    """
    return {
        "id": "CL-DEP-OSV-UNAVAILABLE",
        "title": "تعذّر الوصول إلى قاعدة الثغرات الرسمية (OSV)",
        "severity": "info",
        "description": (
            f"تم تحليل {packages_count} حزمة محليًا، لكن الاستعلام من قاعدة "
            f"OSV فشل ({reason}). النتائج المعروضة من القاعدة المحلية "
            "الاحتياطية فقط، وتغطيتها محدودة. "
            "غياب النتائج هنا لا يعني خلوّ المشروع من الثغرات."
        ),
        "recommendation": (
            "تحقق من اتصال الخادم بالإنترنت ومن السماح بالوصول إلى "
            "api.osv.dev، ثم أعد الفحص للحصول على تغطية كاملة."
        ),
        "source": "CyberLens",
        "metadata": {"reason": reason, "packages_analyzed": packages_count},
    }


def database_stats() -> dict[str, Any]:
    """إحصاءات القاعدة المحلية — للتوثيق والعرض."""
    total = sum(len(items) for items in OFFLINE_VULN_DB.values())

    return {
        "packages_covered": len(OFFLINE_VULN_DB),
        "advisories_total": total,
        "ecosystems": ["PyPI", "npm"],
        "note": "قاعدة احتياطية محدودة — المصدر الأساسي يبقى api.osv.dev",
    }
