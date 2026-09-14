"""
cvss_mapper_ext.py
=========================================================
امتداد متجهات CVSS v3.1 للقواعد غير المغطّاة في cvss_mapper.py

المشكلة التي يحلّها هذا الملف:
    cvss_mapper.py الأصلي غطّى قواعد فحص الكود فقط (21 قاعدة).
    باقي الماسحات كانت تحصل على درجة احتياطية مشتقّة من مستوى
    الخطورة النصي، فتظهر ثغرات مختلفة تمامًا بنفس الدرجة (6.5،
    6.5، 6.5) — وهذا يكشف فورًا أن الدرجة ليست CVSS حقيقيًا.

القواعد المغطّاة هنا (31 قاعدة):
    CL-URL-001 .. CL-URL-014      ماسح الروابط
    CL-URL-H001 .. CL-URL-H009    ترويسات الأمان
    CL-URL-W000                   تحذير الوصول
    CL-ADV-*                      الماسح المتقدم
    CL-DEP-*                      المكتبات والتبعيات

مبدأ اشتقاق المتجهات:
    كل متجه محدد يدويًا بناءً على طبيعة الثغرة، لا مولّد آليًا.
    المبرر مكتوب في حقل "rationale" بجانب كل متجه ليكون قابلًا
    للمراجعة والنقد في المناقشة — وهذا أهم من الرقم نفسه.

    ملاحظة منهجية مهمة: غياب ترويسة أمان ليس ثغرة قائمة بذاتها،
    بل ضعف في التحصين (Hardening) يزيد أثر ثغرة أخرى. لذلك
    مُنحت متجهات منخفضة بـ AC:H (تعقيد مرتفع) لأن استغلالها
    يتطلب وجود ثغرة ثانية — وهذا أدقّ من منحها High اعتباطًا.
"""

from __future__ import annotations

from typing import Any


# =========================================================
# 1. ماسح الروابط — تحليل بنية الرابط
# =========================================================

URL_VECTORS: dict[str, dict[str, str]] = {

    "CL-URL-001": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
        "cwe": "CWE-1021 (Improper Restriction of Rendered UI Layers)",
        "owasp": "A05:2021 - Security Misconfiguration",
        "rationale": (
            "غياب بروتوكول صريح في الرابط. لا يُستغل مباشرة، لكنه قد يؤدي "
            "لاتصال غير مشفّر عند التحويل التلقائي — أثر محدود على السرية."
        ),
    },

    "CL-URL-002": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N",
        "cwe": "CWE-319 (Cleartext Transmission of Sensitive Information)",
        "owasp": "A02:2021 - Cryptographic Failures",
        "rationale": (
            "HTTP غير مشفّر: أي وسيط على المسار يقرأ البيانات ويعدّلها. "
            "AC:H لأن الهجوم يتطلب موقعًا على مسار الشبكة (MITM)."
        ),
    },

    "CL-URL-003": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
        "cwe": "CWE-350 (Reliance on Reverse DNS Resolution)",
        "owasp": "A05:2021 - Security Misconfiguration",
        "rationale": (
            "استخدام عنوان IP بدل اسم نطاق يمنع التحقق من الشهادة بالاسم، "
            "ويُستخدم كثيرًا في البنية التحتية للتصيّد."
        ),
    },

    "CL-URL-004": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "cwe": "CWE-1007 (Insufficient Visual Distinction of Homoglyphs)",
        "owasp": "A07:2021 - Identification and Authentication Failures",
        "rationale": (
            "Punycode يسمح بنطاقات تبدو مطابقة بصريًا لنطاقات شرعية. "
            "S:C لأن الضرر يقع على المستخدم خارج النطاق المفحوص."
        ),
    },

    "CL-URL-005": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
        "cwe": "CWE-1007 (Insufficient Visual Distinction of Homoglyphs)",
        "owasp": "A05:2021 - Security Misconfiguration",
        "rationale": (
            "عدد كبير من النطاقات الفرعية نمط شائع في التصيّد لإخفاء "
            "النطاق الحقيقي خلف بادئة تبدو موثوقة."
        ),
    },

    "CL-URL-006": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
        "cwe": "CWE-1007 (Insufficient Visual Distinction of Homoglyphs)",
        "owasp": "A05:2021 - Security Misconfiguration",
        "rationale": "كثرة الشرطات في اسم النطاق مؤشر إحصائي على نطاقات التصيّد.",
    },

    "CL-URL-007": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N",
        "cwe": "CWE-522 (Insufficiently Protected Credentials)",
        "owasp": "A07:2021 - Identification and Authentication Failures",
        "rationale": (
            "علامة @ في الرابط تخفي الوجهة الحقيقية: كل ما قبلها يُعامل "
            "كبيانات مستخدم. ناقل تصيّد مباشر وفعّال."
        ),
    },

    "CL-URL-008": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
        "cwe": "CWE-20 (Improper Input Validation)",
        "owasp": "A05:2021 - Security Misconfiguration",
        "rationale": "منفذ غير اعتيادي قد يشير لخدمة إدارية مكشوفة دون قصد.",
    },

    "CL-URL-009": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
        "cwe": "CWE-116 (Improper Encoding or Escaping of Output)",
        "owasp": "A03:2021 - Injection",
        "rationale": (
            "ترميز كثيف داخل الرابط أسلوب معروف لتجاوز مرشّحات الأمان "
            "وأنظمة كشف التسلل."
        ),
    },

    "CL-URL-010": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
        "cwe": "CWE-20 (Improper Input Validation)",
        "owasp": "A05:2021 - Security Misconfiguration",
        "rationale": "طول غير معتاد للرابط يُستخدم لإخفاء الوجهة عن نظر المستخدم.",
    },

    "CL-URL-011": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
        "cwe": "CWE-200 (Exposure of Sensitive Information)",
        "owasp": "A01:2021 - Broken Access Control",
        "rationale": (
            "كلمات حساسة داخل الرابط (token، password، key) تُسجَّل في سجلات "
            "الخادم وسجل المتصفح وترويسة Referer."
        ),
    },

    "CL-URL-012": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "cwe": "CWE-918 (Server-Side Request Forgery)",
        "owasp": "A10:2021 - Server-Side Request Forgery",
        "rationale": (
            "الإشارة لعنوان محلي أو خاص مؤشر على SSRF محتمل: الخادم قد "
            "يجلب موارد من الشبكة الداخلية بناءً على مدخل المستخدم."
        ),
    },

    "CL-URL-013": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
        "cwe": "CWE-434 (Unrestricted Upload of File with Dangerous Type)",
        "owasp": "A08:2021 - Software and Data Integrity Failures",
        "rationale": (
            "رابط يشير لملف قابل للتنفيذ. الخطورة تعتمد على مصدر الملف، "
            "لذا UI:R — يحتاج المستخدم لتنزيله وتشغيله."
        ),
    },

    "CL-URL-014": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "cwe": "CWE-601 (URL Redirection to Untrusted Site)",
        "owasp": "A01:2021 - Broken Access Control",
        "rationale": (
            "إعادة توجيه مفتوحة: النطاق الموثوق يصبح منصة إطلاق للتصيّد. "
            "S:C لأن الضرر يقع خارج التطبيق المفحوص."
        ),
    },
}


# =========================================================
# 2. ترويسات الأمان — ضعف تحصين لا ثغرة قائمة بذاتها
# =========================================================
#
# كل هذه المتجهات تستخدم AC:H عمدًا. المبرر: غياب الترويسة وحده
# لا يُنتج اختراقًا — بل يزيل طبقة دفاع تحدّ من أثر ثغرة أخرى.
# استغلالها يشترط وجود ثغرة ثانية، وهذا بالضبط معنى AC:H في
# مواصفة CVSS: "شروط خارجة عن سيطرة المهاجم يجب توفرها".

HEADER_VECTORS: dict[str, dict[str, str]] = {

    "CL-URL-H001": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "cwe": "CWE-1021 (Improper Restriction of Rendered UI Layers)",
        "owasp": "A05:2021 - Security Misconfiguration",
        "rationale": (
            "غياب CSP يزيل أهم طبقة احتواء لهجمات XSS. لا يُستغل وحده، "
            "لكنه يحوّل XSS محدود الأثر إلى سيطرة كاملة على الصفحة."
        ),
    },

    "CL-URL-H002": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N",
        "cwe": "CWE-319 (Cleartext Transmission of Sensitive Information)",
        "owasp": "A02:2021 - Cryptographic Failures",
        "rationale": (
            "غياب HSTS يترك نافذة لهجوم تنزيل البروتوكول (SSL Stripping) "
            "في أول اتصال قبل التوجيه إلى HTTPS."
        ),
    },

    "CL-URL-H003": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "cwe": "CWE-1021 (Improper Restriction of Rendered UI Layers)",
        "owasp": "A05:2021 - Security Misconfiguration",
        "rationale": (
            "غياب X-Frame-Options يسمح بـ Clickjacking: تحميل الصفحة داخل "
            "إطار شفاف وخداع المستخدم للنقر على إجراءات حساسة."
        ),
    },

    "CL-URL-H004": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
        "cwe": "CWE-430 (Deployment of Wrong Handler)",
        "owasp": "A05:2021 - Security Misconfiguration",
        "rationale": (
            "غياب nosniff يسمح للمتصفح بتخمين نوع المحتوى، فقد يُنفَّذ ملف "
            "مرفوع كـ JavaScript رغم رفعه كصورة."
        ),
    },

    "CL-URL-H005": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
        "cwe": "CWE-200 (Exposure of Sensitive Information)",
        "owasp": "A05:2021 - Security Misconfiguration",
        "rationale": (
            "غياب Referrer-Policy يسرّب الرابط الكامل — بما فيه الرموز في "
            "معاملات الاستعلام — إلى مواقع خارجية."
        ),
    },

    "CL-URL-H006": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
        "cwe": "CWE-1004 (Sensitive Cookie Without HttpOnly Flag)",
        "owasp": "A05:2021 - Security Misconfiguration",
        "rationale": (
            "غياب Permissions-Policy يترك واجهات الجهاز (كاميرا، ميكروفون، "
            "موقع) متاحة لأي إطار مضمّن في الصفحة."
        ),
    },

    "CL-URL-H007": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "cwe": "CWE-200 (Exposure of Sensitive Information)",
        "owasp": "A05:2021 - Security Misconfiguration",
        "rationale": (
            "كشف إصدار الخادم في ترويسة Server يختصر مرحلة الاستطلاع: "
            "يربط المهاجم الإصدار بثغرات منشورة مباشرة. AC:L لأن القراءة "
            "لا تحتاج أي شرط."
        ),
    },

    "CL-URL-H008": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "cwe": "CWE-200 (Exposure of Sensitive Information)",
        "owasp": "A05:2021 - Security Misconfiguration",
        "rationale": "كشف تقنية التشغيل عبر X-Powered-By — نفس منطق H007.",
    },

    "CL-URL-H009": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
        "cwe": "CWE-942 (Permissive Cross-domain Policy)",
        "owasp": "A05:2021 - Security Misconfiguration",
        "rationale": (
            "CORS مفتوح بالكامل (Allow-Origin: *) مع بيانات اعتماد يسمح "
            "لأي موقع بقراءة الاستجابات المصادَق عليها. هذا استغلال مباشر "
            "لا يحتاج ثغرة أخرى — لذلك AC:L و S:C وأثر مرتفع."
        ),
    },

    "CL-URL-W000": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N",
        "cwe": "CWE-noinfo",
        "owasp": "غير مصنّف",
        "rationale": (
            "تحذير تشغيلي لا ثغرة: تعذّر الوصول للهدف. الدرجة صفر لأن "
            "الأثر معدوم — إدراجه للشفافية فقط."
        ),
    },
}


# =========================================================
# 3. الماسح المتقدم — أنماط سياقية
# =========================================================
#
# متجهات هذه القواعد أدنى قليلًا من نظيراتها في الماسح الأساسي،
# رغم أنها تصف نفس الثغرات. المبرر: الماسح المتقدم يعمل بالاستدلال
# السياقي فتزيد احتمالية الإنذار الكاذب، ويُعبَّر عن ذلك بـ AC:H.

ADVANCED_VECTORS: dict[str, dict[str, str]] = {

    "CL-ADV-SQLI-001": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-89 (SQL Injection)",
        "owasp": "A03:2021 - Injection",
        "rationale": (
            "حقن SQL مكتشف بالاستدلال السياقي. الأثر مطابق للقاعدة "
            "الأساسية، لكن AC:H يعكس الحاجة للتحقق اليدوي."
        ),
    },

    "CL-ADV-CMD-001": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "cwe": "CWE-78 (OS Command Injection)",
        "owasp": "A03:2021 - Injection",
        "rationale": (
            "حقن أوامر نظام محتمل. S:C لأن الضرر يتجاوز التطبيق إلى نظام "
            "التشغيل المستضيف."
        ),
    },

    "CL-ADV-XSS-001": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "cwe": "CWE-79 (Cross-site Scripting)",
        "owasp": "A03:2021 - Injection",
        "rationale": "XSS محتمل. S:C لأن الضرر يقع على متصفح الضحية لا الخادم.",
    },

    "CL-ADV-DESER-001": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-502 (Deserialization of Untrusted Data)",
        "owasp": "A08:2021 - Software and Data Integrity Failures",
        "rationale": (
            "فك تسلسل غير آمن محتمل. الأثر كامل لأن نجاح الاستغلال يعني "
            "تنفيذ كود قبل أي منطق تحقق."
        ),
    },

    "CL-ADV-SECRET-001": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N",
        "cwe": "CWE-798 (Use of Hard-coded Credentials)",
        "owasp": "A07:2021 - Identification and Authentication Failures",
        "rationale": (
            "سر محتمل مكتشف بالاستدلال. S:C لأن السر يفتح خدمة خارجية "
            "خارج حدود التطبيق."
        ),
    },

    "CL-ADV-AUTH-001": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:L/A:N",
        "cwe": "CWE-287 (Improper Authentication)",
        "owasp": "A07:2021 - Identification and Authentication Failures",
        "rationale": (
            "ضعف محتمل في المصادقة. PR:L لأن الاستغلال يفترض حسابًا صالحًا "
            "لمحاولة تصعيد الصلاحية."
        ),
    },
}


# =========================================================
# 4. المكتبات والتبعيات
# =========================================================

DEPENDENCY_VECTORS: dict[str, dict[str, str]] = {

    "CL-DEP-VULN": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-1395 (Dependency on Vulnerable Third-Party Component)",
        "owasp": "A06:2021 - Vulnerable and Outdated Components",
        "rationale": (
            "مكوّن خارجي بثغرة منشورة. AC:L لأن كود الاستغلال غالبًا "
            "متاح ومؤتمت. ملاحظة: إن وفّر OSV متجهًا رسميًا للثغرة، "
            "فهو يُقدَّم على هذا المتجه الافتراضي."
        ),
    },

    "CL-DEP-UNPINNED": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "cwe": "CWE-1104 (Use of Unmaintained Third Party Components)",
        "owasp": "A08:2021 - Software and Data Integrity Failures",
        "rationale": (
            "إصدار غير مثبّت يجعل البناء غير قابل لإعادة الإنتاج، ويفتح "
            "الباب أمام هجوم سلسلة التوريد عبر إصدار خبيث جديد."
        ),
    },

    "CL-DEP-OSV-UNAVAILABLE": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N",
        "cwe": "CWE-noinfo",
        "owasp": "غير مصنّف",
        "rationale": (
            "تحذير تشغيلي: تعذّر الوصول لقاعدة OSV. الدرجة صفر لأنه ليس "
            "ثغرة — لكن إدراجه إلزامي حتى لا يُفهم الفحص الفارغ على أنه "
            "شهادة سلامة."
        ),
    },
}


# =========================================================
# 5. التجميع والواجهة العامة
# =========================================================

EXTENDED_CVSS_MAP: dict[str, dict[str, str]] = {
    **URL_VECTORS,
    **HEADER_VECTORS,
    **ADVANCED_VECTORS,
    **DEPENDENCY_VECTORS,
}


def get_extended_entry(rule_id: str) -> dict[str, Any] | None:
    """
    البحث عن متجه لقاعدة، مع دعم المطابقة بالبادئة.

    المطابقة بالبادئة ضرورية لأن ماسح المكتبات يولّد معرّفات ديناميكية
    مثل CL-DEP-UNPINNED-requests، فلا يمكن إدراجها كلها مسبقًا.
    """
    if not rule_id:
        return None

    key = str(rule_id).strip().upper()

    entry = EXTENDED_CVSS_MAP.get(key)
    if entry:
        return entry

    # مطابقة بالبادئة للمعرّفات الديناميكية
    for prefix, value in EXTENDED_CVSS_MAP.items():
        if key.startswith(prefix + "-") or key.startswith(prefix):
            return value

    return None


def coverage_summary() -> dict[str, Any]:
    """ملخص التغطية — يُعرض في التوثيق وفي المناقشة."""
    return {
        "url_rules": len(URL_VECTORS),
        "header_rules": len(HEADER_VECTORS),
        "advanced_rules": len(ADVANCED_VECTORS),
        "dependency_rules": len(DEPENDENCY_VECTORS),
        "total_extended": len(EXTENDED_CVSS_MAP),
    }
