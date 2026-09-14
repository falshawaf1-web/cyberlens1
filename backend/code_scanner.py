from __future__ import annotations

import re
from pathlib import Path
from typing import Any


# =========================================================
# إعدادات عامة
# =========================================================

MAX_CODE_FILE_SIZE = 5 * 1024 * 1024

SUPPORTED_EXTENSIONS = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".php",
    ".java",
    ".html",
    ".htm",
    ".css",
    ".sql",
    ".json",
    ".xml",
    ".yml",
    ".yaml",
    ".sh",
    ".ps1",
    ".c",
    ".cpp",
    ".h",
    ".hpp",
    ".cs",
}


# =========================================================
# ربط الامتداد بلغة البرمجة
# =========================================================

LANGUAGE_BY_EXTENSION = {
    ".py": "Python",
    ".js": "JavaScript",
    ".jsx": "JavaScript React",
    ".ts": "TypeScript",
    ".tsx": "TypeScript React",
    ".php": "PHP",
    ".java": "Java",
    ".html": "HTML",
    ".htm": "HTML",
    ".css": "CSS",
    ".sql": "SQL",
    ".json": "JSON",
    ".xml": "XML",
    ".yml": "YAML",
    ".yaml": "YAML",
    ".sh": "Shell",
    ".ps1": "PowerShell",
    ".c": "C",
    ".cpp": "C++",
    ".h": "C/C++ Header",
    ".hpp": "C++ Header",
    ".cs": "C#",
}


# =========================================================
# قواعد الفحص الأمني
# =========================================================

RULES: list[dict[str, Any]] = [
    # -----------------------------------------------------
    # Python
    # -----------------------------------------------------
    {
        "id": "CL-PY-001",
        "title": "استخدام eval()",
        "pattern": r"\beval\s*\(",
        "severity": "high",
        "languages": {"Python"},
        "description": (
            "تم اكتشاف استخدام eval()، وهي دالة قد تنفذ "
            "مدخلات كنص برمجي وتؤدي إلى تنفيذ كود غير موثوق."
        ),
        "recommendation": (
            "تجنب eval() واستبدلها بمعالجة صريحة للبيانات. "
            "للبيانات المهيكلة استخدم JSON أو محللًا آمنًا مناسبًا."
        ),
        "confidence": "high",
    },
    {
        "id": "CL-PY-002",
        "title": "استخدام exec()",
        "pattern": r"\bexec\s*\(",
        "severity": "high",
        "languages": {"Python"},
        "description": (
            "تم اكتشاف استخدام exec()، مما قد يسمح بتنفيذ "
            "كود ديناميكي غير موثوق."
        ),
        "recommendation": (
            "أزل التنفيذ الديناميكي للكود، وحدد العمليات "
            "المسموحة بشكل صريح داخل البرنامج."
        ),
        "confidence": "high",
    },
    {
        "id": "CL-PY-003",
        "title": "تنفيذ أوامر نظام باستخدام os.system",
        "pattern": r"\bos\.system\s*\(",
        "severity": "high",
        "languages": {"Python"},
        "description": (
            "استخدام os.system قد يؤدي إلى Command Injection "
            "إذا دخلت بيانات المستخدم في الأمر."
        ),
        "recommendation": (
            "استخدم subprocess بقائمة معاملات ثابتة، "
            "وتجنب shell، ولا تدمج مدخلات المستخدم في الأوامر."
        ),
        "confidence": "high",
    },
    {
        "id": "CL-PY-004",
        "title": "تشغيل subprocess مع shell=True",
        "pattern": r"\bshell\s*=\s*True\b",
        "severity": "high",
        "languages": {"Python"},
        "description": (
            "تم اكتشاف shell=True، وقد يزيد خطر حقن أوامر النظام."
        ),
        "recommendation": (
            "استخدم shell=False، ومرر الأمر والمعاملات كقائمة "
            "منفصلة بعد التحقق الصارم من أي مدخلات خارجية."
        ),
        "confidence": "high",
    },
    {
        "id": "CL-PY-005",
        "title": "إلغاء التحقق من شهادة TLS",
        "pattern": r"\bverify\s*=\s*False\b",
        "severity": "high",
        "languages": {"Python"},
        "description": (
            "تم تعطيل التحقق من شهادة TLS، مما قد يعرض الاتصال "
            "لهجمات الرجل في المنتصف."
        ),
        "recommendation": (
            "فعّل التحقق من الشهادات واستخدم شهادة CA موثوقة."
        ),
        "confidence": "high",
    },
    {
        "id": "CL-PY-006",
        "title": "تحميل Pickle غير موثوق",
        "pattern": r"\bpickle\.(load|loads)\s*\(",
        "severity": "high",
        "languages": {"Python"},
        "description": (
            "Pickle قد ينفذ تعليمات أثناء فك التسلسل إذا كانت "
            "البيانات من مصدر غير موثوق."
        ),
        "recommendation": (
            "لا تستخدم Pickle لبيانات غير موثوقة. "
            "استخدم JSON أو تنسيقًا آمنًا لا ينفذ كودًا."
        ),
        "confidence": "high",
    },
    {
        "id": "CL-PY-007",
        "title": "تشغيل وضع Debug",
        "pattern": r"\bdebug\s*=\s*True\b",
        "severity": "medium",
        "languages": {"Python"},
        "description": (
            "وضع Debug قد يكشف معلومات حساسة، وفي بعض البيئات "
            "قد يوسع أثر الأخطاء الأمنية."
        ),
        "recommendation": (
            "عطل Debug في بيئة الإنتاج واستخدم إعدادات منفصلة "
            "للتطوير والإنتاج."
        ),
        "confidence": "medium",
    },

    # -----------------------------------------------------
    # JavaScript / TypeScript
    # -----------------------------------------------------
    {
        "id": "CL-JS-001",
        "title": "استخدام eval() في JavaScript",
        "pattern": r"\beval\s*\(",
        "severity": "high",
        "languages": {
            "JavaScript",
            "JavaScript React",
            "TypeScript",
            "TypeScript React",
        },
        "description": (
            "eval() قد ينفذ محتوى غير موثوق ككود JavaScript."
        ),
        "recommendation": (
            "أزل eval() واستخدم parsing آمنًا أو منطقًا محددًا "
            "بدل التنفيذ الديناميكي."
        ),
        "confidence": "high",
    },
    {
        "id": "CL-JS-002",
        "title": "استخدام innerHTML",
        "pattern": r"\.innerHTML\s*=",
        "severity": "medium",
        "languages": {
            "JavaScript",
            "JavaScript React",
            "TypeScript",
            "TypeScript React",
        },
        "description": (
            "إسناد محتوى غير موثوق إلى innerHTML قد يؤدي "
            "إلى Cross-Site Scripting."
        ),
        "recommendation": (
            "استخدم textContent للنصوص، أو طبقة Sanitization "
            "موثوقة عند الحاجة إلى HTML."
        ),
        "confidence": "medium",
    },
    {
        "id": "CL-JS-003",
        "title": "تنفيذ أوامر نظام من Node.js",
        "pattern": (
            r"\b(child_process\.)?"
            r"(exec|execSync)\s*\("
        ),
        "severity": "high",
        "languages": {
            "JavaScript",
            "JavaScript React",
            "TypeScript",
            "TypeScript React",
        },
        "description": (
            "تنفيذ أوامر نظام قد يؤدي إلى Command Injection "
            "إذا احتوى الأمر على مدخلات خارجية."
        ),
        "recommendation": (
            "استخدم spawn/execFile بمعاملات منفصلة، "
            "وامنع دمج مدخلات المستخدم داخل نص الأمر."
        ),
        "confidence": "medium",
    },

    # -----------------------------------------------------
    # PHP
    # -----------------------------------------------------
    {
        "id": "CL-PHP-001",
        "title": "تنفيذ أوامر نظام في PHP",
        "pattern": (
            r"\b(system|shell_exec|passthru|"
            r"popen|proc_open)\s*\("
        ),
        "severity": "high",
        "languages": {"PHP"},
        "description": (
            "تم اكتشاف دالة تنفذ أوامر نظام من PHP."
        ),
        "recommendation": (
            "تجنب تنفيذ أوامر النظام. عند الضرورة استخدم "
            "قائمة سماح صارمة ولا تمرر مدخلات المستخدم مباشرة."
            ),
        "confidence": "high",
    },
    {
        "id": "CL-PHP-002",
        "title": "فك تسلسل PHP باستخدام unserialize",
        "pattern": r"\bunserialize\s*\(",
        "severity": "high",
        "languages": {"PHP"},
        "description": (
            "unserialize على بيانات غير موثوقة قد يؤدي "
            "إلى Object Injection."
        ),
        "recommendation": (
            "استخدم JSON للبيانات غير الموثوقة، "
            "وتجنب unserialize لمدخلات المستخدم."
        ),
        "confidence": "high",
    },

    # -----------------------------------------------------
    # SQL
    # -----------------------------------------------------
    {
        "id": "CL-SQL-001",
        "title": "استعلام SQL مبني بدمج نصوص",
        "pattern": (
            r"(SELECT|INSERT|UPDATE|DELETE)"
            r".*(\+|\.\s*\$|\$\{)"
        ),
        "severity": "high",
        "languages": {
            "Python",
            "JavaScript",
            "JavaScript React",
            "TypeScript",
            "TypeScript React",
            "PHP",
            "Java",
            "C#",
        },
        "description": (
            "تم رصد نمط قد يشير إلى بناء استعلام SQL "
            "بدمج قيم ديناميكية."
        ),
        "recommendation": (
            "استخدم Parameterized Queries أو Prepared Statements "
            "ولا تدمج مدخلات المستخدم داخل نص SQL."
        ),
        "confidence": "medium",
    },

    # -----------------------------------------------------
    # خوارزميات ضعيفة
    # -----------------------------------------------------
    {
        "id": "CL-CRYPTO-001",
        "title": "استخدام MD5",
        "pattern": r"\b(md5|MD5)\b",
        "severity": "medium",
        "languages": None,
        "description": (
            "MD5 خوارزمية تجزئة قديمة وغير مناسبة "
            "للأغراض الأمنية الحساسة."
        ),
        "recommendation": (
            "للتجزئة العامة استخدم SHA-256 أو أقوى حسب السياق، "
            "ولكلمات المرور استخدم Argon2 أو bcrypt أو scrypt."
        ),
        "confidence": "medium",
    },
    {
        "id": "CL-CRYPTO-002",
        "title": "استخدام SHA-1",
        "pattern": r"\b(sha1|SHA1|SHA-1)\b",
        "severity": "medium",
        "languages": None,
        "description": (
            "SHA-1 لم يعد مناسبًا للاستخدامات الأمنية "
            "التي تتطلب مقاومة تصادم قوية."
        ),
        "recommendation": (
            "استخدم SHA-256 أو خوارزمية أحدث وفق طبيعة الاستخدام."
        ),
        "confidence": "medium",
    },

    # -----------------------------------------------------
    # C / C++
    # -----------------------------------------------------
    {
        "id": "CL-C-001",
        "title": "استخدام gets() غير الآمن",
        "pattern": r"\bgets\s*\(",
        "severity": "critical",
        "languages": {
            "C",
            "C++",
            "C/C++ Header",
            "C++ Header",
        },
        "description": (
            "gets() لا يفرض حدًا لطول الإدخال وقد يؤدي "
            "إلى Buffer Overflow."
        ),
        "recommendation": (
            "استخدم fgets() مع طول محدد وتحقق من حدود البيانات."
        ),
        "confidence": "high",
    },
    {
        "id": "CL-C-002",
        "title": "استخدام strcpy() دون حدود",
        "pattern": r"\bstrcpy\s*\(",
        "severity": "high",
        "languages": {
            "C",
            "C++",
            "C/C++ Header",
            "C++ Header",
        },
        "description": (
            "strcpy() لا يتحقق من حجم الوجهة وقد يسبب "
            "Buffer Overflow."
        ),
        "recommendation": (
            "تحقق من أحجام الذاكرة واستخدم بدائل آمنة "
            "وفق المنصة والسياق."
        ),
        "confidence": "medium",
    },

    # -----------------------------------------------------
    # Generic
    # -----------------------------------------------------
    {
        "id": "CL-GEN-001",
        "title": "تعطيل التحقق من TLS",
        "pattern": (
            r"(rejectUnauthorized\s*:\s*false|"
            r"CURLOPT_SSL_VERIFYPEER\s*,\s*false)"
        ),
        "severity": "high",
        "languages": None,
        "description": (
            "تم اكتشاف إعداد قد يعطل التحقق من شهادات TLS."
        ),
        "recommendation": (
            "فعّل التحقق من شهادات TLS واستخدم مخزن ثقة موثوقًا."
        ),
        "confidence": "high",
    },
]


# =========================================================
# قواعد اكتشاف أسرار ثابتة
# =========================================================

SECRET_RULES: list[dict[str, Any]] = [
    {
        "id": "CL-SECRET-001",
        "title": "كلمة مرور ثابتة داخل الكود",
        "pattern": (
            r"""(?ix)
            \b(password|passwd|pwd)
            \s*[:=]\s*
            ["']
            ([^"'\\]{6,})
            ["']
            """
        ),
        "severity": "high",
        "description": (
            "تم اكتشاف قيمة تبدو ككلمة مرور مخزنة مباشرة "
            "داخل الكود."
        ),
        "recommendation": (
            "انقل الأسرار إلى متغيرات بيئة أو Secret Manager، "
            "ولا تحفظ كلمات المرور داخل المستودع."
        ),
        "confidence": "medium",
    },
    {
        "id": "CL-SECRET-002",
        "title": "مفتاح API محتمل داخل الكود",
        "pattern": (
            r"""(?ix)
            \b(api[_-]?key|apikey)
            \s*[:=]\s*
            ["']
            ([A-Za-z0-9_\-]{12,})
            ["']
            """
        ),
        "severity": "high",
        "description": (
            "تم اكتشاف قيمة قد تكون API Key ثابتًا داخل الكود."
        ),
        "recommendation": (
            "ألغ المفتاح إذا كان حقيقيًا، ثم استخدم متغيرات "
            "البيئة أو خدمة إدارة أسرار."
        ),
        "confidence": "medium",
    },
    {
        "id": "CL-SECRET-003",
        "title": "Token محتمل داخل الكود",
        "pattern": (
            r"""(?ix)
            \b(access[_-]?token|auth[_-]?token|token)
            \s*[:=]\s*
            ["']
            ([A-Za-z0-9_\-\.]{16,})
            ["']
            """
        ),
        "severity": "high",
        "description": (
            "تم اكتشاف قيمة قد تكون Token ثابتًا داخل الكود."
        ),
        "recommendation": (
            "لا تحفظ Tokens داخل المصدر. استخدم Secret Manager "
            "أو متغيرات بيئة وقم بتدوير السر إذا كان حقيقيًا."
        ),
        "confidence": "medium",
    },
]


# =========================================================
# اكتشاف اللغة
# =========================================================

def detect_language(
    file_path: Path,
) -> str:
    extension = file_path.suffix.lower()

    return LANGUAGE_BY_EXTENSION.get(
        extension,
        "Unknown",
    )


# =========================================================
# قراءة الملف بأمان
# =========================================================

def read_text_file(
    file_path: Path,
) -> str:
    if not file_path.exists():
        raise ValueError(
            "الملف المطلوب غير موجود."
        )

    if not file_path.is_file():
        raise ValueError(
            "المسار المحدد ليس ملفًا."
        )

    file_size = file_path.stat().st_size

    if file_size > MAX_CODE_FILE_SIZE:
        raise ValueError(
            "حجم ملف الكود أكبر من الحد المسموح وهو 5MB."
        )

    raw_data = file_path.read_bytes()

    encodings = [
        "utf-8-sig",
        "utf-8",
        "cp1256",
        "cp1252",
        "latin-1",
    ]

    for encoding in encodings:
        try:
            return raw_data.decode(encoding)

        except UnicodeDecodeError:
            continue

    raise UnicodeDecodeError(
        "unknown",
        b"",
        0,
        1,
        "تعذر قراءة ترميز الملف",
    )


# =========================================================
# إخفاء الأسرار من مقتطفات الكود
# =========================================================
def redact_sensitive_snippet(
    line: str,
) -> str:
    redacted = line

    patterns = [
        (
            r"""(?i)
            ((password|passwd|pwd)
            \s*[:=]\s*
            ["'])
            ([^"']+)
            (["'])
            """,
            r"\1*REDACTED*\4",
        ),
        (
            r"""(?i)
            ((api[_-]?key|apikey)
            \s*[:=]\s*
            ["'])
            ([^"']+)
            (["'])
            """,
            r"\1*REDACTED*\4",
        ),
        (
            r"""(?i)
            ((access[_-]?token|auth[_-]?token|token)
            \s*[:=]\s*
            ["'])
            ([^"']+)
            (["'])
            """,
            r"\1*REDACTED*\4",
        ),
    ]

    for pattern, replacement in patterns:
        redacted = re.sub(
            pattern,
            replacement,
            redacted,
            flags=re.VERBOSE,
        )

    redacted = redacted.strip()

    if len(redacted) > 220:
        redacted = (
            redacted[:217]
            + "..."
        )

    return redacted


# =========================================================
# معرفة هل القاعدة تنطبق على اللغة
# =========================================================

def rule_applies_to_language(
    rule: dict[str, Any],
    language: str,
) -> bool:
    languages = rule.get(
        "languages"
    )

    if languages is None:
        return True

    return language in languages


# =========================================================
# إنشاء Finding
# =========================================================

def build_finding(
    rule: dict[str, Any],
    file_name: str,
    line_number: int,
    line_text: str,
) -> dict[str, Any]:
    return {
        "id": rule["id"],
        "title": rule["title"],
        "severity": rule["severity"],
        "description": rule["description"],
        "recommendation": rule["recommendation"],
        "source": "CyberLens SAST",
        "file": file_name,
        "line": line_number,
        "code": redact_sensitive_snippet(line_text),
        "confidence": rule.get("confidence", "medium"),

        "evidence": rule.get(
            "evidence",
            f"تم اكتشاف نمط أمني مشبوه في الملف {file_name} عند السطر {line_number}.",
        ),

        "impact": rule.get(
            "impact",
            "قد يؤدي هذا الضعف إلى تعريض سرية البيانات أو سلامتها أو توفرها للخطر.",
        ),

        "why_detected": rule.get(
            "why_detected",
            "تطابق سطر الكود مع قاعدة تحليل أمني ضمن محرك CyberLens SAST.",
        ),

        "remediation_steps": rule.get(
            "remediation_steps",
            [
                "راجع السطر الذي تم اكتشافه.",
                "تجنب استخدام إدخال المستخدم بشكل مباشر.",
                "استخدم الدوال والمكتبات الآمنة.",
                "أعد فحص الملف بعد التعديل.",
            ],
        ),

        "secure_example": rule.get(
            "secure_example",
            "",
        ),

        "verification": rule.get(
            "verification",
            "أعد تشغيل فحص الكود وتأكد من اختفاء النتيجة.",
        ),

        "owasp": rule.get(
            "owasp",
            "OWASP Top 10",
        ),

        "cwe": rule.get(
            "cwe",
            "",
        ),

        "metadata": {
            "engine": "CyberLens Static Analysis",
            "rule_id": rule["id"],
        },
    }

# =========================================================
# فحص القواعد العامة
# =========================================================

def scan_security_rules(
    content: str,
    file_name: str,
    language: str,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []

    lines = content.splitlines()

    for line_number, line_text in enumerate(
        lines,
        start=1,
    ):
        for rule in RULES:

            if not rule_applies_to_language(
                rule,
                language,
            ):
                continue

            pattern = rule["pattern"]

            try:
                matched = re.search(
                    pattern,
                    line_text,
                    flags=re.IGNORECASE,
                )

            except re.error:
                continue

            if not matched:
                continue

            findings.append(
                build_finding(
                    rule=rule,
                    file_name=file_name,
                    line_number=line_number,
                    line_text=line_text,
                )
            )

    return findings


# =========================================================
# فحص الأسرار
# =========================================================

def scan_secret_rules(
    content: str,
    file_name: str,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []

    lines = content.splitlines()

    for line_number, line_text in enumerate(
        lines,
        start=1,
    ):
        for rule in SECRET_RULES:

            try:
                matched = re.search(
                    rule["pattern"],
                    line_text,
                    flags=re.VERBOSE,
                )
            except re.error:
                 continue

            if not matched:
                continue

            findings.append(
                build_finding(
                    rule=rule,
                    file_name=file_name,
                    line_number=line_number,
                    line_text=line_text,
                )
            )

    return findings


# =========================================================
# إزالة النتائج المكررة
# =========================================================

def deduplicate_findings(
    findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    unique: list[dict[str, Any]] = []

    seen: set[
        tuple[str, str, int]
    ] = set()

    for finding in findings:
        key = (
            str(
                finding.get("id", "")
            ),
            str(
                finding.get("file", "")
            ),
            int(
                finding.get("line") or 0
            ),
        )

        if key in seen:
            continue

        seen.add(key)

        unique.append(finding)

    return unique


# =========================================================
# ترتيب النتائج
# =========================================================

def sort_findings(
    findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    severity_rank = {
        "critical": 5,
        "high": 4,
        "medium": 3,
        "low": 2,
        "info": 1,
    }

    return sorted(
        findings,
        key=lambda item: (
            -severity_rank.get(
                str(
                    item.get(
                        "severity",
                        "low",
                    )
                ).lower(),
                0,
            ),
            int(
                item.get("line") or 0
            ),
        ),
    )


# =========================================================
# الدالة الرئيسية
# =========================================================

def _scan_code_file_base(
    file_path: str | Path,
) -> dict[str, Any]:
    path = Path(
        file_path
    ).resolve()

    extension = path.suffix.lower()

    if extension not in SUPPORTED_EXTENSIONS:
        raise ValueError(
            f"امتداد الملف غير مدعوم: "
            f"{extension or 'بدون امتداد'}"
        )

    content = read_text_file(
        path
    )

    language = detect_language(
        path
    )

    findings: list[dict[str, Any]] = []

    findings.extend(
        scan_security_rules(
            content=content,
            file_name=path.name,
            language=language,
        )
    )

    findings.extend(
        scan_secret_rules(
            content=content,
            file_name=path.name,
        )
    )

    findings = deduplicate_findings(
        findings
    )

    findings = sort_findings(
        findings
    )

    return {
        "file_name": path.name,
        "language": language,
        "file_size": path.stat().st_size,
        "lines_scanned": len(
            content.splitlines()
        ),
        "findings": findings,
        "total_findings": len(
            findings
        ),
        "engine": (
            "CyberLens Static Application "
            "Security Testing"
        ),
        "execution": False,
    }


# =========================================================
# اختبار مباشر
# =========================================================

if __name__ == "__main__":

    print("=" * 60)
    print("CyberLens Code Scanner")
    print("=" * 60)
    print(
        "هذا الملف يحتوي محرك SAST دفاعي."
    )
    print(
        "لا يتم تنفيذ الكود أثناء الفحص."
    )
    print("=" * 60)

# =========================================================
# Advanced Code Scan Wrapper
# =========================================================

def scan_code_file(file_path, *args, **kwargs):
    result = _scan_code_file_base(
        file_path,
        *args,
        **kwargs,
    )

    try:
        try:
            from .advanced_code_scanner import run_advanced_code_checks
        except Exception:
            from advanced_code_scanner import run_advanced_code_checks

        advanced_findings = run_advanced_code_checks(
            file_path,
            result.get("language"),
        )

        all_findings = (
            result.get("findings") or []
        ) + advanced_findings

        result["findings"] = sort_findings(
            deduplicate_findings(
                all_findings
            )
        )

        result["total_findings"] = len(
            result["findings"]
        )

        result["advanced_engine"] = "CyberLens Advanced Code Analysis"

    except Exception as exc:
        result["advanced_engine_error"] = str(exc)

    return result
