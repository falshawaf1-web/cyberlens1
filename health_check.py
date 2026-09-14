"""
health_check.py — الفحص الذاتي الشامل لمنصة CyberLens
======================================================

يختبر كل مكوّن في المنصة ويُخرج تقريرًا واضحًا: ما يعمل، وما لا يعمل،
وسبب كل إخفاق.

الاستخدام:
    .\\venv\\Scripts\\python.exe health_check.py

يعمل محليًا بالكامل ولا يحتاج الخادم مشغّلًا.
"""

from __future__ import annotations

import io
import json
import sys
import time
import traceback
from pathlib import Path

BASE = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE / "backend"))
sys.path.insert(0, str(BASE))

PASS = "نجح"
FAIL = "فشل"
WARN = "تنبيه"

results: list[tuple[str, str, str]] = []


def record(status: str, name: str, detail: str = "") -> None:
    results.append((status, name, detail))
    mark = {"نجح": "[+]", "فشل": "[!]", "تنبيه": "[~]"}[status]
    line = f"  {mark} {name}"
    if detail:
        line += f"  ({detail})"
    print(line)


def section(title: str) -> None:
    print()
    print("=" * 62)
    print(f"  {title}")
    print("=" * 62)


# =====================================================================
# 1. البيئة والاعتماديات
# =====================================================================

section("1. البيئة والاعتماديات")

record(PASS, "إصدار بايثون", sys.version.split()[0])

for module, label in [
    ("flask", "Flask"),
    ("sqlalchemy", "SQLAlchemy"),
    ("requests", "requests"),
    ("openai", "openai"),
    ("dotenv", "python-dotenv"),
    ("reportlab", "ReportLab"),
    ("arabic_reshaper", "arabic-reshaper"),
    ("bidi", "python-bidi"),
]:
    try:
        __import__(module)
        record(PASS, f"مكتبة {label}")
    except ImportError:
        record(FAIL, f"مكتبة {label}", "غير مثبّتة")


# =====================================================================
# 2. سلامة الملفات
# =====================================================================

section("2. سلامة ملفات المشروع")

import ast

for path in sorted((BASE / "backend").glob("*.py")):
    try:
        ast.parse(path.read_text(encoding="utf-8-sig"))
        record(PASS, f"صحة {path.name}")
    except SyntaxError as exc:
        record(FAIL, f"صحة {path.name}", f"سطر {exc.lineno}")

# نصوص عربية تالفة
corrupted = 0
for path in list((BASE / "backend").glob("*.py")) + list((BASE / "frontend").glob("*.js")):
    try:
        if "???" in path.read_text(encoding="utf-8-sig"):
            corrupted += 1
    except Exception:
        pass

if corrupted:
    record(FAIL, "نصوص عربية سليمة", f"{corrupted} ملف تالف")
else:
    record(PASS, "نصوص عربية سليمة")


# =====================================================================
# 3. الإعدادات
# =====================================================================

section("3. الإعدادات والمفاتيح")

import os

from dotenv import load_dotenv

env_file = BASE / ".env"

if env_file.exists():
    load_dotenv(env_file, override=True)
    record(PASS, "ملف .env موجود")
else:
    record(WARN, "ملف .env", "غير موجود — الذكاء سيعمل محليًا")

groq_key = os.getenv("GROQ_API_KEY", "").strip()
groq_model = os.getenv("GROQ_MODEL", "").strip()

if groq_key:
    shape = "صحيح" if groq_key.startswith("gsk_") and len(groq_key) > 40 else "مشبوه"
    record(
        PASS if shape == "صحيح" else WARN,
        "مفتاح Groq",
        f"{len(groq_key)} محرف، الشكل {shape}، ينتهي بـ {groq_key[-4:]}",
    )
else:
    record(WARN, "مفتاح Groq", "غير مضبوط")

if groq_model:
    record(PASS, "نموذج Groq", groq_model)
else:
    record(WARN, "نموذج Groq", "غير مضبوط — سيُستخدم الافتراضي")

# تحذير من متغير نظام يتجاوز .env
system_key = os.environ.get("GROQ_API_KEY", "")
if env_file.exists() and groq_key and system_key != groq_key:
    record(WARN, "تعارض مفاتيح", "متغير النظام يختلف عن .env")


# =====================================================================
# 4. الاتصال بالخدمات الخارجية
# =====================================================================

section("4. الخدمات الخارجية")

# --- OSV ---
try:
    import requests as _rq

    started = time.time()
    response = _rq.post(
        "https://api.osv.dev/v1/querybatch",
        json={
            "queries": [
                {
                    "package": {"name": "requests", "ecosystem": "PyPI"},
                    "version": "2.19.1",
                }
            ]
        },
        timeout=20,
    )
    elapsed = time.time() - started

    if response.status_code == 200:
        record(PASS, "قاعدة OSV", f"{elapsed:.1f} ثانية")
    else:
        record(FAIL, "قاعدة OSV", f"رمز {response.status_code}")
except Exception as exc:
    record(FAIL, "قاعدة OSV", type(exc).__name__)

# --- Groq ---
if groq_key:
    try:
        from openai import OpenAI

        client = OpenAI(
            api_key=groq_key,
            base_url="https://api.groq.com/openai/v1",
        )

        started = time.time()
        completion = client.chat.completions.create(
            model=groq_model or "openai/gpt-oss-120b",
            messages=[{"role": "user", "content": "ping"}],
            max_tokens=2000,
            timeout=30,
        )
        elapsed = time.time() - started
        record(PASS, "خدمة Groq", f"{elapsed:.1f} ثانية")

    except Exception as exc:
        name = type(exc).__name__
        hint = {
            "AuthenticationError": "المفتاح غير صالح",
            "NotFoundError": "النموذج غير موجود",
            "RateLimitError": "تجاوز الحد المجاني",
        }.get(name, str(exc)[:60])
        record(FAIL, "خدمة Groq", f"{name}: {hint}")
else:
    record(WARN, "خدمة Groq", "تخطّي — لا يوجد مفتاح")


# =====================================================================
# 5. محركات الفحص
# =====================================================================

section("5. محركات الفحص")

SAMPLE_CODE = b"""import os
import pickle
import hashlib

PASSWORD = "S3cret_Pass_2024"

def run(host):
    os.system("ping " + host)

def load(data):
    return pickle.loads(data)

def digest(value):
    return hashlib.md5(value.encode()).hexdigest()
"""

SAMPLE_REQS = b"""requests==2.19.1
pyyaml==5.1
flask==0.12.2
urllib3==1.24.1
"""

try:
    import app as A

    client = A.app.test_client()
    record(PASS, "تحميل التطبيق", f"{len(list(A.app.url_map.iter_rules()))} مسار")

    # تسجيل الدخول
    admin_password = os.getenv("CYBERLENS_ADMIN_PASSWORD", "").strip()

    if not admin_password:
        record(WARN, "تسجيل الدخول", "CYBERLENS_ADMIN_PASSWORD غير مضبوط")
        client = None
    else:
        login = client.post(
            "/api/auth/login",
            json={"username": os.getenv("CYBERLENS_ADMIN_USERNAME", "admin"),
                  "password": admin_password},
        )
        if login.status_code == 200:
            record(PASS, "تسجيل الدخول")
        else:
            record(FAIL, "تسجيل الدخول", f"رمز {login.status_code}")
            client = None

except Exception as exc:
    record(FAIL, "تحميل التطبيق", type(exc).__name__)
    traceback.print_exc()
    client = None


def run_scan(label: str, path: str, **kwargs):
    """تشغيل فحص وقياس زمنه وفحص اكتمال نتائجه."""
    if client is None:
        record(WARN, label, "تخطّي — لا توجد جلسة")
        return None

    try:
        started = time.time()
        response = client.post(path, **kwargs)
        elapsed = time.time() - started

        payload = json.loads(response.data)

        if not payload.get("success"):
            record(FAIL, label, str(payload.get("message"))[:60])
            return None

        data = payload["data"]
        count = data.get("total_findings", 0)
        record(PASS, label, f"{count} نتيجة في {elapsed:.1f} ثانية")
        return data

    except Exception as exc:
        record(FAIL, label, type(exc).__name__)
        return None


code_scan = run_scan(
    "فحص الكود",
    "/api/scan/code",
    data={"file": (io.BytesIO(SAMPLE_CODE), "sample.py")},
    content_type="multipart/form-data",
)

dep_scan = run_scan(
    "فحص المكتبات",
    "/api/scan/dependencies",
    data={"file": (io.BytesIO(SAMPLE_REQS), "requirements.txt")},
    content_type="multipart/form-data",
)

url_scan = run_scan(
    "فحص الروابط",
    "/api/scan/url",
    json={"url": "http://testphp.vulnweb.com/login.php?next=http://x.com"},
)

# فحص مشروع مضغوط
try:
    import zipfile

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("src/app.py", SAMPLE_CODE.decode())
        archive.writestr("requirements.txt", SAMPLE_REQS.decode())
    buffer.seek(0)

    project_scan = run_scan(
        "فحص المشروع",
        "/api/scan/project",
        data={"file": (buffer, "project.zip")},
        content_type="multipart/form-data",
    )
except Exception as exc:
    record(FAIL, "فحص المشروع", type(exc).__name__)
    project_scan = None


# =====================================================================
# 6. جودة النتائج
# =====================================================================

section("6. جودة النتائج")

if code_scan:
    findings = code_scan.get("findings", [])

    missing_cvss = [f for f in findings if not f.get("cvss_score")]
    if missing_cvss:
        record(FAIL, "تغطية CVSS", f"{len(missing_cvss)} نتيجة بلا درجة")
    else:
        record(PASS, "تغطية CVSS", f"{len(findings)} نتيجة")

    missing_cwe = [f for f in findings if not f.get("cwe")]
    if missing_cwe:
        record(WARN, "تغطية CWE", f"{len(missing_cwe)} نتيجة بلا تصنيف")
    else:
        record(PASS, "تغطية CWE")

    ai = code_scan.get("ai_analysis", {})
    mode = ai.get("mode")
    provider = ai.get("provider", "")

    if mode == "external":
        record(PASS, "وضع الذكاء", f"خارجي — {provider}")
    else:
        record(WARN, "وضع الذكاء", "محلي — راجع مفتاح Groq")

    details = ai.get("detailed_analysis", [])
    if details:
        field_count = len(details[0])
        if field_count >= 25:
            record(PASS, "اكتمال البطاقات", f"{field_count} حقل")
        else:
            record(WARN, "اكتمال البطاقات", f"{field_count} حقل فقط")
    else:
        record(FAIL, "اكتمال البطاقات", "لا توجد بطاقات")

if dep_scan:
    complete = dep_scan.get("scan_complete", True)
    if complete:
        record(PASS, "اكتمال فحص المكتبات")
    else:
        record(WARN, "اكتمال فحص المكتبات", "تعذّر الوصول إلى OSV")

    with_cve = [f for f in dep_scan.get("findings", []) if f.get("cve")]
    record(
        PASS if with_cve else WARN,
        "معرّفات CVE",
        f"{len(with_cve)} نتيجة",
    )

    # تكرار
    seen: dict[str, list[str]] = {}
    for finding in dep_scan.get("findings", []):
        cve = finding.get("cve")
        if cve:
            seen.setdefault(cve, []).append(finding.get("severity"))

    duplicates = sum(1 for v in seen.values() if len(v) > 1)
    conflicts = sum(1 for v in seen.values() if len(set(v)) > 1)

    record(PASS if duplicates == 0 else FAIL, "بلا تكرار CVE",
           "" if duplicates == 0 else f"{duplicates} مكرر")
    record(PASS if conflicts == 0 else FAIL, "بلا تضارب خطورة",
           "" if conflicts == 0 else f"{conflicts} متضارب")


# =====================================================================
# 7. التقارير والأمان
# =====================================================================

section("7. التقارير والأمان")

if client and code_scan:
    scan_id = code_scan.get("scan_id")
    if scan_id:
        try:
            report = client.get(f"/api/scans/{scan_id}/report.pdf")
            if report.status_code == 200:
                size_kb = len(report.data) // 1024
                record(PASS, "تقرير PDF", f"{size_kb} كيلوبايت")
            else:
                record(FAIL, "تقرير PDF", f"رمز {report.status_code}")
        except Exception as exc:
            record(FAIL, "تقرير PDF", type(exc).__name__)

if client:
    headers = client.get("/").headers
    required = [
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
        "Permissions-Policy",
    ]
    missing = [h for h in required if h not in headers]

    if missing:
        record(FAIL, "ترويسات الأمان", f"ناقص {len(missing)}")
    else:
        record(PASS, "ترويسات الأمان", f"{len(required)} ترويسة")

    guest = A.app.test_client()
    if guest.get("/api/dashboard").status_code == 401:
        record(PASS, "حماية المسارات")
    else:
        record(FAIL, "حماية المسارات", "مسار محمي مفتوح")


# =====================================================================
# الخلاصة
# =====================================================================

section("الخلاصة")

passed = sum(1 for status, _, _ in results if status == PASS)
failed = sum(1 for status, _, _ in results if status == FAIL)
warned = sum(1 for status, _, _ in results if status == WARN)

print(f"  نجح   : {passed}")
print(f"  فشل   : {failed}")
print(f"  تنبيه : {warned}")
print()

if failed:
    print("  الإخفاقات التي تحتاج معالجة:")
    for status, name, detail in results:
        if status == FAIL:
            print(f"    - {name}: {detail}")
    print()

if warned:
    print("  التنبيهات (لا تمنع التشغيل):")
    for status, name, detail in results:
        if status == WARN:
            print(f"    - {name}: {detail}")
    print()

if failed == 0:
    print("  النتيجة: المنصة جاهزة.")
else:
    print("  النتيجة: توجد أعطال تحتاج معالجة قبل العرض.")

print()
