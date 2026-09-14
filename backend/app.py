
from __future__ import annotations

import os
import re
import secrets
import time
from collections import defaultdict, deque
from pathlib import Path
from urllib.parse import urlparse
from uuid import uuid4
from typing import Any

from flask import Flask, jsonify, request, send_file, send_from_directory, session
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.utils import secure_filename
from werkzeug.security import check_password_hash, generate_password_hash
# =========================================================
# CyberLens Local Modules
# =========================================================

# =========================================================
# CyberLens Local Modules
# =========================================================
# الاختيار يتم حسب طريقة التشغيل لا عبر try/except:
# الكتلة القديمة كانت تبتلع أي ImportError حقيقي (مكتبة
# ناقصة أو ملف فارغ) وتعرض رسالة مضلِّلة عن ملف آخر.
# =========================================================

if __package__:
    from .ai_engine import explain_findings_with_ai
    from .code_scanner import scan_code_file
    from .cvss_mapper import apply_cvss_to_findings
    from .database import (
        create_user,
        get_dashboard_statistics,
        get_scan_by_id,
        get_scan_history,
        get_user_by_id,
        get_user_by_username,
        init_database,
        list_users_with_stats,
        save_scan_result,
        set_user_active,
    )
    from .pdf_report import PDFReportError, build_pdf_report
    from .project_scanner import scan_project_archive
    from .sbom_scanner import scan_dependency_file
    from .score_calculator import calculate_security_score
    from .url_scanner import scan_url

else:
    from ai_engine import explain_findings_with_ai
    from code_scanner import scan_code_file
    from cvss_mapper import apply_cvss_to_findings
    from database import (
        create_user,
        get_dashboard_statistics,
        get_scan_by_id,
        get_scan_history,
        get_user_by_id,
        get_user_by_username,
        init_database,
        list_users_with_stats,
        save_scan_result,
        set_user_active,
    )
    from pdf_report import PDFReportError, build_pdf_report
    from project_scanner import scan_project_archive
    from sbom_scanner import scan_dependency_file
    from score_calculator import calculate_security_score
    from url_scanner import scan_url


# =========================================================
# المسارات الأساسية
# =========================================================

BASE_DIR = Path(__file__).resolve().parent.parent
BACKEND_DIR = BASE_DIR / "backend"
FRONTEND_DIR = BASE_DIR / "frontend"
UPLOAD_DIR = BASE_DIR / "uploads"

UPLOAD_DIR.mkdir(parents=True, exist_ok=True)


# =========================================================
# إنشاء تطبيق Flask
# =========================================================

app = Flask(
    __name__,
    static_folder=str(FRONTEND_DIR),
    static_url_path="",
)

# الحد الأقصى لحجم الرفع. project_scanner يفحص أرشيفات حتى
# MAX_ARCHIVE_SIZE، فنجعل الحدين متسقين بدل أن يوقف Flask
# الرفع قبل وصوله للفاحص.
MAX_UPLOAD_SIZE = 50 * 1024 * 1024

app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_SIZE
app.config["UPLOAD_FOLDER"] = str(UPLOAD_DIR)
app.config["JSON_AS_ASCII"] = False


# =========================================================
# المفتاح السري
# =========================================================
# لا يوجد مفتاح افتراضي في الكود: من يعرفه يستطيع تزوير
# كوكي الجلسة وانتحال أي حساب بما فيه المدير.
# =========================================================

IS_DEBUG = os.environ.get("FLASK_DEBUG", "false").lower() == "true"

_secret_key = os.environ.get("CYBERLENS_SECRET_KEY", "").strip()

if _secret_key:
    app.secret_key = _secret_key

elif IS_DEBUG:
    app.secret_key = secrets.token_hex(32)
    print(
        "[CyberLens] تحذير: CYBERLENS_SECRET_KEY غير مضبوط. "
        "تم توليد مفتاح مؤقت للتطوير، وستُفقد الجلسات عند "
        "إعادة التشغيل."
    )

else:
    raise RuntimeError(
        "CYBERLENS_SECRET_KEY مطلوب في الإنتاج. "
        "ولّد مفتاحًا بالأمر: "
        "python -c \"import secrets; print(secrets.token_hex(32))\""
    )


# =========================================================
# إعدادات أمان كوكي الجلسة
# =========================================================

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=not IS_DEBUG,
)



# =========================================================
# الامتدادات المسموحة
# =========================================================

CODE_EXTENSIONS = {
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
    ".cs",
}

DEPENDENCY_FILENAMES = {
    "requirements.txt",
    "package.json",
    "package-lock.json",
    "composer.lock",
    "go.mod",
    "cargo.lock",
}


# =========================================================
# أدوات مساعدة
# =========================================================

def api_success(
    data: Any = None,
    message: str = "تمت العملية بنجاح",
    status_code: int = 200,
):
    return (
        jsonify(
            {
                "success": True,
                "message": message,
                "data": data,
            }
        ),
        status_code,
    )


def api_error(
    message: str,
    status_code: int = 400,
    details: Any = None,
):
    payload = {
        "success": False,
        "message": message,
    }

    if details is not None:
        payload["details"] = details

    return jsonify(payload), status_code


def normalize_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []

    for index, finding in enumerate(findings, start=1):
        severity = str(finding.get("severity", "low")).lower().strip()

        if severity not in {"critical", "high", "medium", "low", "info"}:
            severity = "low"

        normalized.append(
            {
                "id": finding.get("id") or f"CL-{index:04d}",
                "title": finding.get("title") or "ملاحظة أمنية",
                "description": finding.get("description") or "",
                "severity": severity,
                "recommendation": finding.get("recommendation") or "",
                "source": finding.get("source") or "CyberLens",
                "file": finding.get("file"),
                "line": finding.get("line"),
                "code": finding.get("code"),
                "cve": finding.get("cve"),
                "package": finding.get("package"),
         "installed_version": finding.get("installed_version"),
        "fixed_version": finding.get("fixed_version"),
        "confidence": finding.get("confidence"),
        "metadata": finding.get("metadata") or {},
    }
)

    return normalized


def deduplicate_security_findings(
    findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:

    unique: list[dict[str, Any]] = []
    seen: set[tuple[str, ...]] = set()

    for finding in findings:

        metadata = (
            finding.get("metadata")
            if isinstance(
                finding.get("metadata"),
                dict,
            )
            else {}
        )

        finding_id = str(
            finding.get("id")
            or ""
        ).strip()

        cve = str(
            finding.get("cve")
            or metadata.get("cve")
            or ""
        ).strip().lower()

        ghsa = str(
            finding.get("ghsa")
            or metadata.get("ghsa")
            or finding.get("advisory")
            or metadata.get("advisory")
            or ""
        ).strip().lower()

        package = str(
            finding.get("package")
            or ""
        ).strip().lower()

        installed = str(
            finding.get("installed_version")
            or ""
        ).strip().lower()

        title = str(
            finding.get("title")
            or ""
        ).strip().lower()

        if finding_id:
            key = (
                "id",
                finding_id.lower(),
            )

        elif cve:
            key = (
                "cve",
                cve,
                package,
                installed,
            )

        elif ghsa:
            key = (
                "advisory",
                ghsa,
                package,
                installed,
            )

        elif finding_id.lower().startswith(
            "cl-dep-unpinned"
        ):
            key = (
                "unpin",
                package,
            )

        else:
            key = (
                "fallback",
                package,
                installed,
                title,
            )

        if key in seen:
            continue

        seen.add(key)
        unique.append(finding)

    return unique
def build_scan_response(
    scan_type: str,
    target_name: str,
    findings: list[dict[str, Any]],
    extra_metadata: dict[str, Any] | None = None,
):
    # =====================================================
    # 1. توحيد وتنظيف النتائج
    # =====================================================

    normalized = normalize_findings(
        deduplicate_security_findings(
            findings
        )
    )

    # =====================================================
    # 1.5 حساب CVSS v3.1 حقيقي لكل Finding
    #
    # لازم يصير هون، قبل استدعاء AI Engine، لأن الـ prompt
    # الخاص بالمحلل الذكي ممنوع يخترع أو يغيّر CVSS - فقط
    # يفسّرها. فيجب أن تكون القيمة موجودة مسبقًا بالـ finding.
    # =====================================================

    try:
        normalized = apply_cvss_to_findings(normalized)
    except Exception as exc:
        print(
            "[CyberLens] CVSS scoring failed:",
            str(exc)[:500],
        )

    # =====================================================
    # 2. حساب Security Score
    # =====================================================

    score_data = calculate_security_score(
        normalized
    )
    # =====================================================
    # 3. تشغيل AI Security Analyst
    #
    # يعمل محليًا دائمًا.
    # وإذا تم إعداد OpenAI لاحقًا يمكن أن ينتقل
    # للوضع الخارجي تلقائيًا.
    # =====================================================

    ai_analysis = explain_findings_with_ai(
        findings=normalized,
        target_name=target_name,
        scan_type=scan_type,
    )
        # =====================================================
    # UNIFIED AI FINDINGS
    # توحيد تحليل الذكاء الاصطناعي مع نتائج الفحص الأساسية
    # =====================================================

    try:
        detailed_analysis = (
            ai_analysis.get("detailed_analysis", [])
            if isinstance(ai_analysis, dict)
            else []
        )

        if isinstance(detailed_analysis, list):
            details_by_id = {}

            for detail in detailed_analysis:
                if not isinstance(detail, dict):
                    continue

                finding_id = detail.get("finding_id")

                if finding_id:
                    details_by_id[str(finding_id)] = detail

            for finding in normalized:
                if not isinstance(finding, dict):
                    continue

                # ملاحظة إصلاح: normalize_findings() لا يضيف مفتاح
                # "finding_id" أبدًا (فقط "id")، لذلك كان هذا الشرط
                # يتجاهل كل finding بصمت ولا يربط تحليل AI أبدًا.
                # الإصلاح: الرجوع لـ "id" كذلك.
                finding_id = (
                    finding.get("finding_id")
                    or finding.get("id")
                )

                if not finding_id:
                    continue

                detail = details_by_id.get(str(finding_id))

                if not detail:
                    continue

                # الاحتفاظ بتحليل AI كاملًا داخل نفس Finding
                finding["ai_analysis"] = detail

                # الحقول العلمية الموحدة
                if detail.get("what_is_the_issue"):
                    finding["description"] = detail["what_is_the_issue"]

                if detail.get("technical_analysis"):
                    finding["technical_analysis"] = (
                        detail["technical_analysis"]
                    )

                if detail.get("why_detected"):
                    finding["why_detected"] = (
                        detail["why_detected"]
                    )

                if detail.get("why_it_matters"):
                    finding["why_it_matters"] = (
                        detail["why_it_matters"]
                    )

                if detail.get("security_impact"):
                    finding["security_impact"] = (
                        detail["security_impact"]
                    )

                if detail.get("recommended_fix"):
                    finding["recommendation"] = (
                        detail["recommended_fix"]
                    )

                if detail.get("verification"):
                    finding["verification"] = (
                        detail["verification"]
                    )

                if detail.get("false_positive_note"):
                    finding["false_positive_note"] = (
                        detail["false_positive_note"]
                    )

                if detail.get("owasp"):
                    finding["owasp"] = detail["owasp"]

                if detail.get("cwe"):
                    finding["cwe"] = detail["cwe"]

    except Exception as exc:
        print(
            "[CyberLens] Unified AI findings merge failed:",
            str(exc)[:500],
        )

    # =====================================================
    # 4. تجهيز Metadata
    # =====================================================

    metadata = (
        extra_metadata
        if isinstance(
            extra_metadata,
            dict,
        )
        else {}
    )
    metadata["ai_analysis"] = ai_analysis
    # =====================================================
    # 5. حفظ الفحص في قاعدة البيانات
    # =====================================================

    scan_id = save_scan_result(
        scan_type=scan_type,
        target_name=target_name,
        security_score=score_data["score"],
        highest_severity=score_data[
            "highest_severity"
        ],
        findings=normalized,
        metadata=metadata,
        user_id=current_user_id(),
    )

    # =====================================================
    # 6. بناء الاستجابة النهائية
    # =====================================================

    return {
        "scan_id": scan_id,

        "scan_type": scan_type,

        "target_name": target_name,

        "security_score": score_data[
            "score"
        ],

        "risk_level": score_data[
            "risk_level"
        ],

        "highest_severity": score_data[
            "highest_severity"
        ],

        "severity_counts": score_data[
            "severity_counts"
        ],

        "total_findings": len(
            normalized
        ),

        "findings": normalized,

        "ai_analysis": ai_analysis,

        "metadata": metadata,
    }
    return {
        "scan_id": scan_id,
        "scan_type": scan_type,
        "target_name": target_name,
        "security_score": score_data["score"],
        "risk_level": score_data["risk_level"],
        "highest_severity": score_data["highest_severity"],
        "severity_counts": score_data["severity_counts"],
        "total_findings": len(normalized),
        "findings": normalized,
        "metadata": extra_metadata or {},
    }


def save_uploaded_file(uploaded_file) -> Path:
    """
    يحفظ الملف باسم فريد داخل UPLOAD_DIR.
    البادئة العشوائية ضرورية: بدونها يتصادم مستخدمان يرفعان
    ملفًا بنفس الاسم، فيكتب أحدهما فوق ملف الآخر أو يحذفه
    أثناء فحص جارٍ.
    """
    original_name = uploaded_file.filename or ""

    if not original_name:
        raise ValueError("اسم الملف غير موجود.")

    safe_name = secure_filename(original_name)

    # secure_filename يحذف الأسماء العربية بالكامل، فنولّد
    # اسمًا بديلًا مع الحفاظ على الامتداد بدل رفض الملف.
    if not safe_name:
        suffix = Path(original_name).suffix.lower()

        if not re.fullmatch(r"\.[A-Za-z0-9]{1,10}", suffix or ""):
            suffix = ""

        safe_name = f"upload{suffix}"

    # مجلد فريد لكل عملية رفع بدل بادئة على الاسم:
    # هذا يمنع التصادم مع الحفاظ على اسم الملف الأصلي،
    # وهو ضروري لأن فاحص المكتبات يتعرّف على النوع من
    # اسم الملف (requirements.txt، package.json ...).
    target_dir = UPLOAD_DIR / uuid4().hex

    target_dir.mkdir(parents=True, exist_ok=True)

    target_path = target_dir / safe_name

    uploaded_file.save(target_path)

    return target_path


def cleanup_uploaded_file(uploaded_path: Path | None) -> None:
    """يحذف الملف المؤقت ومجلده الفريد."""
    if not uploaded_path:
        return

    try:
        if uploaded_path.exists():
            uploaded_path.unlink()

        parent = uploaded_path.parent

        if parent != UPLOAD_DIR and parent.is_relative_to(UPLOAD_DIR):
            parent.rmdir()

    except OSError:
        pass


# =========================================================
# الواجهة الرئيسية
# =========================================================

@app.get("/")
def home():
    return send_from_directory(FRONTEND_DIR, "index.html")

@app.get("/frontend/<path:filename>")
def serve_frontend_asset(filename):
    return send_from_directory(
        FRONTEND_DIR,
        filename,
    )
@app.get("/dashboard")
def dashboard_page():
    return send_from_directory(FRONTEND_DIR, "dashboard.html")


@app.get("/<path:filename>")
def frontend_files(filename: str):
    """
    يخدم ملفات الواجهة. الملف المفقود الذي له امتداد يعيد
    404 صريحًا بدل index.html، وإلا فإن أي رابط مكسور
    (مثل report.html الخاطئ سابقًا) يفشل بصمت ويظهر وكأنه
    يعمل.
    """
    requested_path = FRONTEND_DIR / filename

    if requested_path.exists() and requested_path.is_file():
        return send_from_directory(FRONTEND_DIR, filename)

    # الملفات ذات الامتداد أصول حقيقية: مفقودة = 404
    if Path(filename).suffix:
        return api_error(
            "الملف المطلوب غير موجود.",
            404,
        )

    # المسارات بلا امتداد مسارات واجهة: نعيد الصفحة الرئيسية
    return send_from_directory(FRONTEND_DIR, "index.html")


# =========================================================
# API: Health Check
# =========================================================


# =========================================================
# Authentication helpers
# =========================================================

def current_user_id() -> int | None:
    value = session.get("user_id")

    if value is None:
        return None

    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def current_user() -> dict[str, Any] | None:
    user_id = current_user_id()

    if user_id is None:
        return None

    return get_user_by_id(user_id)


def require_login_response():
    if current_user_id() is None:
        return api_error(
            "Login is required.",
            401,
        )

    return None





def require_admin_response():
    user = current_user()

    if not user:
        return api_error(
            "Login is required.",
            401,
        )

    if int(user.get("is_admin") or 0) != 1:
        return api_error(
            "Admin permission is required.",
            403,
        )

    return None


@app.get("/api/auth/me")
def auth_me():
    user = current_user()

    return api_success(
        {
            "authenticated": user is not None,
            "user": user,
        },
        "Authentication status loaded.",
    )



@app.post("/api/auth/register")
def auth_register():
    return api_error(
        "Public registration is disabled. Ask the admin to create an account.",
        403,
    )


# =========================================================
# تحديد معدل محاولات الدخول
# =========================================================
# نافذة منزلقة في الذاكرة. ملاحظة: كل عامل gunicorn له
# ذاكرته الخاصة، فمع عدة عمّال استخدم Redis أو
# Flask-Limiter للحصول على حد مشترك دقيق.
# =========================================================

LOGIN_MAX_ATTEMPTS = 5

LOGIN_WINDOW_SECONDS = 300

_login_attempts: dict[str, deque] = defaultdict(deque)

# تجزئة وهمية لتثبيت زمن الرد ومنع تعداد المستخدمين
_DUMMY_HASH = generate_password_hash("cyberlens-timing-equalizer")


def login_rate_limit_key() -> str:
    return request.remote_addr or "unknown"


def login_is_rate_limited(key: str) -> bool:
    now = time.monotonic()
    attempts = _login_attempts[key]

    while attempts and now - attempts[0] > LOGIN_WINDOW_SECONDS:
        attempts.popleft()

    return len(attempts) >= LOGIN_MAX_ATTEMPTS


def register_failed_login(key: str) -> None:
    _login_attempts[key].append(time.monotonic())


@app.post("/api/auth/login")
def auth_login():
    rate_key = login_rate_limit_key()

    if login_is_rate_limited(rate_key):
        return api_error(
            "Too many login attempts. Try again later.",
            429,
        )

    payload = request.get_json(silent=True) or {}

    username = str(payload.get("username") or "").strip()
    password = str(payload.get("password") or "")

    user = get_user_by_username(username)

    if user is None:
        # نُجري تجزئة وهمية حتى يتساوى زمن الرد مع حالة
        # المستخدم الموجود، فلا يُستدل على الأسماء الصحيحة.
        check_password_hash(_DUMMY_HASH, password)

        register_failed_login(rate_key)

        return api_error(
            "Invalid username or password.",
            401,
        )

    if not check_password_hash(
        user["password_hash"],
        password,
    ):
        register_failed_login(rate_key)

        return api_error(
            "Invalid username or password.",
            401,
        )

    if int(user.get("is_active") or 0) != 1:
        return api_error(
            "This account is disabled.",
            403,
        )

    _login_attempts.pop(rate_key, None)

    # تجديد الجلسة بعد المصادقة يمنع تثبيت الجلسة
    session.clear()
    session["user_id"] = int(user["id"])

    return api_success(
        {
            "authenticated": True,
            "user": get_user_by_id(user["id"]),
        },
        "Logged in successfully.",
    )



@app.post("/api/auth/logout")
def auth_logout():
    session.clear()

    return api_success(
        {
            "authenticated": False,
            "user": None,
        },
        "Logged out successfully.",
    )



SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


@app.before_request
def block_cross_site_requests():
    """
    حماية CSRF عبر التحقق من مصدر الطلب.
    ضرورية لأن المصادقة تعتمد على كوكي الجلسة: بدون هذا
    الفحص يستطيع موقع خبيث إرسال POST نيابة عن مستخدم
    مسجّل الدخول (رفع ملف أو تعطيل حساب).
    """
    if request.method in SAFE_METHODS:
        return None

    if not request.path.startswith("/api/"):
        return None

    origin = request.headers.get("Origin")
    referer = request.headers.get("Referer")

    expected_host = request.host

    def host_of(value: str) -> str:
        try:
            return urlparse(value).netloc
        except Exception:
            return ""

    if origin:
        if host_of(origin) != expected_host:
            return api_error(
                "Cross-site request blocked.",
                403,
            )

    elif referer:
        if host_of(referer) != expected_host:
            return api_error(
                "Cross-site request blocked.",
                403,
            )

    # غياب الترويستين معًا يعني عميلًا غير متصفح (curl مثلًا).
    # المتصفحات ترسل Origin دائمًا في الطلبات المُغيِّرة،
    # و SameSite=Lax يغطي هذه الحالة.
    return None


@app.before_request
def require_auth_for_private_api():
    path = request.path

    public_api = (
        path.startswith("/api/auth/")
        or path == "/api/health"
    )

    if path.startswith("/api/") and not public_api:
        if current_user_id() is None:
            return api_error(
                "Login is required.",
                401,
            )



@app.get("/api/admin/users")
def admin_users():
    admin_error = require_admin_response()

    if admin_error:
        return admin_error

    users = list_users_with_stats()

    return api_success(
        users,
        "Users loaded successfully.",
    )



@app.post("/api/admin/users")
def admin_create_user():
    admin_error = require_admin_response()

    if admin_error:
        return admin_error

    payload = request.get_json(silent=True) or {}

    username = str(payload.get("username") or "").strip()
    password = str(payload.get("password") or "")

    if len(username) < 3:
        return api_error(
            "Username must be at least 3 characters.",
            400,
        )

    if len(password) < 6:
        return api_error(
            "Password must be at least 6 characters.",
            400,
        )

    try:
        user_id = create_user(
            username,
            generate_password_hash(password),
        )

        return api_success(
            {
                "user": get_user_by_id(user_id),
            },
            "User created successfully.",
        )

    except ValueError as exc:
        return api_error(str(exc), 400)



@app.post("/api/admin/users/<int:user_id>/active")
def admin_set_user_active(user_id: int):
    admin_error = require_admin_response()

    if admin_error:
        return admin_error

    if user_id == current_user_id():
        return api_error(
            "You cannot disable your own admin account.",
            400,
        )

    payload = request.get_json(silent=True)

    # بدون هذا الفحص يتحوّل طلب بلا جسم JSON إلى
    # is_active=False، أي تعطيل صامت للحساب.
    if not isinstance(payload, dict) or "is_active" not in payload:
        return api_error(
            "Field 'is_active' is required.",
            400,
        )

    is_active = bool(payload.get("is_active"))

    updated = set_user_active(
        user_id,
        is_active,
    )

    if not updated:
        return api_error(
            "User not found.",
            404,
        )

    return api_success(
        {
            "user_id": user_id,
            "is_active": is_active,
        },
        "User status updated successfully.",
    )



# =========================================================
# Default admin setup
# =========================================================

def ensure_default_admin():
    """
    ينشئ حساب المدير الأول من متغيرات البيئة فقط.
    لا توجد بيانات اعتماد افتراضية في الكود إطلاقًا:
    إن لم تُضبط المتغيرات لا يُنشأ أي حساب.
    """
    username = os.environ.get(
        "CYBERLENS_ADMIN_USERNAME",
        "",
    ).strip()

    password = os.environ.get(
        "CYBERLENS_ADMIN_PASSWORD",
        "",
    )

    if not username or not password:
        print(
            "[CyberLens] لم يُنشأ حساب مدير: اضبط "
            "CYBERLENS_ADMIN_USERNAME و CYBERLENS_ADMIN_PASSWORD."
        )
        return

    if len(password) < 12:
        raise RuntimeError(
            "CYBERLENS_ADMIN_PASSWORD يجب ألا تقل عن 12 محرفًا."
        )

    existing = get_user_by_username(
        username
    )

    if existing:
        return

    create_user(
        username,
        generate_password_hash(password),
        is_admin=1,
        is_active=1,
    )

    print(f"[CyberLens] تم إنشاء حساب المدير: {username}")


# =========================================================
# التهيئة عند الاستيراد
# =========================================================
# هذه السطور تعمل مع gunicorn ومع التشغيل المباشر على السواء.
# init_database يجب أن تسبق ensure_default_admin لأن الأخيرة
# تستعلم عن جدول users.
# =========================================================

init_database()
ensure_default_admin()


@app.after_request
def apply_security_headers(response):
    """
    ترويسات الأمان.

    أداة تفحص ترويسات الأمان في المواقع يجب أن تطبّقها على نفسها،
    وإلا رسبت في فحص ذاتها. هذه الترويسات هي ما يفحصه
    passive_web_scanner في الأهداف تحت القواعد CL-URL-H001 وما بعدها.
    """
    is_production = os.environ.get("FLASK_ENV", "development").lower() == "production"

    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault(
        "Permissions-Policy",
        "geolocation=(), microphone=(), camera=()",
    )
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "frame-ancestors 'none'",
    )

    if is_production:
        response.headers.setdefault(
            "Strict-Transport-Security",
            "max-age=31536000; includeSubDomains",
        )

    return response


@app.get("/api/health")
def health_check():
    return api_success(
        {
            "service": "CyberLens",
            "status": "online",
            "version": "1.0.0",
        },
        "CyberLens تعمل بنجاح",
    )


# =========================================================
# API: Dashboard
# =========================================================


def current_user_is_scan_admin():
    """
    يتحقق إن كان المستخدم الحالي مديرًا.
    """
    user_id = current_user_id()

    if user_id is None:
        return False

    user = get_user_by_id(user_id)

    return bool(
        user
        and int(user.get("is_admin") or 0) == 1
    )


def scan_scope_user_id():
    """
    يحدد نطاق الفحوصات المرئية للمستخدم.
    المدير يرى كل الفحوصات (None)، وغيره يرى فحوصاته فقط.
    """
    if current_user_is_scan_admin():
        return None

    return current_user_id()


def require_scan_ownership(scan):
    """
    يمنع المستخدم من فتح فحص لا يملكه.
    المدير مستثنى ويصل إلى كل الفحوصات.
    """
    if scan is None:
        return None

    user_id = current_user_id()

    if user_id is None:
        return api_error(
            "Login is required.",
            401,
        )

    if current_user_is_scan_admin():
        return None

    owner_id = scan.get("user_id")

    if owner_id is None:
        return api_error(
            "You do not have permission to access this scan.",
            403,
        )

    if int(owner_id) != int(user_id):
        return api_error(
            "You do not have permission to access this scan.",
            403,
        )

    return None


@app.get("/api/dashboard")
def dashboard_data():
    try:
        user_scans = get_scan_history(
            limit=100,
            user_id=scan_scope_user_id(),
        )

        total_scans = len(user_scans)

        total_findings = sum(
            int(scan.get("total_findings") or 0)
            for scan in user_scans
        )

        scores = [
            int(scan.get("security_score") or 100)
            for scan in user_scans
        ]

        average_score = (
            round(sum(scores) / len(scores))
            if scores
            else 100
        )

        lowest_score = (
            min(scores)
            if scores
            else 100
        )

        highest_score = (
            max(scores)
            if scores
            else 100
        )

        scan_type_counts = {}

        highest_severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
            "unknown": 0,
        }

        for scan in user_scans:
            scan_type = str(
                scan.get("scan_type") or "unknown"
            )

            scan_type_counts[scan_type] = (
                scan_type_counts.get(scan_type, 0) + 1
            )

            severity = str(
                scan.get("highest_severity") or "unknown"
            ).lower()

            if severity not in highest_severity_counts:
                severity = "unknown"

            highest_severity_counts[severity] += 1

        statistics = {
            "summary": {
                "total_scans": total_scans,
                "average_score": average_score,
                "lowest_score": lowest_score,
                "highest_score": highest_score,
                "total_findings": total_findings,
            },
            "total_scans": total_scans,
            "average_score": average_score,
            "total_findings": total_findings,
            "scan_type_counts": scan_type_counts,
            "highest_severity_counts": highest_severity_counts,
            "severity_counts": highest_severity_counts,
            "latest_scan": (
                user_scans[0]
                if user_scans
                else None
            ),
            "recent_scans": user_scans[:10],
        }

        return api_success(
            statistics,
            "تم تحميل بيانات لوحة التحكم",
        )

    except Exception as exc:
        msg = str(exc)
        try:
            msg = msg.replace(os.environ.get('DATABASE_URL', ''), '<DATABASE_URL>')
        except Exception:
            pass

        print(
            '[CyberLens ERROR]',
            type(exc).__name__,
            msg[:1000]
        )

        return api_error(
            "تعذر تحميل بيانات لوحة التحكم.",
            500,
        )


# =========================================================
# API: سجل الفحوصات
# =========================================================

@app.get("/api/scans")
def scans_history():
    try:
        limit_raw = request.args.get("limit", "20")

        try:
            limit = int(limit_raw)
        except ValueError:
            limit = 20

        limit = max(1, min(limit, 100))

        scans = get_scan_history(
            limit=limit,
            user_id=scan_scope_user_id(),
        )

        return api_success(
            scans,
            "تم تحميل سجل الفحوصات",
        )

    except Exception as exc:
        msg = str(exc)

        try:
            msg = msg.replace(
                os.environ.get(
                    "DATABASE_URL",
                    ""
                ),
                "<DATABASE_URL>",
            )
        except Exception:
            pass

        print(
            "[CyberLens ERROR]",
            type(exc).__name__,
            msg[:1000],
        )

        return api_error(
            "تعذر تحميل سجل الفحوصات.",
            500,
        )


@app.get("/api/scans/<int:scan_id>")
def scan_details(scan_id: int):
    try:
        scan = get_scan_by_id(scan_id)

        if scan is None:
            return api_error(
                "الفحص المطلوب غير موجود.",
                404,
            )

        scan_access_error = require_scan_ownership(scan)

        if scan_access_error:
            return scan_access_error

        return api_success(
            scan,
            "تم تحميل تفاصيل الفحص",
        )

    except Exception as exc:
        msg = str(exc)
        try:
            msg = msg.replace(os.environ.get('DATABASE_URL', ''), '<DATABASE_URL>')
        except Exception:
            pass

        print(
            '[CyberLens ERROR]',
            type(exc).__name__,
            msg[:1000],
        )

        return api_error(
            "تعذر تحميل تفاصيل الفحص.",
            500,
        )


@app.get("/api/scans/<int:scan_id>/report.pdf")
def download_scan_report(scan_id: int):
    try:
        scan = get_scan_by_id(scan_id)

        if scan is None:
            return api_error(
                "الفحص المطلوب غير موجود.",
                404,
            )

        scan_access_error = require_scan_ownership(scan)

        if scan_access_error:
            return scan_access_error

        pdf_buffer = build_pdf_report(
            scan
        )

        return send_file(
            pdf_buffer,
            mimetype="application/pdf",
            as_attachment=True,
            download_name=(
                f"cyberlens_scan_{scan_id}.pdf"
            ),
            max_age=0,
        )

    except PDFReportError as exc:
        return api_error(
            str(exc),
            500,
        )

    except Exception as exc:
        msg = str(exc)
        try:
            msg = msg.replace(os.environ.get('DATABASE_URL', ''), '<DATABASE_URL>')
        except Exception:
            pass
        print('[CyberLens ERROR]', type(exc).__name__, msg[:1000])
        return api_error(
            "تعذر إنشاء تقرير PDF: "
            + str(exc),
            500,
        )


    # =========================================================
# API: فحص الروابط
# =========================================================


@app.get("/api/scans/<int:scan_id>/report/view")
def view_scan_report(scan_id: int):
    try:
        scan = get_scan_by_id(scan_id)

        if scan is None:
            return api_error(
                "Scan not found.",
                404,
            )

        scan_access_error = require_scan_ownership(scan)

        if scan_access_error:
            return scan_access_error

        pdf_buffer = build_pdf_report(
            scan
        )

        return send_file(
            pdf_buffer,
            mimetype="application/pdf",
            as_attachment=False,
            download_name=(
                f"cyberlens_scan_{scan_id}.pdf"
            ),
            max_age=0,
        )

    except PDFReportError as exc:
        return api_error(
            str(exc),
            500,
        )

    except Exception as exc:
        msg = str(exc)
        try:
            msg = msg.replace(os.environ.get('DATABASE_URL', ''), '<DATABASE_URL>')
        except Exception:
            pass
        print('[CyberLens ERROR]', type(exc).__name__, msg[:1000])
        return api_error(
            "Could not view PDF report: "
            + str(exc),
            500,
        )



@app.get("/api/scans/<int:scan_id>/report/inline")
def inline_scan_report(scan_id: int):
    try:
        import base64

        scan = get_scan_by_id(scan_id)

        if scan is None:
            return api_error(
                "Scan not found.",
                404,
            )

        scan_access_error = require_scan_ownership(scan)

        if scan_access_error:
            return scan_access_error

        pdf_buffer = build_pdf_report(
            scan
        )

        pdf_base64 = base64.b64encode(
            pdf_buffer.getvalue()
        ).decode("ascii")

        html = (
            "<!doctype html>"
            "<html lang='ar' dir='rtl'>"
            "<head>"
            "<meta charset='utf-8'>"
            "<title>CyberLens PDF Report</title>"
            "<style>"
            "html,body{margin:0;width:100%;height:100%;background:#0f172a;}"
            "header{height:52px;display:flex;align-items:center;justify-content:space-between;"
            "padding:0 18px;color:white;font-family:Arial,sans-serif;background:#111827;}"
            "iframe{width:100%;height:calc(100vh - 52px);border:0;background:white;}"
            "a{color:white;text-decoration:none;border:1px solid rgba(255,255,255,.35);"
            "padding:8px 12px;border-radius:10px;}"
            "</style>"
            "</head>"
            "<body>"
            "<header>"
            "<strong>CyberLens PDF Report</strong>"
            "<a href='/'>Back to CyberLens</a>"
            "</header>"
            "<iframe title='CyberLens PDF Report' src='data:application/pdf;base64,"
            + pdf_base64 +
            "'></iframe>"
            "</body>"
            "</html>"
        )

        return html, 200, {
            "Content-Type": "text/html; charset=utf-8",
            "Cache-Control": "no-store",
        }

    except PDFReportError as exc:
        return api_error(
            str(exc),
            500,
        )

    except Exception as exc:
        msg = str(exc)
        try:
            msg = msg.replace(os.environ.get('DATABASE_URL', ''), '<DATABASE_URL>')
        except Exception:
            pass
        print('[CyberLens ERROR]', type(exc).__name__, msg[:1000])
        return api_error(
            "Could not open inline PDF report: "
            + str(exc),
            500,
        )


@app.post("/api/scan/url")
def url_scan_endpoint():
    try:
        payload = request.get_json(silent=True) or {}

        url = str(payload.get("url", "")).strip()

        if not url:
            return api_error(
                "الرجاء إدخال رابط للفحص.",
                400,
            )

        if len(url) > 2048:
            return api_error(
                "الرابط طويل جدًا.",
                400,
            )

        result = scan_url(url)

        findings = result.get("findings", [])

        response_data = build_scan_response(
            scan_type="url",
            target_name=url,
            findings=findings,
            extra_metadata={
                "normalized_url": result.get("normalized_url"),
                "domain": result.get("domain"),
                "scheme": result.get("scheme"),
                "risk_indicators": result.get("risk_indicators", []),
            },
        )

        return api_success(
            response_data,
            "اكتمل فحص الرابط",
        )

    except ValueError as exc:
        return api_error(str(exc), 400)

    except Exception as exc:
        msg = str(exc)
        try:
            msg = msg.replace(os.environ.get('DATABASE_URL', ''), '<DATABASE_URL>')
        except Exception:
            pass
        print('[CyberLens ERROR]', type(exc).__name__, msg[:1000])
        return api_error(
            "حدث خطأ أثناء فحص الرابط.",
            500,
        )


# =========================================================
# API: فحص الأكواد
# =========================================================

@app.post("/api/scan/code")
def code_scan_endpoint():
    uploaded_path: Path | None = None

    try:
        if "file" not in request.files:
            return api_error(
                "الرجاء اختيار ملف كود.",
                400,
            )

        uploaded_file = request.files["file"]

        if not uploaded_file.filename:
            return api_error(
                "لم يتم اختيار ملف.",
                400,
            )

        filename = uploaded_file.filename
        extension = Path(filename).suffix.lower()

        if extension not in CODE_EXTENSIONS:
            return api_error(
                f"امتداد الملف غير مدعوم: {extension or 'بدون امتداد'}",
                400,
            )

        uploaded_path = save_uploaded_file(uploaded_file)

        scan_result = scan_code_file(uploaded_path)

        findings = scan_result.get("findings", [])

        response_data = build_scan_response(
            scan_type="code",
            target_name=filename,
            findings=findings,
            extra_metadata={
                "language": scan_result.get("language"),
                "lines_scanned": scan_result.get("lines_scanned", 0),
                "file_size": scan_result.get("file_size", 0),
            },
        )

        return api_success(
            response_data,
            "اكتمل فحص الكود",
        )

    except ValueError as exc:
        return api_error(str(exc), 400)

    except UnicodeDecodeError:
        return api_error(
            "تعذر قراءة الملف كنص برمجي.",
            400,
        )

    except Exception as exc:
        msg = str(exc)
        try:
            msg = msg.replace(os.environ.get('DATABASE_URL', ''), '<DATABASE_URL>')
        except Exception:
            pass
        print('[CyberLens ERROR]', type(exc).__name__, msg[:1000])
        return api_error(
            "حدث خطأ أثناء فحص الكود.",
            500,
        )

    finally:
        cleanup_uploaded_file(uploaded_path)
# =========================================================
# Project ZIP Scan API
# =========================================================

@app.post("/api/scan/project")
def project_scan_endpoint():
    uploaded_path: Path | None = None

    try:
        # =================================================
        # 1. التأكد من وجود ملف
        # =================================================

        if "file" not in request.files:
            return api_error(
                "الرجاء اختيار ملف مشروع ZIP.",
                400,
            )

        uploaded_file = request.files[
            "file"
        ]

        if not uploaded_file.filename:
            return api_error(
                "لم يتم اختيار ملف.",
                400,
            )

        # =================================================
        # 2. تنظيف اسم الملف
        # =================================================

        filename = Path(
            uploaded_file.filename
        ).name

        # =================================================
        # 3. السماح بملفات ZIP فقط
        # =================================================

        if (
            Path(
                filename
            ).suffix.lower()
            != ".zip"
        ):
            return api_error(
                "فحص المشروع يدعم ملفات ZIP فقط.",
                400,
                {
                    "supported_files": [
                        ".zip"
                    ],
                },
            )

        # =================================================
        # 4. حفظ الملف مؤقتًا
        # =================================================

        uploaded_path = save_uploaded_file(
            uploaded_file
        )

        # =================================================
        # 5. تشغيل Safe Project Scanner
        # =================================================

        scan_result = scan_project_archive(
            uploaded_path
        )

        findings = scan_result.get(
            "findings",
            [],
        )

        if not isinstance(
            findings,
            list,
        ):
            findings = []

        # =================================================
        # 6. بناء الاستجابة
        #
        # build_scan_response سيقوم بـ:
        # - Security Score
        # - AI Security Analyst
        # - Correlations
        # - SQLite Save
        # =================================================

        response_data = build_scan_response(
            scan_type="project",

            target_name=filename,

            findings=findings,

            extra_metadata={
                "project_name": scan_result.get(
                    "project_name"
                ),

                "archive_type": scan_result.get(
                    "archive_type"
                ),

                "engine": scan_result.get(
                    "engine"
                ),

                "files_discovered": scan_result.get(
                    "files_discovered",
                    0,
                ),

                "code_files_discovered": scan_result.get(
                    "code_files_discovered",
                    0,
                ),

                "dependency_files_discovered": scan_result.get(
                    "dependency_files_discovered",
                    0,
                ),

                "other_files_discovered": scan_result.get(
                    "other_files_discovered",
                    0,
                ),

                "code_files_scanned": scan_result.get(
                    "code_files_scanned",
                    0,
                ),

                "dependency_files_scanned": scan_result.get(
                    "dependency_files_scanned",
                    0,
                ),

                "dependency_scans": scan_result.get(
                    "dependency_scans",
                    [],
                ),
                "total_errors": scan_result.get(
                    "total_errors",
                    0,
                ),

                "errors": scan_result.get(
                    "errors",
                    [],
                ),

                "extraction": scan_result.get(
                    "extraction",
                    {},
                ),

                "security": scan_result.get(
                    "security",
                    {},
                ),
            },
        )

        # =================================================
        # 7. نجاح
        # =================================================

        return api_success(
            response_data,
            "اكتمل فحص المشروع",
        )

    except ValueError as exc:
        return api_error(
            str(exc),
            400,
        )

    except Exception as exc:
        msg = str(exc)
        try:
            msg = msg.replace(os.environ.get('DATABASE_URL', ''), '<DATABASE_URL>')
        except Exception:
            pass
        print('[CyberLens ERROR]', type(exc).__name__, msg[:1000])
        return api_error(
            "حدث خطأ أثناء فحص المشروع.",
            500,
        )

    finally:
        # =================================================
        # 8. حذف ZIP المؤقت دائمًا
        # =================================================

        cleanup_uploaded_file(uploaded_path)


# =========================================================
# API: فحص المكتبات
# =========================================================

@app.post("/api/scan/dependencies")
def dependency_scan_endpoint():
    uploaded_path: Path | None = None

    try:
        if "file" not in request.files:
            return api_error(
                "الرجاء اختيار ملف مكتبات.",
                400,
            )

        uploaded_file = request.files["file"]

        if not uploaded_file.filename:
            return api_error(
                "لم يتم اختيار ملف.",
                400,
            )

        filename = Path(uploaded_file.filename).name
        if filename.lower() not in DEPENDENCY_FILENAMES:
            return api_error(
                "نوع ملف المكتبات غير مدعوم حاليًا.",
                400,
                {
                    "supported_files": sorted(DEPENDENCY_FILENAMES),
                },
            )

        uploaded_path = save_uploaded_file(uploaded_file)

        scan_result = scan_dependency_file(uploaded_path)

        findings = scan_result.get("findings", [])

        response_data = build_scan_response(
            scan_type="dependencies",
            target_name=filename,
            findings=findings,
            extra_metadata={
                "ecosystem": scan_result.get("ecosystem"),
                "packages_scanned": scan_result.get("packages_scanned", 0),
                "packages": scan_result.get("packages", []),
            },
        )

        return api_success(
            response_data,
            "اكتمل فحص المكتبات",
        )

    except ValueError as exc:
        return api_error(str(exc), 400)

    except Exception as exc:
        msg = str(exc)
        try:
            msg = msg.replace(os.environ.get('DATABASE_URL', ''), '<DATABASE_URL>')
        except Exception:
            pass
        print('[CyberLens ERROR]', type(exc).__name__, msg[:1000])
        return api_error(
            "حدث خطأ أثناء فحص المكتبات.",
            500,
        )

    finally:
        cleanup_uploaded_file(uploaded_path)


# =========================================================
# API: شرح النتائج بالذكاء الاصطناعي
# =========================================================

@app.post("/api/ai/explain")
def ai_explain_endpoint():
    try:
        payload = request.get_json(silent=True) or {}

        findings = payload.get("findings", [])
        target_name = str(payload.get("target_name", "Unknown Target"))
        scan_type = str(payload.get("scan_type", "general"))

        if not isinstance(findings, list):
            return api_error(
                "صيغة النتائج غير صحيحة.",
                400,
            )

        if not findings:
            return api_error(
                "لا توجد نتائج لإرسالها إلى المحلل الذكي.",
                400,
            )

        findings = normalize_findings(findings)

        explanation = explain_findings_with_ai(
            findings=findings,
            target_name=target_name,
            scan_type=scan_type,
        )

        return api_success(
            explanation,
            "تم إنشاء التحليل الأمني",
        )

    except Exception as exc:
        msg = str(exc)
        try:
            msg = msg.replace(os.environ.get('DATABASE_URL', ''), '<DATABASE_URL>')
        except Exception:
            pass
        print('[CyberLens ERROR]', type(exc).__name__, msg[:1000])
        return api_error(
            "تعذر إنشاء التحليل الأمني.",
            500,
        )


# =========================================================
# معالجة الأخطاء
# =========================================================

@app.errorhandler(RequestEntityTooLarge)
def handle_large_file(_error):
    return api_error(
        f"حجم الملف أكبر من الحد المسموح وهو {MAX_UPLOAD_SIZE // (1024 * 1024)}MB.",
        413,
    )


@app.errorhandler(404)
def handle_not_found(_error):
    return api_error(
        "المسار المطلوب غير موجود.",
        404,
    )


@app.errorhandler(405)
def handle_method_not_allowed(_error):
    return api_error(
        "طريقة الطلب غير مسموحة لهذا المسار.",
        405,
    )


@app.errorhandler(500)
def handle_internal_error(_error):
    return api_error(
        "حدث خطأ داخلي غير متوقع.",
        500,
    )


@app.get("/api/debug/ai")
def debug_ai_status():
    admin_error = require_admin_response()

    if admin_error:
        return admin_error

    try:
        try:
            from .gemini_ai_provider import check_gemini_status
        except Exception:
            from gemini_ai_provider import check_gemini_status

        status = check_gemini_status()

        return jsonify({
            "success": True,
            "message": "AI debug status loaded.",
            "data": status,
        })

    except Exception as exc:
        return jsonify({
            "success": False,
            "message": "AI debug failed.",
            "error": str(exc)[:700],
        }), 500


# =========================================================
# تشغيل محلي مباشر فقط (python app.py)
# في الإنتاج يُستخدم wsgi.py عبر gunicorn
# =========================================================

if __name__ == "__main__":
    host = os.getenv("HOST", "127.0.0.1")

    try:
        port = int(os.getenv("PORT", "5000"))
    except ValueError:
        port = 5000

    debug_mode = os.getenv("FLASK_DEBUG", "false").lower() == "true"

    print("=" * 60)
    print("CyberLens Security Platform")
    print(f"Local URL: http://127.0.0.1:{port}")
    print(f"Network Host: {host}")
    print(f"Debug: {debug_mode}")
    print("=" * 60)

    app.run(
        host=host,
        port=port,
        debug=debug_mode,
    )
