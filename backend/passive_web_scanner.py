"""
=========================================================
CyberLens - Passive Web Scanner
=========================================================
يقرأ ترويسات HTTP للرابط الهدف دون أي فحص هجومي.

تنبيه أمني: هذه الوحدة هي الوحيدة التي تُصدر طلبًا شبكيًا
إلى عنوان يتحكم به المستخدم، لذلك تحتوي على حاجز SSRF
يمنع الوصول إلى العناوين الداخلية وخدمات بيانات السحابة.
=========================================================
"""

from typing import Any
import ipaddress
import socket
import urllib.error
import urllib.request
from urllib.parse import urlparse


ALLOWED_SCHEMES = {"http", "https"}

MAX_REDIRECTS = 5

REQUEST_TIMEOUT = 8


class BlockedTargetError(ValueError):
    """يُرفع عند محاولة الوصول لعنوان غير عام."""


def _address_is_public(ip_text: str) -> bool:
    try:
        address = ipaddress.ip_address(ip_text)
    except ValueError:
        return False

    # is_global تستبعد loopback والخاصة و link-local
    # والمحجوزة والـ multicast دفعة واحدة.
    # 169.254.169.254 (بيانات السحابة) link-local ومحجوبة هنا.
    return address.is_global


def assert_url_is_public(url: str) -> None:
    """
    يتحقق أن الرابط http/https وأن كل عناوين IP التي يشير
    إليها اسم النطاق عامة. يرفع BlockedTargetError خلاف ذلك.
    """
    parsed = urlparse(url)

    scheme = (parsed.scheme or "").lower()

    if scheme not in ALLOWED_SCHEMES:
        raise BlockedTargetError(
            "يُسمح بروابط HTTP وHTTPS فقط."
        )

    hostname = (parsed.hostname or "").strip()

    if not hostname:
        raise BlockedTargetError(
            "تعذر استخراج اسم النطاق من الرابط."
        )

    port = parsed.port or (443 if scheme == "https" else 80)

    try:
        addresses = socket.getaddrinfo(
            hostname,
            port,
            proto=socket.IPPROTO_TCP,
        )

    except socket.gaierror as exc:
        raise BlockedTargetError(
            "تعذر ترجمة اسم النطاق إلى عنوان IP."
        ) from exc

    if not addresses:
        raise BlockedTargetError(
            "لا يوجد عنوان IP لاسم النطاق."
        )

    for entry in addresses:
        ip_text = entry[4][0]

        if not _address_is_public(ip_text):
            raise BlockedTargetError(
                "تم منع الفحص: الرابط يشير إلى عنوان داخلي "
                "أو محجوز وليس إلى خادم عام."
            )


class GuardedRedirectHandler(urllib.request.HTTPRedirectHandler):
    """
    يسجّل التحويلات ويتحقق من كل وجهة قبل اتباعها، حتى لا
    يُستخدم تحويل من خادم خارجي للوصول للشبكة الداخلية.
    """

    def __init__(self, redirects: list[dict[str, Any]]):
        self.redirects = redirects

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if len(self.redirects) >= MAX_REDIRECTS:
            raise BlockedTargetError(
                "تم تجاوز الحد الأقصى لعدد التحويلات."
            )

        assert_url_is_public(newurl)

        self.redirects.append({"status": code, "url": newurl})

        return super().redirect_request(
            req, fp, code, msg, headers, newurl
        )


def fetch_web_info(url: str) -> dict[str, Any]:
    redirects: list[dict[str, Any]] = []

    try:
        assert_url_is_public(url)

    except BlockedTargetError as exc:
        return {
            "ok": False,
            "blocked": True,
            "error": str(exc),
            "headers": {},
            "cookies": [],
            "redirects": redirects,
        }

    opener = urllib.request.build_opener(
        GuardedRedirectHandler(redirects)
    )

    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "CyberLens Passive Scanner",
            "Accept": "text/html,*/*",
        },
        method="GET",
    )

    try:
        with opener.open(request, timeout=REQUEST_TIMEOUT) as response:
            headers = response.headers
            return {
                "ok": True,
                "status_code": getattr(response, "status", None),
                "final_url": response.geturl(),
                "headers": {
                    str(k).lower(): str(v)
                    for k, v in headers.items()
                },
                "cookies": headers.get_all("Set-Cookie") or [],
                "redirects": redirects,
            }

    except BlockedTargetError as exc:
        return {
            "ok": False,
            "blocked": True,
            "error": str(exc),
            "headers": {},
            "cookies": [],
            "redirects": redirects,
        }

    except urllib.error.HTTPError as exc:
        headers = exc.headers
        return {
            "ok": True,
            "status_code": exc.code,
            "final_url": exc.geturl(),
            "headers": {
                str(k).lower(): str(v)
                for k, v in headers.items()
            },
            "cookies": headers.get_all("Set-Cookie") or [],
            "redirects": redirects,
        }

    except Exception as exc:
        return {
            "ok": False,
            "error": f"{type(exc).__name__}",
            "headers": {},
            "cookies": [],
            "redirects": redirects,
        }


def run_passive_web_checks(url: str, make_finding_func):
    findings = []
    indicators = []

    info = fetch_web_info(url)

    if not info.get("ok"):
        findings.append(
            make_finding_func(
                "CL-URL-W000",
                "تعذر تنفيذ الفحص الشبكي السلبي",
                "info",
                "لم يتمكن CyberLens من قراءة ترويسات HTTP لهذا الرابط.",
                "أعد الفحص لاحقًا أو تحقق من الرابط يدويًا.",
                "low",
                {"error": info.get("error")},
            )
        )
        return findings, indicators, info

    headers = info.get("headers") or {}
    final_url = info.get("final_url") or url
    final_scheme = urlparse(final_url).scheme.lower()

    checks = [
        ("content-security-policy", "CL-URL-H001", "غياب Content-Security-Policy", "medium", "missing_csp"),
        ("x-frame-options", "CL-URL-H003", "غياب X-Frame-Options", "low", "missing_x_frame_options"),
        ("x-content-type-options", "CL-URL-H004", "غياب X-Content-Type-Options", "low", "missing_x_content_type_options"),
        ("referrer-policy", "CL-URL-H005", "غياب Referrer-Policy", "low", "missing_referrer_policy"),
        ("permissions-policy", "CL-URL-H006", "غياب Permissions-Policy", "info", "missing_permissions_policy"),
    ]

    if final_scheme == "https":
        checks.append(
            ("strict-transport-security", "CL-URL-H002", "غياب Strict-Transport-Security", "medium", "missing_hsts")
        )

    for header_name, finding_id, title, severity, indicator in checks:
        if header_name not in headers:
            indicators.append(indicator)
            findings.append(
                make_finding_func(
                    finding_id,
                    title,
                    severity,
                    "هذه الترويسة الأمنية غير موجودة في استجابة الموقع، وقد يقلل ذلك من مستوى الحماية.",
                    "أضف هذه الترويسة الأمنية من إعدادات الخادم أو منصة الاستضافة.",
                    "high",
                    {"missing_header": header_name, "final_url": final_url},
                )
            )

    server_header = headers.get("server")
    if server_header:
        indicators.append("server_header_disclosure")
        findings.append(
            make_finding_func(
                "CL-URL-H007",
                "ظهور ترويسة Server",
                "info",
                "الخادم يعرض معلومات عامة عن نوع السيرفر. هذه ليست ثغرة مباشرة لكنها معلومة تقنية ظاهرة.",
                "قلل المعلومات الظاهرة في ترويسة Server إن أمكن.",
                "medium",
                {"server": server_header},
            )
        )

    if len(info.get("redirects") or []) >= 3:
        indicators.append("long_redirect_chain")
        findings.append(
            make_finding_func(
                "CL-URL-H009",
                "سلسلة تحويلات طويلة",
                "low",
                "الرابط مر بعدة Redirects قبل الوصول للوجهة النهائية.",
                "قلل عدد التحويلات وتأكد أن كل تحويل ضروري وآمن.",
                "medium",
                {"redirects": info.get("redirects")},
            )
        )

    for cookie in (info.get("cookies") or [])[:5]:
        low = cookie.lower()
        missing = []

        if final_scheme == "https" and "secure" not in low:
            missing.append("Secure")

        if "httponly" not in low:
            missing.append("HttpOnly")

        if "samesite" not in low:
            missing.append("SameSite")

        if missing:
            indicators.append("cookie_missing_security_flags")
            findings.append(
                make_finding_func(
                    "CL-URL-H008",
                    "Cookie بدون خصائص حماية كافية",
                    "medium",
                    "تم العثور على Cookie لا تحتوي على بعض خصائص الحماية المهمة.",
                    "أضف Secure وHttpOnly وSameSite للكوكيز الحساسة.",
                    "medium",
                    {"missing_flags": missing},
                )
            )

    return findings, indicators, info
