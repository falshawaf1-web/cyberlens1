from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from packaging.version import InvalidVersion, Version


# =========================================================
# إعدادات عامة
# =========================================================

OSV_QUERYBATCH_URL = "https://api.osv.dev/v1/querybatch"

OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{vuln_id}"

HTTP_TIMEOUT = 20

MAX_PACKAGES = 300

MAX_VULN_DETAILS = 150


SUPPORTED_FILES = {
    "requirements.txt",
    "package.json",
    "package-lock.json",
    "composer.lock",
    "go.mod",
    "cargo.lock",
}


SEVERITY_RANK = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
}


# =========================================================
# إنشاء Finding موحد
# =========================================================

def make_finding(
    finding_id: str,
    title: str,
    severity: str,
    description: str,
    recommendation: str,
    **extra: Any,
) -> dict[str, Any]:
    item: dict[str, Any] = {
        "id": finding_id,
        "title": title,
        "severity": severity,
        "description": description,
        "recommendation": recommendation,
        "source": "OSV / CyberLens Dependency Scanner",
        "confidence": "high",
        "metadata": {},
    }

    item.update(extra)

    return item


# =========================================================
# قراءة النصوص مع دعم الترميزات
# =========================================================

def read_text(
    path: Path,
) -> str:
    if not path.exists():
        raise ValueError(
            "الملف المطلوب غير موجود."
        )

    if not path.is_file():
        raise ValueError(
            "المسار المحدد ليس ملفًا."
        )

    raw = path.read_bytes()

    # -----------------------------------------------------
    # BOM Detection
    # -----------------------------------------------------

    if raw.startswith(b"\xff\xfe"):
        try:
            return raw.decode("utf-16")
        except UnicodeDecodeError:
            pass

    if raw.startswith(b"\xfe\xff"):
        try:
            return raw.decode("utf-16")
        except UnicodeDecodeError:
            pass

    if raw.startswith(b"\xef\xbb\xbf"):
        try:
            return raw.decode("utf-8-sig")
        except UnicodeDecodeError:
            pass

    # -----------------------------------------------------
    # Fallback Encodings
    # -----------------------------------------------------

    for encoding in (
        "utf-8-sig",
        "utf-8",
        "utf-16",
        "utf-16-le",
        "utf-16-be",
        "cp1256",
        "cp1252",
        "latin-1",
    ):
        try:
            return raw.decode(
                encoding
            )

        except UnicodeDecodeError:
            continue

    raise ValueError(
        "تعذر قراءة ترميز الملف."
    )


# =========================================================
# تنظيف الإصدار
# =========================================================

def exact_version(
    raw: str,
) -> str | None:
    value = str(
        raw or ""
    ).strip()

    if not value:
        return None

    value = re.sub(
        r"^[vV]",
        "",
        value,
    ).strip()

    # -----------------------------------------------------
    # رفض Version Ranges
    # -----------------------------------------------------

    if any(
        token in value
        for token in (
            "*",
            "||",
            " ",
            ",",
            "<",
            ">",
            "^",
            "~",
        )
    ):
        return None

    # -----------------------------------------------------
    # رفض مصادر غير إصدارات رقمية واضحة
    # -----------------------------------------------------

    if value.startswith(
        (
            "git+",
            "http://",
            "https://",
            "file:",
            "workspace:",
            "link:",
        )
    ):
        return None
    return value or None


# =========================================================
# Package Record
# =========================================================

def package(
    name: str,
    version: str | None,
    ecosystem: str,
    source: str,
) -> dict[str, Any]:
    clean_name = str(
        name or ""
    ).strip()

    clean_version = (
        str(version).strip()
        if version is not None
        else None
    )

    return {
        "name": clean_name,
        "version": clean_version,
        "ecosystem": ecosystem,
        "source": source,
        "queryable": bool(
            clean_name
            and clean_version
        ),
    }


# =========================================================
# requirements.txt
# =========================================================

def parse_requirements(
    path: Path,
) -> list[dict[str, Any]]:
    items: list[
        dict[str, Any]
    ] = []

    content = read_text(
        path
    )

    for raw_line in content.splitlines():
        line = raw_line.strip()

        if not line:
            continue

        if line.startswith(
            (
                "#",
                "-r",
                "--",
                "git+",
                "http://",
                "https://",
            )
        ):
            continue

        # -------------------------------------------------
        # إزالة Environment Marker
        # -------------------------------------------------

        value = (
            line
            .split(";", 1)[0]
            .split(" #", 1)[0]
            .strip()
        )

        if not value:
            continue

        # -------------------------------------------------
        # إصدار مثبت بـ ==
        #
        # مثال:
        # Flask==3.1.3
        # requests[socks]==2.32.0
        # -------------------------------------------------

        pinned = re.match(
            r"^([A-Za-z0-9_.-]+)"
            r"(?:\[[^\]]+\])?"
            r"\s*==\s*"
            r"([^\s]+)$",
            value,
        )

        if pinned:
            items.append(
                package(
                    name=pinned.group(1),
                    version=exact_version(
                        pinned.group(2)
                    ),
                    ecosystem="PyPI",
                    source="requirements.txt",
                )
            )

            continue

        # -------------------------------------------------
        # مكتبة غير مثبتة بإصدار واضح
        # -------------------------------------------------

        name_match = re.match(
            r"^([A-Za-z0-9_.-]+)",
            value,
        )

        if name_match:
            items.append(
                package(
                    name=name_match.group(1),
                    version=None,
                    ecosystem="PyPI",
                    source="requirements.txt",
                )
            )

    return items


# =========================================================
# package.json
# =========================================================

def parse_package_json(
    path: Path,
) -> list[dict[str, Any]]:
    data = json.loads(
        read_text(path)
    )

    items: list[
        dict[str, Any]
    ] = []

    for section in (
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ):
        deps = data.get(
            section,
            {},
        )

        if not isinstance(
            deps,
            dict,
        ):
            continue

        for name, version in deps.items():
            items.append(
                package(
                    name=name,
                    version=exact_version(
                        str(version)
                    ),
                    ecosystem="npm",
                    source=(
                        f"package.json:"
                        f"{section}"
                    ),
                )
            )

    return items
# =========================================================
# package-lock.json
# =========================================================

def parse_package_lock(
    path: Path,
) -> list[dict[str, Any]]:
    data = json.loads(
        read_text(path)
    )

    items: list[
        dict[str, Any]
    ] = []

    # -----------------------------------------------------
    # npm lockfile حديث
    # -----------------------------------------------------

    package_map = data.get(
        "packages"
    )

    if isinstance(
        package_map,
        dict,
    ):
        for key, info in package_map.items():
            if not isinstance(
                info,
                dict,
            ):
                continue

            if (
                not key
                or "node_modules/" not in key
            ):
                continue

            name = key.rsplit(
                "node_modules/",
                1,
            )[-1]

            version = exact_version(
                str(
                    info.get(
                        "version",
                        "",
                    )
                )
            )

            items.append(
                package(
                    name=name,
                    version=version,
                    ecosystem="npm",
                    source="package-lock.json",
                )
            )

    # -----------------------------------------------------
    # npm lockfile قديم
    # -----------------------------------------------------

    if not items:
        deps = data.get(
            "dependencies",
            {},
        )

        if isinstance(
            deps,
            dict,
        ):
            for name, info in deps.items():
                if not isinstance(
                    info,
                    dict,
                ):
                    continue

                items.append(
                    package(
                        name=name,
                        version=exact_version(
                            str(
                                info.get(
                                    "version",
                                    "",
                                )
                            )
                        ),
                        ecosystem="npm",
                        source="package-lock.json",
                    )
                )

    return items


# =========================================================
# composer.lock
# =========================================================

def parse_composer_lock(
    path: Path,
) -> list[dict[str, Any]]:
    data = json.loads(
        read_text(path)
    )

    items: list[
        dict[str, Any]
    ] = []

    for section in (
        "packages",
        "packages-dev",
    ):
        values = data.get(
            section,
            [],
        )

        if not isinstance(
            values,
            list,
        ):
            continue

        for value in values:
            if not isinstance(
                value,
                dict,
            ):
                continue

            name = value.get(
                "name"
            )

            if not name:
                continue

            items.append(
                package(
                    name=str(name),
                    version=exact_version(
                        str(
                            value.get(
                                "version",
                                "",
                            )
                        )
                    ),
                    ecosystem="Packagist",
                    source=(
                        f"composer.lock:"
                        f"{section}"
                    ),
                )
            )

    return items


# =========================================================
# go.mod
# =========================================================

def parse_go_mod(
    path: Path,
) -> list[dict[str, Any]]:
    items: list[
        dict[str, Any]
    ] = []
    in_block = False

    for raw_line in read_text(
        path
    ).splitlines():
        line = raw_line.split(
            "//",
            1,
        )[0].strip()

        if not line:
            continue

        if line == "require (":
            in_block = True
            continue

        if (
            in_block
            and line == ")"
        ):
            in_block = False
            continue

        if line.startswith(
            "require "
        ):
            candidate = line[
                len("require "):
            ].strip()

        else:
            candidate = line

        if (
            not in_block
            and not line.startswith(
                "require "
            )
        ):
            continue

        parts = candidate.split()

        if len(parts) < 2:
            continue

        items.append(
            package(
                name=parts[0],
                version=exact_version(
                    parts[1]
                ),
                ecosystem="Go",
                source="go.mod",
            )
        )

    return items


# =========================================================
# Cargo.lock
# =========================================================

def parse_cargo_lock(
    path: Path,
) -> list[dict[str, Any]]:
    items: list[
        dict[str, Any]
    ] = []

    current: dict[
        str,
        str,
    ] = {}

    def flush() -> None:
        name = current.get(
            "name",
            "",
        ).strip()

        if name:
            items.append(
                package(
                    name=name,
                    version=exact_version(
                        current.get(
                            "version",
                            "",
                        )
                    ),
                    ecosystem="crates.io",
                    source="Cargo.lock",
                )
            )

        current.clear()

    for raw_line in read_text(
        path
    ).splitlines():
        line = raw_line.strip()

        if line == "[[package]]":
            if current:
                flush()

            continue

        match = re.match(
            r'^(name|version)'
            r'\s*=\s*'
            r'"([^"]+)"$',
            line,
        )

        if match:
            current[
                match.group(1)
            ] = match.group(2)

    if current:
        flush()

    return items


# =========================================================
# اختيار Parser
# =========================================================

def parse_dependency_file(
    path: Path,
) -> tuple[
    str,
    list[dict[str, Any]],
]:
    name = path.name.lower()

    if name == "requirements.txt":
        return (
            "PyPI",
            parse_requirements(path),
        )

    if name == "package.json":
        return (
            "npm",
            parse_package_json(path),
        )

    if name == "package-lock.json":
        return (
            "npm",
            parse_package_lock(path),
        )

    if name == "composer.lock":
        return (
            "Packagist",
            parse_composer_lock(path),
        )

    if name == "go.mod":
        return (
            "Go",
            parse_go_mod(path),
        )

    if name == "cargo.lock":
        return (
            "crates.io",
            parse_cargo_lock(path),
        )

    raise ValueError(
        "نوع ملف المكتبات غير مدعوم: "
        f"{path.name}"
    )


# =========================================================
# إزالة الحزم المكررة
# =========================================================

def deduplicate_packages(
    items: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    unique: list[
        dict[str, Any]
    ] = []

    seen: set[
        tuple[str, str, str | None]
    ] = set()

    for item in items:
        key = (
            str(
                item.get(
                    "ecosystem",
                    "",
                )
            ).lower(),
            str(
                item.get(
                    "name",
                    "",
                )
            ).lower(),

            item.get(
                "version"
            ),
        )

        if key in seen:
            continue

        seen.add(key)

        unique.append(
            item
        )

    return unique


# =========================================================
# HTTP JSON
# =========================================================

def http_json(
    url: str,
    method: str = "GET",
    payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    body = None

    if payload is not None:
        body = json.dumps(
            payload
        ).encode(
            "utf-8"
        )

    headers = {
        "Accept": "application/json",
        "User-Agent": "CyberLens/1.0",
    }

    if body is not None:
        headers[
            "Content-Type"
        ] = "application/json"

    request = urllib.request.Request(
        url,
        data=body,
        headers=headers,
        method=method,
    )

    try:
        with urllib.request.urlopen(
            request,
            timeout=HTTP_TIMEOUT,
        ) as response:
            decoded = response.read().decode(
                "utf-8"
            )

            result = json.loads(
                decoded
            )

            if not isinstance(
                result,
                dict,
            ):
                raise ValueError(
                    "استجابة OSV غير متوقعة."
                )

            return result

    except urllib.error.HTTPError as exc:
        raise RuntimeError(
            f"فشل طلب OSV HTTP "
            f"{exc.code}."
        ) from exc

    except urllib.error.URLError as exc:
        raise RuntimeError(
            "تعذر الاتصال بخدمة OSV."
        ) from exc

    except TimeoutError as exc:
        raise RuntimeError(
            "انتهت مهلة الاتصال بخدمة OSV."
        ) from exc


# =========================================================
# OSV Batch Query
# =========================================================

def query_osv_batch(
    items: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    queryable = [
        item
        for item in items
        if item.get(
            "queryable"
        )
    ][:MAX_PACKAGES]

    if not queryable:
        return []

    queries = [
        {
            "package": {
                "name": item["name"],
                "ecosystem": item[
                    "ecosystem"
                ],
            },
            "version": item[
                "version"
            ],
        }
        for item in queryable
    ]

    response = http_json(
        OSV_QUERYBATCH_URL,
        method="POST",
        payload={
            "queries": queries
        },
    )

    results = response.get(
        "results",
        [],
    )

    matches: list[
        dict[str, Any]
    ] = []

    if not isinstance(
        results,
        list,
    ):
        return matches

    for item, result in zip(
        queryable,
        results,
    ):
        if not isinstance(
            result,
            dict,
        ):
            continue

        vulns = result.get(
            "vulns",
            [],
        )

        if not isinstance(
            vulns,
            list,
        ):
            continue

        for vuln in vulns:
            if not isinstance(
                vuln,
                dict,
            ):
                continue

            vuln_id = vuln.get(
                "id"
            )

            if not vuln_id:
                continue

            matches.append(
                {
                    "package": item,
                    "vuln_id": str(
                        vuln_id
                    ),
                }
            )

    return matches


# =========================================================
# جلب تفاصيل الثغرة
# =========================================================
def get_osv_vulnerability(
    vuln_id: str,
) -> dict[str, Any]:
    safe_id = urllib.parse.quote(
        vuln_id,
        safe="",
    )

    url = OSV_VULN_URL.format(
        vuln_id=safe_id
    )

    return http_json(
        url
    )


# =========================================================
# Severity Helpers
# =========================================================

def normalize_severity(
    value: Any,
) -> str | None:
    mapping = {
        "critical": "critical",
        "high": "high",
        "moderate": "medium",
        "medium": "medium",
        "low": "low",
        "info": "info",
        "informational": "info",
    }

    return mapping.get(
        str(
            value or ""
        ).strip().lower()
    )


def extract_severity(
    vuln: dict[str, Any],
) -> str:
    """
    تحديد مستوى الخطورة من سجل OSV.

    ترتيب المصادر مقصود، ويعالج مشكلة رصدناها عمليًا:

        قاعدة OSV تجمع سجلات من مصادر متعددة (PYSEC و GHSA وغيرها)
        للثغرة الواحدة. بعض المصادر تُرفق تصنيفًا نصيًا في الحقل
        database_specific، وبعضها يُرفق درجة CVSS رقمية فقط.

        وحين كان التصنيف النصي مُقدَّمًا على الدرجة الرقمية، ظهرت
        الثغرة نفسها بمستويين مختلفين حسب المصدر الذي وصل أولًا —
        فتظهر CVE واحدة مرة "عالية" ومرة "متوسطة".

    الحل: تقديم درجة CVSS الرقمية لأنها معيارية وموحّدة عبر المصادر،
    والرجوع إلى التصنيف النصي فقط عند غيابها.
    """

    # -----------------------------------------------------
    # الأولوية الأولى: درجة CVSS الرقمية (معيارية وموحّدة)
    # -----------------------------------------------------

    entries = vuln.get("severity", [])

    if isinstance(entries, list):
        for entry in entries:
            if not isinstance(entry, dict):
                continue

            score_value = str(entry.get("score", "")).strip()

            try:
                score = float(score_value)
            except ValueError:
                continue

            if score >= 9.0:
                return "critical"
            if score >= 7.0:
                return "high"
            if score >= 4.0:
                return "medium"
            return "low"

    # -----------------------------------------------------
    # الأولوية الثانية: التصنيف النصي من المصدر
    # -----------------------------------------------------

    for key in (
        "database_specific",
        "ecosystem_specific",
    ):
        container = vuln.get(
            key
        )

        if not isinstance(
            container,
            dict,
        ):
            continue

        severity = normalize_severity(
            container.get(
                "severity"
            )
        )

        if severity:
            return severity

    # -----------------------------------------------------
    # لا نخترع Critical/High بدون بيانات واضحة
    # -----------------------------------------------------

    return "medium"


# =========================================================
# استخراج Fixed Versions
# =========================================================

def extract_fixed_versions(
    vuln: dict[str, Any],
    name: str,
    ecosystem: str,
) -> list[str]:
    fixed: list[
        str
    ] = []

    affected = vuln.get(
        "affected",
        [],
    )

    if not isinstance(
        affected,
        list,
    ):
        return fixed

    for item in affected:
        if not isinstance(
            item,
            dict,
        ):
            continue

        pkg = item.get(
            "package",
            {},
        )

        if not isinstance(
            pkg,
            dict,
        ):
            continue

        package_name = str(
            pkg.get(
                "name",
                "",
            )
        )

        package_ecosystem = str(
            pkg.get(
                "ecosystem",
                "",
            )
        )

        if (
            package_name.lower()
            != name.lower()
        ):
            continue

        if (
            package_ecosystem.lower()
            != ecosystem.lower()
        ):
            continue

        ranges = item.get(
            "ranges",
            [],
        )

        if not isinstance(
            ranges,
            list,
        ):
            continue

        for range_item in ranges:
            if not isinstance(
                range_item,
                dict,
            ):
                continue
            events = range_item.get(
                "events",
                [],
            )

            if not isinstance(
                events,
                list,
            ):
                continue

            for event in events:
                if not isinstance(
                    event,
                    dict,
                ):
                    continue

                fixed_value = event.get(
                    "fixed"
                )

                if fixed_value:
                    fixed.append(
                        str(
                            fixed_value
                        )
                    )

    return list(
        dict.fromkeys(
            fixed
        )
    )


# =========================================================
# اختيار أفضل إصدار إصلاح
# =========================================================

def select_best_fixed_version(
    installed_version: str | None,
    fixed_versions: list[str],
) -> str | None:
    """
    اختيار إصدار إصلاح مناسب.

    الأولوية:
    1. يجب أن يكون أعلى من الإصدار المثبت.
    2. نفضل نفس Major.Minor.
    3. نختار أصغر ترقية مناسبة.
    """

    if not installed_version:
        return None

    if not fixed_versions:
        return None

    try:
        installed = Version(
            installed_version
        )

    except InvalidVersion:
        return None

    valid_candidates: list[
        tuple[Version, str]
    ] = []

    for raw_version in fixed_versions:
        try:
            parsed = Version(
                raw_version
            )

        except InvalidVersion:
            continue

        # -------------------------------------------------
        # لا نقترح إصدارًا مساويًا أو أقدم
        # -------------------------------------------------

        if parsed <= installed:
            continue

        valid_candidates.append(
            (
                parsed,
                raw_version,
            )
        )

    if not valid_candidates:
        return None

    # -----------------------------------------------------
    # ترتيب تصاعدي
    # -----------------------------------------------------

    valid_candidates.sort(
        key=lambda item: item[0]
    )

    installed_release = (
        installed.release
    )

    installed_major = (
        installed_release[0]
        if len(installed_release) >= 1
        else None
    )

    installed_minor = (
        installed_release[1]
        if len(installed_release) >= 2
        else None
    )

    # -----------------------------------------------------
    # نفس Major.Minor
    #
    # 2.2.0
    # يفضل:
    # 2.2.21
    # 2.2.28
    #
    # بدل:
    # 1.11.x
    # 3.x
    # -----------------------------------------------------

    same_branch: list[
        tuple[Version, str]
    ] = []

    for parsed, raw_version in valid_candidates:
        release = parsed.release

        candidate_major = (
            release[0]
            if len(release) >= 1
            else None
        )

        candidate_minor = (
            release[1]
            if len(release) >= 2
            else None
        )

        if (
            candidate_major
            == installed_major
            and candidate_minor
            == installed_minor
        ):
            same_branch.append(
                (
                    parsed,
                    raw_version,
                )
            )

    if same_branch:
        same_branch.sort(
            key=lambda item: item[0]
        )

        return same_branch[0][1]

    # -----------------------------------------------------
    # لا يوجد Fix في نفس الفرع
    #
    # اختر أصغر إصدار أعلى من المثبت
    # -----------------------------------------------------

    return None


# =========================================================
# تحويل Vulnerability إلى Finding
# =========================================================
def vulnerability_finding(
    pkg: dict[str, Any],
    vuln: dict[str, Any],
) -> dict[str, Any]:
    vuln_id = str(
        vuln.get(
            "id",
            "OSV-UNKNOWN",
        )
    )

    aliases_raw = vuln.get(
        "aliases",
        [],
    )

    aliases = [
        str(value)
        for value in aliases_raw
        if value
    ]

    cve = next(
        (
            value
            for value in aliases
            if value.upper().startswith(
                "CVE-"
            )
        ),
        None,
    )

    summary = str(
        vuln.get(
            "summary"
        )
        or vuln.get(
            "details"
        )
        or (
            "ثغرة معروفة "
            "في الاعتمادية."
        )
    ).strip()

    if len(summary) > 900:
        summary = (
            summary[:897]
            + "..."
        )

    # -----------------------------------------------------
    # استخراج كل Fix Versions
    # -----------------------------------------------------

    fixed_versions = extract_fixed_versions(
        vuln=vuln,
        name=pkg["name"],
        ecosystem=pkg["ecosystem"],
    )

    # -----------------------------------------------------
    # اختيار أفضل Fix
    # -----------------------------------------------------

    best_fixed_version = (
        select_best_fixed_version(
            installed_version=pkg.get(
                "version"
            ),
            fixed_versions=fixed_versions,
        )
    )

    recommendation = (
        "راجع التنبيه الأمني وحدّث "
        "الاعتمادية إلى إصدار غير متأثر "
        "بعد اختبار التوافق. "
        "لم يتم تحديد إصدار إصلاح مناسب "
        "بثقة ضمن الفرع الحالي."
    )

    if best_fixed_version:
        recommendation = (
            "اختبر التحديث إلى إصدار إصلاح مناسب. "
            "أفضل إصدار إصلاح مقترح حسب "
            "بيانات OSV وفرع الإصدار المثبت هو: "
            f"{best_fixed_version}. "
            "تحقق من التوافق وأعد الفحص بعد التحديث."
        )

    return make_finding(
        finding_id=vuln_id,

        title=(
            "ثغرة معروفة في "
            f"{pkg['name']}"
        ),

        severity=extract_severity(
            vuln
        ),

        description=summary,

        recommendation=recommendation,

        cve=cve,

        package=pkg["name"],

        installed_version=pkg.get(
            "version"
        ),

        fixed_version=(
            best_fixed_version
        ),

        metadata={
            "osv_id": vuln_id,

            "aliases": aliases[:15],

            "ecosystem": pkg[
                "ecosystem"
            ],

            "all_fixed_versions": (
                fixed_versions[:30]
            ),

            "best_fixed_version": (
                best_fixed_version
            ),

            "published": vuln.get(
                "published"
            ),

            "modified": vuln.get(
                "modified"
            ),
        },
    )


# =========================================================
# Unpinned Dependencies
# =========================================================

def unpinned_findings(
    items: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    findings: list[
        dict[str, Any]
    ] = []

    for item in items:
        if item.get(
            "version"
        ):
            continue

        findings.append(
            make_finding(
                finding_id=(
                    "CL-DEP-UNPINNED-"
                    f"{len(findings) + 1:03d}"
                ),

                title=(
                    "إصدار غير مثبت للاعتمادية "
                    f"{item['name']}"
                ),

                severity="low",

                description=(
                    "تعذر إجراء مطابقة دقيقة حسب الإصدار "
                    "لأن ملف الاعتماديات لا يحتوي إصدارًا "
                    "ثابتًا قابلًا للاستعلام."
                ),
                recommendation=(
                    "ثبّت إصدارًا واضحًا أو استخدم "
                    "ملف Lock مناسب، ثم أعد الفحص "
                    "للحصول على مطابقة أدق."
                ),

                package=item[
                    "name"
                ],

                installed_version=None,

                fixed_version=None,

                metadata={
                    "ecosystem": item[
                        "ecosystem"
                    ],

                    "source": item[
                        "source"
                    ],
                },
            )
        )

    return findings


# =========================================================
# إزالة Findings المكررة
# =========================================================

def deduplicate_findings(
    findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    unique: list[
        dict[str, Any]
    ] = []

    seen: set[
        tuple[str, str, str]
    ] = set()

    for finding in findings:
        # =====================================================
        # مفتاح إزالة التكرار
        # =====================================================
        #
        # المشكلة التي يعالجها هذا التعديل:
        #
        #   قاعدة OSV تُرجع الثغرة الواحدة بعدة معرّفات: معرّف PYSEC
        #   ومعرّف GHSA ومعرّف CVE. وكان مفتاح إزالة التكرار يعتمد على
        #   الحقل id، فتمرّ الثغرة نفسها ثلاث مرات بمعرّفات مختلفة —
        #   ويظهر CVE-2019-14234 مثلاً مرتين في النتائج.
        #
        # الحل: الاعتماد على معرّف CVE عند وجوده، لأنه المعرّف المعياري
        # الموحّد. ويُرجَع إلى id فقط عند غيابه.

        identifier = str(
            finding.get("cve")
            or finding.get("id", "")
        ).strip().upper()

        key = (
            identifier,

            str(
                finding.get(
                    "package",
                    "",
                )
            ).lower(),

            str(
                finding.get(
                    "installed_version",
                    "",
                )
            ),
        )

        if key in seen:
            continue

        seen.add(key)

        unique.append(
            finding
        )

    return unique


# =========================================================
# ترتيب Findings
# =========================================================

def sort_findings(
    findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    return sorted(
        findings,
        key=lambda item: (
            -SEVERITY_RANK.get(
                str(
                    item.get(
                        "severity",
                        "low",
                    )
                ).lower(),
                0,
            ),

            str(
                item.get(
                    "package",
                    "",
                )
            ).lower(),

            str(
                item.get(
                    "id",
                    "",
                )
            ),
        ),
    )


# =========================================================
# الدالة الرئيسية
# =========================================================

def scan_dependency_file(
    file_path: str | Path,
) -> dict[str, Any]:
    path = Path(
        file_path
    ).resolve()

    if not path.exists():
        raise ValueError(
            "ملف الاعتماديات غير موجود."
        )

    if not path.is_file():
        raise ValueError(
            "المسار المحدد ليس ملفًا."
        )

    if (
        path.name.lower()
        not in SUPPORTED_FILES
    ):
        raise ValueError(
            "نوع ملف الاعتماديات غير مدعوم: "
            f"{path.name}"
        )

    ecosystem, items = (
        parse_dependency_file(
            path
        )
    )

    items = deduplicate_packages(
        items
    )

    items = items[
        :MAX_PACKAGES
    ]

    findings = unpinned_findings(
        items
    )

    osv_status = "not_queried"

    osv_error: str | None = None

    matches: list[
        dict[str, Any]
    ] = []

    try:
        matches = query_osv_batch(
            items
        )

        osv_status = "ok"

        # -------------------------------------------------
        # Cache لمنع جلب نفس Advisory أكثر من مرة
        # -------------------------------------------------

        cache: dict[
            str,
            dict[str, Any],
        ] = {}

        unique_ids = list(
            dict.fromkeys(
                match["vuln_id"]
                for match in matches
            )
        )
        for vuln_id in unique_ids[
            :MAX_VULN_DETAILS
        ]:
            cache[vuln_id] = (
                get_osv_vulnerability(
                    vuln_id
                )
            )

        for match in matches:
            vuln = cache.get(
                match[
                    "vuln_id"
                ]
            )

            if not vuln:
                continue

            findings.append(
                vulnerability_finding(
                    pkg=match[
                        "package"
                    ],
                    vuln=vuln,
                )
            )

    except Exception as exc:
        osv_status = "unavailable"

        osv_error = str(
            exc
        )

    # -----------------------------------------------------
    # إزالة التكرار
    # -----------------------------------------------------

    findings = deduplicate_findings(
        findings
    )

    # -----------------------------------------------------
    # ترتيب
    # -----------------------------------------------------

    # =====================================================
    # الفشل الآمن عند تعذّر الوصول إلى OSV
    # =====================================================
    #
    # قبل هذا الإصلاح كان الماسح يرجع findings فارغة و success=True
    # عند فشل الاتصال بـ OSV — أي يعلن "لا توجد ثغرات" بينما الحقيقة
    # "لم أستطع الفحص". وهذا أخطر من الفشل الصريح لأن المستخدم يبني
    # قرار إصدار على معلومة كاذبة.
    #
    # البديل المطبَّق:
    #   1. تشغيل القاعدة المحلية الاحتياطية للحصول على تغطية جزئية.
    #   2. إضافة تحذير صريح يوضّح أن الفحص لم يكتمل.

    offline_used = False

    if osv_status != "ok":
        try:
            try:
                from .offline_vuln_db import (
                    build_unavailable_notice,
                    scan_packages_offline,
                )
            except ImportError:
                from offline_vuln_db import (
                    build_unavailable_notice,
                    scan_packages_offline,
                )

            offline_findings = scan_packages_offline(items)
            findings.extend(offline_findings)
            offline_used = True

            findings.append(
                build_unavailable_notice(
                    reason=osv_error or osv_status,
                    packages_count=len(items),
                )
            )

            print(
                "[CyberLens SBOM] رجوع للقاعدة المحلية:",
                len(offline_findings),
                "نتيجة |",
                "سبب فشل OSV:",
                str(osv_error)[:120],
            )

        except Exception as offline_exc:
            print(
                "[CyberLens SBOM] تعذّر تحميل القاعدة المحلية:",
                type(offline_exc).__name__,
                str(offline_exc)[:160],
            )

    findings = deduplicate_findings(findings)

    findings = sort_findings(
        findings
    )

    return {
        "file_name": path.name,

        "scan_complete": osv_status == "ok",

        "offline_fallback_used": offline_used,

        "ecosystem": ecosystem,

        "packages_scanned": len(
            items
        ),

        "queryable_packages": sum(
            1
            for item in items
            if item.get(
                "queryable"
            )
        ),

        "packages": items,

        "findings": findings,

        "total_findings": len(
            findings
        ),

        "engine": (
            "CyberLens Dependency "
            "+ OSV Analysis"
        ),

        "osv": {
            "status": osv_status,

            "error": osv_error,

            "matches": len(
                matches
            ),
        },
    }


# =========================================================
# اختبار مباشر
# =========================================================

if __name__ == "__main__":
    print("=" * 60)
    print("CyberLens Dependency Scanner")
    print("=" * 60)
    print("Dependency analysis engine ready.")
    print("Supported files:")

    for filename in sorted(
        SUPPORTED_FILES
    ):
        print(
            "-",
            filename,
        )

    print("=" * 60)