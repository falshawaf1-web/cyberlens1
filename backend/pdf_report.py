from __future__ import annotations

import io
import json
import re

from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape

import arabic_reshaper

from bidi.algorithm import get_display

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import (
    ParagraphStyle,
    getSampleStyleSheet,
)
from reportlab.lib.units import mm

from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


PAGE_WIDTH, PAGE_HEIGHT = A4


ARABIC_RE = re.compile(
    r"[\u0600-\u06FF\u0750-\u077F\u08A0-\u08FF]"
)


SEVERITY_ORDER = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
    "none": 0,
}


SEVERITY_LABELS = {
    "critical": "حرجة",
    "high": "عالية",
    "medium": "متوسطة",
    "low": "منخفضة",
    "info": "معلوماتية",
    "none": "لا توجد",
}


SCAN_TYPE_LABELS = {
    "url": "فحص رابط",
    "code": "فحص كود",
    "dependencies": "فحص مكتبات",
    "project": "فحص مشروع ZIP",
    "general": "فحص عام",
}


SEVERITY_COLORS = {
    "critical": colors.HexColor("#B42318"),
    "high": colors.HexColor("#D92D20"),
    "medium": colors.HexColor("#F79009"),
    "low": colors.HexColor("#12B76A"),
    "info": colors.HexColor("#2E90FA"),
    "none": colors.HexColor("#667085"),
}


class PDFReportError(RuntimeError):
    """
    Raised when CyberLens cannot generate
    a PDF security report.
    """


def _safe_text(
    value: Any,
    fallback: str = "غير متوفر",
) -> str:
    if value is None:
        return fallback

    if isinstance(
        value,
        (
            dict,
            list,
            tuple,
            set,
        ),
    ):
        try:
            return json.dumps(
                value,
                ensure_ascii=False,
                default=str,
            )
        except TypeError:
            return str(value)

    text = str(value).strip()

    return text or fallback


def _has_arabic(
    text: str,
) -> bool:
    return bool(
        ARABIC_RE.search(text)
    )


def rtl_text(
    value: Any,
    fallback: str = "غير متوفر",
) -> str:
    """
    Shape Arabic text and apply bidi ordering.
    """

    text = _safe_text(
        value,
        fallback,
    )

    if not _has_arabic(text):
        return text

    try:
        reshaped = (
            arabic_reshaper.reshape(
                text
            )
        )

        return get_display(
            reshaped
        )

    except Exception:
        return text


def _paragraph_text(
    value: Any,
    fallback: str = "غير متوفر",
) -> str:
    text = rtl_text(
        value,
        fallback,
    )

    return (
        escape(text)
        .replace(
            "\n",
            "<br/>",
        )
    )


def _find_first_existing(
    paths: list[Path],
) -> Path | None:
    for path in paths:
        if path.is_file():
            return path

    return None


def _discover_fonts() -> tuple[
    Path,
    Path,
]:
    regular_candidates = [
        Path(
            r"C:\Windows\Fonts\arial.ttf"
        ),
        Path(
            r"C:\Windows\Fonts\tahoma.ttf"
        ),
        Path(
            r"C:\Windows\Fonts\calibri.ttf"
        ),
        Path(
            "/usr/share/fonts/truetype/"
            "dejavu/DejaVuSans.ttf"
        ),
        Path(
            "/usr/share/fonts/truetype/"
            "noto/NotoSansArabic-Regular.ttf"
        ),
        Path(
            "/Library/Fonts/Arial.ttf"
        ),
    ]

    bold_candidates = [
        Path(
            r"C:\Windows\Fonts\arialbd.ttf"
        ),
        Path(
            r"C:\Windows\Fonts\tahomabd.ttf"
        ),
        Path(
            r"C:\Windows\Fonts\calibrib.ttf"
        ),
        Path(
            "/usr/share/fonts/truetype/"
            "dejavu/DejaVuSans-Bold.ttf"
        ),
        Path(
            "/usr/share/fonts/truetype/"
            "noto/NotoSansArabic-Bold.ttf"
        ),
        Path(
            "/Library/Fonts/Arial Bold.ttf"
        ),
    ]

    regular = _find_first_existing(
        regular_candidates
    )

    bold = _find_first_existing(
        bold_candidates
    )

    if regular is None:
        raise PDFReportError(
            "لم يتم العثور على خط يدعم العربية. "
            "تأكد من وجود Arial أو Tahoma "
            "أو DejaVu Sans."
        )

    return (
        regular,
        bold or regular,
    )


def _register_fonts() -> tuple[
    str,
    str,
]:
    regular_name = (
        "CyberLensArabic"
    )

    bold_name = (
        "CyberLensArabicBold"
    )

    registered = set(
        pdfmetrics.getRegisteredFontNames()
    )

    if (
        regular_name in registered
        and bold_name in registered
    ):
        return (
            regular_name,
            bold_name,
        )

    regular_path, bold_path = (
        _discover_fonts()
    )

    if regular_name not in registered:
        pdfmetrics.registerFont(
            TTFont(
                regular_name,
                str(regular_path),
            )
        )

    if bold_name not in registered:
        pdfmetrics.registerFont(
            TTFont(
                bold_name,
                str(bold_path),
            )
        )

    return (
        regular_name,
        bold_name,
    )


def _normalize_severity(
    value: Any,
) -> str:
    severity = _safe_text(
        value,
        "info",
    ).lower()

    if severity in SEVERITY_ORDER:
        return severity

    return "info"


def _extract_findings(
    scan: dict[str, Any],
) -> list[dict[str, Any]]:
    candidates = [
        scan.get(
            "findings"
        ),
    ]

    result = scan.get(
        "result"
    )

    if isinstance(
        result,
        dict,
    ):
        candidates.append(
            result.get(
                "findings"
            )
        )

    data = scan.get(
        "data"
    )

    if isinstance(
        data,
        dict,
    ):
        candidates.append(
            data.get(
                "findings"
            )
        )

    for candidate in candidates:
        if isinstance(
            candidate,
            list,
        ):
            return [
                item
                for item in candidate
                if isinstance(
                    item,
                    dict,
                )
            ]

    return []


def _extract_ai(
    scan: dict[str, Any],
) -> dict[str, Any]:
    candidates = [
        scan.get(
            "ai_analysis"
        ),
    ]

    result = scan.get(
        "result"
    )

    if isinstance(
        result,
        dict,
    ):
        candidates.append(
            result.get(
                "ai_analysis"
            )
        )

    data = scan.get(
        "data"
    )

    if isinstance(
        data,
        dict,
    ):
        candidates.append(
            data.get(
                "ai_analysis"
            )
        )

    for candidate in candidates:
        if isinstance(
            candidate,
            dict,
        ):
            return candidate

    return {}


def _extract_metadata(
    scan: dict[str, Any],
) -> dict[str, Any]:
    metadata = scan.get(
        "metadata"
    )

    if isinstance(
        metadata,
        dict,
    ):
        return metadata

    return {}


def _severity_counts(
    findings: list[
        dict[str, Any]
    ],
) -> dict[str, int]:
    counts = Counter(
        _normalize_severity(
            item.get(
                "severity"
            )
        )
        for item in findings
    )
    return {
        key: counts.get(
            key,
            0,
        )
        for key in [
            "critical",
            "high",
            "medium",
            "low",
            "info",
        ]
    }


def _highest_severity(
    scan: dict[str, Any],
    findings: list[
        dict[str, Any]
    ],
) -> str:
    explicit = scan.get(
        "highest_severity"
    )

    if explicit:
        return _normalize_severity(
            explicit
        )

    if not findings:
        return "none"

    return max(
        (
            _normalize_severity(
                item.get(
                    "severity"
                )
            )
            for item in findings
        ),
        key=lambda item: (
            SEVERITY_ORDER[item]
        ),
    )


def _security_score(
    scan: dict[str, Any],
) -> int:
    raw = scan.get(
        "security_score",
        scan.get(
            "score",
            0,
        ),
    )

    try:
        score = int(
            round(
                float(raw)
            )
        )

    except (
        TypeError,
        ValueError,
    ):
        score = 0

    return max(
        0,
        min(
            100,
            score,
        ),
    )


def _format_date(
    value: Any,
) -> str:
    if value is None:
        return (
            datetime.now()
            .strftime(
                "%Y-%m-%d %H:%M"
            )
        )

    if isinstance(
        value,
        datetime,
    ):
        return value.strftime(
            "%Y-%m-%d %H:%M"
        )

    text = str(
        value
    ).strip()

    if not text:
        return (
            datetime.now()
            .strftime(
                "%Y-%m-%d %H:%M"
            )
        )

    try:
        parsed = (
            datetime.fromisoformat(
                text.replace(
                    "Z",
                    "+00:00",
                )
            )
        )

        return parsed.strftime(
            "%Y-%m-%d %H:%M"
        )

    except ValueError:
        return text


def _build_styles(
    regular_font: str,
    bold_font: str,
) -> dict[
    str,
    ParagraphStyle,
]:
    base = getSampleStyleSheet()

    return {
        "title":
            ParagraphStyle(
                "CyberLensTitle",
                parent=base["Title"],
                fontName=bold_font,
                fontSize=24,
                leading=31,
                textColor=(
                    colors.HexColor(
                        "#0B3F96"
                    )
                ),
                alignment=TA_CENTER,
                spaceAfter=8,
            ),

        "subtitle":
            ParagraphStyle(
                "CyberLensSubtitle",
                parent=base["Normal"],
                fontName=regular_font,
                fontSize=10,
                leading=16,
                textColor=(
                    colors.HexColor(
                        "#667085"
                    )
                ),
                alignment=TA_CENTER,
                spaceAfter=12,
            ),

        "section":
            ParagraphStyle(
                "CyberLensSection",
                parent=base["Heading2"],
                fontName=bold_font,
                fontSize=15,
                leading=21,
                textColor=(
                    colors.HexColor(
                        "#0D1B2F"
                    )
                ),
                alignment=TA_RIGHT,
                spaceBefore=7,
                spaceAfter=8,
            ),

        "body":
            ParagraphStyle(
                "CyberLensBody",
                parent=base["BodyText"],
                fontName=regular_font,
                fontSize=9.5,
                leading=16,
                textColor=(
                    colors.HexColor(
                        "#344054"
                    )
                ),
                alignment=TA_RIGHT,
                spaceAfter=5,
            ),
            "small":
            ParagraphStyle(
                "CyberLensSmall",
                parent=base["BodyText"],
                fontName=regular_font,
                fontSize=8,
                leading=12,
                textColor=(
                    colors.HexColor(
                        "#667085"
                    )
                ),
                alignment=TA_RIGHT,
            ),

        "finding_title":
            ParagraphStyle(
                "CyberLensFindingTitle",
                parent=base["Heading3"],
                fontName=bold_font,
                fontSize=11,
                leading=16,
                textColor=(
                    colors.HexColor(
                        "#101828"
                    )
                ),
                alignment=TA_RIGHT,
                spaceAfter=4,
            ),

        "analysis_label":
            ParagraphStyle(
                "CyberLensAnalysisLabel",
                parent=base["BodyText"],
                fontName=bold_font,
                fontSize=8.5,
                leading=13,
                textColor=(
                    colors.HexColor(
                        "#0B3F96"
                    )
                ),
                alignment=TA_RIGHT,
                spaceBefore=4,
                spaceAfter=1,
            ),
    }


def _p(
    value: Any,
    style: ParagraphStyle,
    fallback: str = "غير متوفر",
) -> Paragraph:
    return Paragraph(
        _paragraph_text(
            value,
            fallback,
        ),
        style,
    )


def _summary_table(
    scan: dict[str, Any],
    findings: list[
        dict[str, Any]
    ],
    styles: dict[
        str,
        ParagraphStyle,
    ],
) -> Table:
    counts = _severity_counts(
        findings
    )

    score = _security_score(
        scan
    )

    highest = _highest_severity(
        scan,
        findings,
    )

    raw_type = _safe_text(
        scan.get(
            "scan_type"
        ),
        "general",
    ).lower()

    scan_type = (
        SCAN_TYPE_LABELS.get(
            raw_type,
            "فحص عام",
        )
    )

    rows = [
        [
            _p(
                str(score) + "/100",
                styles[
                    "finding_title"
                ],
            ),
            _p(
                "درجة الأمان",
                styles["small"],
            ),
            _p(
                str(
                    len(findings)
                ),
                styles[
                    "finding_title"
                ],
            ),
            _p(
                "إجمالي النتائج",
                styles["small"],
            ),
        ],

        [
            _p(
                SEVERITY_LABELS[
                    highest
                ],
                styles[
                    "finding_title"
                ],
            ),
            _p(
                "أعلى خطورة",
                styles["small"],
            ),
            _p(
                scan_type,
                styles[
                    "finding_title"
                ],
            ),
            _p(
                "نوع الفحص",
                styles["small"],
            ),
        ],

        [
            _p(
                str(
                    counts[
                        "critical"
                    ]
                ),
                styles[
                    "finding_title"
                ],
            ),
            _p(
                "حرجة",
                styles["small"],
            ),
            _p(
                str(
                    counts[
                        "high"
                    ]
                ),
                styles[
                    "finding_title"
                ],
            ),
            _p(
                "عالية",
                styles["small"],
            ),
        ],

        [
            _p(
                str(
                    counts[
                        "medium"
                    ]
                ),
                styles[
                    "finding_title"
                ],
            ),
            _p(
                "متوسطة",
                styles["small"],
            ),
            _p(
                str(
                    counts[
                        "low"
                    ]
                ),
                styles[
                    "finding_title"
                ],
            ),
            _p(
                "منخفضة",
                styles["small"],
            ),
        ],
    ]
    table = Table(
        rows,
        colWidths=[
            35 * mm,
            35 * mm,
            35 * mm,
            35 * mm,
        ],
        hAlign="CENTER",
    )

    table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, -1),
                    colors.HexColor(
                        "#F8FAFC"
                    ),
                ),
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.5,
                    colors.HexColor(
                        "#E4EAF2"
                    ),
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "MIDDLE",
                ),
                (
                    "ALIGN",
                    (0, 0),
                    (-1, -1),
                    "CENTER",
                ),
                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    8,
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    8,
                ),
            ]
        )
    )

    return table


def _metadata_table(
    metadata: dict[str, Any],
    styles: dict[
        str,
        ParagraphStyle,
    ],
) -> Table | None:
    if not metadata:
        return None

    label_map = {
        "ecosystem":
            "النظام البيئي",

        "packages_scanned":
            "الحزم المفحوصة",

        "files_discovered":
            "الملفات المكتشفة",

        "code_files_scanned":
            "ملفات الكود المفحوصة",

        "dependency_files_scanned":
            "ملفات المكتبات المفحوصة",

        "total_errors":
            "أخطاء الفحص",

        "archive_type":
            "نوع الأرشيف",

        "engine":
            "محرك الفحص",

        "osv_status":
            "حالة OSV",

        "path_traversal_protection":
            "حماية المسارات",

        "temporary_cleanup":
            "تنظيف الملفات المؤقتة",
    }

    preferred = [
        "engine",
        "archive_type",
        "ecosystem",
        "packages_scanned",
        "files_discovered",
        "code_files_scanned",
        "dependency_files_scanned",
        "total_errors",
        "osv_status",
        "path_traversal_protection",
        "temporary_cleanup",
    ]

    rows = []

    for key in preferred:
        if key not in metadata:
            continue

        rows.append(
            [
                _p(
                    metadata[key],
                    styles["body"],
                ),
                _p(
                    label_map.get(
                        key,
                        key,
                    ),
                    styles["small"],
                ),
            ]
        )

    if not rows:
        return None

    table = Table(
        rows,
        colWidths=[
            105 * mm,
            45 * mm,
        ],
        hAlign="RIGHT",
    )

    table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, -1),
                    colors.HexColor(
                        "#FBFCFE"
                    ),
                ),
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.4,
                    colors.HexColor(
                        "#E4EAF2"
                    ),
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP",
                    ),
                (
                    "RIGHTPADDING",
                    (0, 0),
                    (-1, -1),
                    7,
                ),
                (
                    "LEFTPADDING",
                    (0, 0),
                    (-1, -1),
                    7,
                ),
                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    6,
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    6,
                ),
            ]
        )
    )

    return table


def _finding_block(
    index: int,
    finding: dict[str, Any],
    styles: dict[
        str,
        ParagraphStyle,
    ],
) -> KeepTogether:
    severity = _normalize_severity(
        finding.get(
            "severity"
        )
    )

    severity_label = (
        SEVERITY_LABELS[
            severity
        ]
    )

    title = (
        finding.get(
            "title"
        )
        or finding.get(
            "name"
        )
        or "نتيجة أمنية"
    )

    description = (
        finding.get(
            "description"
        )
        or finding.get(
            "details"
        )
    )

    recommendation = (
        finding.get(
            "recommendation"
        )
        or finding.get(
            "fix"
        )
    )

    extras = []

    extra_fields = [
        (
            "المعرف",
            "id",
        ),
        (
            "الحزمة",
            "package",
        ),
        (
            "الإصدار المثبت",
            "installed_version",
        ),
        (
            "الإصدار المقترح",
            "fixed_version",
        ),
        (
            "الملف",
            "project_file",
        ),
        (
            "السطر",
            "line",
        ),
        (
            "CVSS",
            "cvss_score",
        ),
        (
            "CWE",
            "cwe",
        ),
        (
            "OWASP",
            "owasp",
        ),
    ]

    for label, key in extra_fields:
        value = finding.get(
            key
        )

        if value not in (
            None,
            "",
        ):
            extras.append(
                label
                + ": "
                + _safe_text(
                    value
                )
            )

    header = Table(
        [
            [
                _p(
                    severity_label,
                    styles["small"],
                ),
                _p(
                    str(index)
                    + ". "
                    + _safe_text(
                        title
                    ),
                    styles[
                        "finding_title"
                    ],
                ),
            ]
        ],
        colWidths=[
            28 * mm,
            132 * mm,
        ],
        hAlign="RIGHT",
    )

    header.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (0, 0),
                    SEVERITY_COLORS[
                        severity
                    ],
                ),
                (
                    "TEXTCOLOR",
                    (0, 0),
                    (0, 0),
                    colors.white,
                ),
                (
                    "BACKGROUND",
                    (1, 0),
                    (1, 0),
                    colors.HexColor(
                        "#F8FAFC"
                    ),
                ),
                (
                    "BOX",
                    (0, 0),
                    (-1, -1),
                    0.6,
                    colors.HexColor(
                        "#E4EAF2"
                    ),
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "MIDDLE",
                ),
                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    7,
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    7,
                ),
                (
                    "LEFTPADDING",
                    (0, 0),
                    (-1, -1),
                    7,
                ),
                (
                    "RIGHTPADDING",
                    (0, 0),
                    (-1, -1),
                    7,
                ),
            ]
        )
    )

    flowables = [
        header,
        Spacer(
            1,
            3 * mm,
        ),
    ]

    ai_analysis = (
        finding.get("ai_analysis")
        if isinstance(
            finding.get("ai_analysis"),
            dict,
        )
        else {}
    )

    cvss_vector = finding.get("cvss_vector")

    if description:
        flowables.append(
            _p(
                description,
                styles["body"],
            )
        )

    if cvss_vector:
        flowables.append(
            _p(
                "CVSS Vector: "
                + _safe_text(
                    cvss_vector
                ),
                styles["small"],
            )
        )

    if ai_analysis.get("executive_summary"):
        flowables.append(
            _p(
                "الملخص التنفيذي (Executive Summary)",
                styles["analysis_label"],
            )
        )
        flowables.append(
            _p(
                ai_analysis["executive_summary"],
                styles["body"],
            )
        )

    if ai_analysis.get("technical_analysis"):
        flowables.append(
            _p(
                "التحليل التقني (Technical Analysis)",
                styles["analysis_label"],
            )
        )
        flowables.append(
            _p(
                ai_analysis["technical_analysis"],
                styles["body"],
            )
        )

    if ai_analysis.get("root_cause"):
        flowables.append(
            _p(
                "السبب الجذري (Root Cause)",
                styles["analysis_label"],
            )
        )
        flowables.append(
            _p(
                ai_analysis["root_cause"],
                styles["body"],
            )
        )

    cia_parts = []

    for label, key in (
        ("السرّية (C)", "confidentiality_impact"),
        ("السلامة (I)", "integrity_impact"),
        ("التوفر (A)", "availability_impact"),
    ):
        value = ai_analysis.get(key)

        if value:
            cia_parts.append(
                label + ": " + _safe_text(value)
            )

    if cia_parts:
        flowables.append(
            _p(
                "الأثر الأمني (CIA Impact)",
                styles["analysis_label"],
            )
        )

        for part in cia_parts:
            flowables.append(
                _p(
                    part,
                    styles["small"],
                )
            )

    if recommendation:
        flowables.append(
            _p(
                "التوصية: "
                + _safe_text(
                    recommendation
                ),
                styles["body"],
            )
        )

    if ai_analysis.get("verification"):
        flowables.append(
            _p(
                "طريقة التحقق (Verification)",
                styles["analysis_label"],
            )
        )
        flowables.append(
            _p(
                ai_analysis["verification"],
                styles["body"],
            )
        )

    if ai_analysis.get("limitations"):
        flowables.append(
            _p(
                "حدود التحليل (Limitations)",
                styles["analysis_label"],
            )
        )
        flowables.append(
            _p(
                ai_analysis["limitations"],
                styles["small"],
            )
        )

    if extras:
        flowables.append(
            _p(
                " | ".join(
                    extras
                ),
                styles["small"],
            )
        )

    flowables.extend(
        [
            Spacer(
                1,
                2 * mm,
            ),
            HRFlowable(
                width="100%",
                thickness=0.5,
                color=(
                    colors.HexColor(
                        "#E4EAF2"
                    )
                ),
            ),
            Spacer(
                1,
                3 * mm,
            ),
        ]
    )

    return KeepTogether(
        flowables
    )


def _ai_blocks(
    ai: dict[str, Any],
    styles: dict[
        str,
        ParagraphStyle,
    ],
) -> list[Any]:
    if not ai:
        return []

    blocks = [
        _p(
            "التحليل الأمني الذكي",
            styles["section"],
        ),
    ]

    summary = ai.get(
        "summary"
    )

    if summary:
        blocks.append(
            _p(
                summary,
                styles["body"],
            )
        )

    provider = ai.get(
        "provider"
    )

    mode = ai.get(
        "mode"
    )

    if provider or mode:
        blocks.append(
            _p(
                "المزود: "
                + _safe_text(
                    provider,
                    "غير متوفر",
                )
                + " | الوضع: "
                + _safe_text(
                    mode,
                    "غير متوفر",
                ),
                styles["small"],
            )
        )

    priorities = ai.get(
        "priority_order"
    )

    if (
        isinstance(
            priorities,
            list,
        )
        and priorities
    ):
        blocks.append(
            _p(
                "أولويات المعالجة",
                styles["section"],
            )
        )

        for index, item in enumerate(
            priorities[:15],
            start=1,
        ):
            if not isinstance(
                item,
                dict,
            ):
                continue

            text = (
                str(index)
                + ". "
                + _safe_text(
                    item.get(
                        "title"
                    ),
                    "أولوية أمنية",
                )
                + " - "
                + _safe_text(
                    item.get(
                        "reason"
                    ),
                    "تحتاج إلى مراجعة",
                )
            )

            blocks.append(
                _p(
                    text,
                    styles["body"],
                )
            )

    correlations = ai.get(
        "correlations"
    )
    if (
        isinstance(
            correlations,
            list,
        )
        and correlations
    ):
        blocks.append(
            _p(
                "المخاطر المترابطة",
                styles["section"],
            )
        )

        for index, item in enumerate(
            correlations[:20],
            start=1,
        ):
            if not isinstance(
                item,
                dict,
            ):
                continue

            title = (
                item.get(
                    "title"
                )
                or "خطر مترابط"
            )

            explanation = (
                item.get(
                    "explanation"
                )
                or item.get(
                    "description"
                )
            )

            severity = (
                SEVERITY_LABELS[
                    _normalize_severity(
                        item.get(
                            "severity"
                        )
                    )
                ]
            )

            text = (
                str(index)
                + ". "
                + _safe_text(
                    title
                )
                + " ("
                + severity
                + ") - "
                + _safe_text(
                    explanation,
                    "تم اكتشاف علاقة "
                    "بين عدة نتائج",
                )
            )

            blocks.append(
                _p(
                    text,
                    styles["body"],
                )
            )

    return blocks


def _page_decorator(
    canvas: Any,
    document: Any,
    regular_font: str,
    bold_font: str,
) -> None:
    canvas.saveState()

    canvas.setFillColor(
        colors.HexColor(
            "#0B3F96"
        )
    )

    canvas.rect(
        0,
        PAGE_HEIGHT - 15 * mm,
        PAGE_WIDTH,
        15 * mm,
        fill=1,
        stroke=0,
    )

    canvas.setFillColor(
        colors.white
    )

    canvas.setFont(
        bold_font,
        10,
    )

    canvas.drawString(
        16 * mm,
        PAGE_HEIGHT - 10 * mm,
        "CyberLens Security Report",
    )

    canvas.setStrokeColor(
        colors.HexColor(
            "#E4EAF2"
        )
    )

    canvas.line(
        15 * mm,
        14 * mm,
        PAGE_WIDTH - 15 * mm,
        14 * mm,
    )

    canvas.setFillColor(
        colors.HexColor(
            "#667085"
        )
    )

    canvas.setFont(
        regular_font,
        8,
    )

    canvas.drawString(
        16 * mm,
        9 * mm,
        "CyberLens - Defensive Security Analysis",
    )

    canvas.drawRightString(
        PAGE_WIDTH - 16 * mm,
        9 * mm,
        "Page "
        + str(
            document.page
        ),
    )

    canvas.restoreState()


def build_pdf_report(
    scan: dict[str, Any],
) -> io.BytesIO:
    """
    Generate a professional Arabic RTL
    CyberLens PDF report in memory.
    """

    if not isinstance(
        scan,
        dict,
    ):
        raise PDFReportError(
            "بيانات الفحص يجب "
            "أن تكون قاموسًا."
        )

    regular_font, bold_font = (
        _register_fonts()
    )

    styles = _build_styles(
        regular_font,
        bold_font,
    )

    findings = _extract_findings(
        scan
    )

    ai = _extract_ai(
        scan
    )

    metadata = _extract_metadata(
        scan
    )

    target = (
        scan.get(
            "target_name"
        )
        or scan.get(
            "target"
        )
        or scan.get(
            "filename"
        )
        or "غير متوفر"
    )

    scan_id = scan.get(
        "id",
        "-",
    )

    created_at = _format_date(
        scan.get(
            "created_at"
        )
        or scan.get(
            "timestamp"
        )
        or scan.get(
            "date"
        )
    )

    buffer = io.BytesIO()
    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=16 * mm,
        leftMargin=16 * mm,
        topMargin=23 * mm,
        bottomMargin=20 * mm,
        title=(
            "CyberLens Security Report"
        ),
        author="CyberLens",
        subject=(
            "Defensive Security "
            "Analysis Report"
        ),
    )

    story = [
        _p(
            "CyberLens",
            styles["title"],
        ),

        _p(
            "تقرير التحليل الأمني الدفاعي",
            styles["subtitle"],
        ),

        Spacer(
            1,
            2 * mm,
        ),

        HRFlowable(
            width="100%",
            thickness=1,
            color=(
                colors.HexColor(
                    "#D9E7F8"
                )
            ),
        ),

        Spacer(
            1,
            5 * mm,
        ),

        _p(
            "ملخص الفحص",
            styles["section"],
        ),

        _summary_table(
            scan,
            findings,
            styles,
        ),

        Spacer(
            1,
            5 * mm,
        ),

        _p(
            "معلومات الهدف",
            styles["section"],
        ),
    ]

    info_rows = [
        [
            _p(
                target,
                styles["body"],
            ),
            _p(
                "الهدف",
                styles["small"],
            ),
        ],

        [
            _p(
                scan_id,
                styles["body"],
            ),
            _p(
                "معرف الفحص",
                styles["small"],
            ),
        ],

        [
            _p(
                created_at,
                styles["body"],
            ),
            _p(
                "تاريخ التقرير",
                styles["small"],
            ),
        ],
    ]

    info_table = Table(
        info_rows,
        colWidths=[
            110 * mm,
            40 * mm,
        ],
        hAlign="RIGHT",
    )

    info_table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, -1),
                    colors.HexColor(
                        "#FBFCFE"
                    ),
                ),
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.4,
                    colors.HexColor(
                        "#E4EAF2"
                    ),
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP",
                ),
                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    7,
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    7,
                ),
                (
                    "LEFTPADDING",
                    (0, 0),
                    (-1, -1),
                    7,
                ),
                (
                    "RIGHTPADDING",
                    (0, 0),
                    (-1, -1),
                    7,
                ),
            ]
        )
    )

    story.extend(
        [
            info_table,

            Spacer(
                1,
                5 * mm,
            ),
        ]
    )

    metadata_table = (
        _metadata_table(
            metadata,
            styles,
        )
    )

    if metadata_table is not None:
        story.extend(
            [
                _p(
                    "معلومات تقنية",
                    styles["section"],
                ),

                metadata_table,

                Spacer(
                    1,
                    5 * mm,
                ),
            ]
        )

    story.extend(
        _ai_blocks(
            ai,
            styles,
        )
    )
    story.extend(
        [
            Spacer(
                1,
                4 * mm,
            ),

            _p(
                "النتائج الأمنية",
                styles["section"],
            ),
        ]
    )

    if findings:
        sorted_findings = sorted(
            findings,
            key=lambda item: (
                SEVERITY_ORDER[
                    _normalize_severity(
                        item.get(
                            "severity"
                        )
                    )
                ]
            ),
            reverse=True,
        )

        for index, finding in enumerate(
            sorted_findings,
            start=1,
        ):
            story.append(
                _finding_block(
                    index,
                    finding,
                    styles,
                )
            )

    else:
        story.append(
            _p(
                "لم يتم اكتشاف نتائج "
                "أمنية في هذا الفحص.",
                styles["body"],
            )
        )

    story.extend(
        [
            Spacer(
                1,
                5 * mm,
            ),

            HRFlowable(
                width="100%",
                thickness=0.8,
                color=(
                    colors.HexColor(
                        "#D9E7F8"
                    )
                ),
            ),

            Spacer(
                1,
                3 * mm,
            ),

            _p(
                "ملاحظة: هذا التقرير مخصص "
                "للتحليل الأمني الدفاعي. "
                "يجب التحقق من النتائج ضمن "
                "سياق المشروع قبل اعتماد "
                "أي تغيير.",
                styles["small"],
            ),
        ]
    )

    def decorate(
        canvas: Any,
        doc: Any,
    ) -> None:
        _page_decorator(
            canvas,
            doc,
            regular_font,
            bold_font,
        )

    try:
        document.build(
            story,
            onFirstPage=decorate,
            onLaterPages=decorate,
        )

    except Exception as exc:
        raise PDFReportError(
            "فشل إنشاء تقرير PDF: "
            + str(exc)
        ) from exc

    buffer.seek(0)

    return buffer


def save_pdf_report(
    scan: dict[str, Any],
    output_path: str | Path,
) -> Path:
    """
    Generate and save a CyberLens
    PDF report to disk.
    """

    destination = Path(
        output_path
    )

    destination.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    buffer = build_pdf_report(
        scan
    )

    destination.write_bytes(
        buffer.getvalue()
    )

    return destination.resolve()