"""
cvss_mapper.py
=========================================================
حاسبة CVSS v3.1 حقيقية لنتائج فحص الكود الثابت (SAST).

بدل ما نعرض Severity نصي فقط (high/medium/low)، هاد الملف
يربط كل قاعدة فحص (Rule ID) بمتجه CVSS v3.1 (Vector String)
حدده المهندس يدويًا بناءً على طبيعة الثغرة، وبعدين يحسب
الـ Base Score من المعادلة الرسمية المنشورة على FIRST.org:

    https://www.first.org/cvss/v3.1/specification-document

المتجهات هون **ثابتة ومحددة من قبل المطوّر** وليست مولّدة
أو مخترعة من الذكاء الاصطناعي، إلتزامًا بنفس مبدأ عدم
اختلاق بيانات أمنية المتّبع بباقي المشروع (راجع
build_external_instructions فوق ai_engine.py).
"""

from __future__ import annotations

import math
from typing import Any


# =========================================================
# قيم أوزان CVSS v3.1 الرسمية
# =========================================================

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def _parse_vector(vector: str) -> dict[str, str]:
    parts = {}

    for chunk in vector.strip().split("/"):
        if ":" not in chunk:
            continue

        key, value = chunk.split(":", 1)
        parts[key.strip().upper()] = value.strip().upper()

    return parts


def calculate_cvss_score(vector: str) -> float:
    """
    يحسب CVSS v3.1 Base Score من Vector String صحيح.
    يرجع 0.0 لو الـ vector غير صالح بدل ما يفشل الفحص كامل.
    """

    if not vector:
        return 0.0

    try:
        m = _parse_vector(vector)

        av = _AV[m["AV"]]
        ac = _AC[m["AC"]]
        ui = _UI[m["UI"]]
        scope_changed = m.get("S", "U") == "C"

        pr_table = _PR_CHANGED if scope_changed else _PR_UNCHANGED
        pr = pr_table[m["PR"]]

        c = _CIA[m["C"]]
        i = _CIA[m["I"]]
        a = _CIA[m["A"]]

        isc_base = 1 - ((1 - c) * (1 - i) * (1 - a))

        if scope_changed:
            impact = 7.52 * (isc_base - 0.029) - 3.25 * (
                (isc_base - 0.02) ** 15
            )
        else:
            impact = 6.42 * isc_base

        if impact <= 0:
            return 0.0

        exploitability = 8.22 * av * ac * pr * ui

        if scope_changed:
            base = min(1.08 * (impact + exploitability), 10)
        else:
            base = min(impact + exploitability, 10)

        # Roundup إلى أقرب عشر (وفق المعادلة الرسمية)
        return math.ceil(base * 10) / 10.0

    except (KeyError, ValueError, ZeroDivisionError):
        return 0.0


def cvss_score_to_severity(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "info"


# =========================================================
# قاعدة معرفة CVSS + CWE + OWASP لكل قاعدة فحص كود ثابتة
# =========================================================
# المصادر التصنيفية (CWE/OWASP) موثّقة من:
#   - cwe.mitre.org
#   - owasp.org/Top10/

RULE_SECURITY_KB: dict[str, dict[str, str]] = {
    # ---- Remote/Dynamic Code Execution family ----
    "CL-PY-001": {  # eval()
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-95 (Eval Injection)",
        "owasp": "A03:2021 - Injection",
    },
    "CL-PY-002": {  # exec()
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-95 (Eval Injection)",
        "owasp": "A03:2021 - Injection",
    },
    "CL-PY-003": {  # os.system
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-78 (OS Command Injection)",
        "owasp": "A03:2021 - Injection",
    },
    "CL-PY-004": {  # shell=True
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-78 (OS Command Injection)",
        "owasp": "A03:2021 - Injection",
    },
    "CL-PY-006": {  # pickle.loads
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-502 (Deserialization of Untrusted Data)",
        "owasp": "A08:2021 - Software and Data Integrity Failures",
    },
    "CL-JS-001": {  # eval() JS
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-95 (Eval Injection)",
        "owasp": "A03:2021 - Injection",
    },
    "CL-JS-003": {  # Node child_process
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-78 (OS Command Injection)",
        "owasp": "A03:2021 - Injection",
    },
    "CL-PHP-001": {  # PHP system exec
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-78 (OS Command Injection)",
        "owasp": "A03:2021 - Injection",
    },
    "CL-PHP-002": {  # unserialize
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-502 (Deserialization of Untrusted Data)",
        "owasp": "A08:2021 - Software and Data Integrity Failures",
    },
    "CL-SQL-001": {  # SQL string concat
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-89 (SQL Injection)",
        "owasp": "A03:2021 - Injection",
    },

    # ---- Memory corruption (C/C++) ----
    "CL-C-001": {  # gets()
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-242 (Use of Inherently Dangerous Function)",
        "owasp": "A06:2021 - Vulnerable and Outdated Components",
    },
    "CL-C-002": {  # strcpy()
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-120 (Buffer Copy without Checking Size of Input)",
        "owasp": "A06:2021 - Vulnerable and Outdated Components",
    },

    # ---- TLS / Transport security ----
    "CL-PY-005": {  # verify=False
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "cwe": "CWE-295 (Improper Certificate Validation)",
        "owasp": "A02:2021 - Cryptographic Failures",
    },
    "CL-GEN-001": {  # disable TLS verification (general)
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "cwe": "CWE-295 (Improper Certificate Validation)",
        "owasp": "A02:2021 - Cryptographic Failures",
    },

    # ---- Weak Cryptography ----
    "CL-CRYPTO-001": {  # MD5
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "cwe": "CWE-327 (Use of a Broken or Risky Cryptographic Algorithm)",
        "owasp": "A02:2021 - Cryptographic Failures",
    },
    "CL-CRYPTO-002": {  # SHA-1
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "cwe": "CWE-327 (Use of a Broken or Risky Cryptographic Algorithm)",
        "owasp": "A02:2021 - Cryptographic Failures",
    },

    # ---- Client-side / XSS ----
    "CL-JS-002": {  # innerHTML
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
        "cwe": "CWE-79 (Cross-Site Scripting)",
        "owasp": "A03:2021 - Injection",
    },

    # ---- Information disclosure / misconfiguration ----
    "CL-PY-007": {  # debug mode
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "cwe": "CWE-489 (Active Debug Code)",
        "owasp": "A05:2021 - Security Misconfiguration",
    },

    # ---- Hard-coded secrets ----
    "CL-SECRET-001": {  # hardcoded password
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        "cwe": "CWE-798 (Use of Hard-coded Credentials)",
        "owasp": "A07:2021 - Identification and Authentication Failures",
    },
    "CL-SECRET-002": {  # api key
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        "cwe": "CWE-798 (Use of Hard-coded Credentials)",
        "owasp": "A07:2021 - Identification and Authentication Failures",
    },
    "CL-SECRET-003": {  # token
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        "cwe": "CWE-798 (Use of Hard-coded Credentials)",
        "owasp": "A07:2021 - Identification and Authentication Failures",
    },
}


# =========================================================
# Fallback عام حسب Severity (لأي Finding بلا Rule ID معروف،
# مثل نتائج URL / Dependencies القادمة من OSV بدون CVSS)
# =========================================================

_SEVERITY_FALLBACK_VECTOR = {
    "critical": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "high": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "medium": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
    "low": "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N",
    "info": "",
}


def get_cvss_for_finding(finding: dict[str, Any]) -> dict[str, Any]:
    """
    يرجع dict فيه cvss_vector و cvss_score لأي finding.
    - لو عنده rule_id معروف بالـ KB، نستخدم المتجه المخصص له.
    - لو الـ finding نفسه (من OSV مثلاً) عنده cvss_vector جاهز
      أصلاً، نحسب الـ score منه مباشرة بدون تعديل القيمة المصدرية.
    - غير هيك منستخدم fallback عام حسب severity.
    """

    existing_vector = str(finding.get("cvss_vector") or "").strip()

    if existing_vector:
        return {
            "cvss_vector": existing_vector,
            "cvss_score": calculate_cvss_score(existing_vector),
        }

    metadata = finding.get("metadata") or {}
    rule_id = str(
        finding.get("id")
        or metadata.get("rule_id")
        or ""
    ).strip()

    kb_entry = RULE_SECURITY_KB.get(rule_id)

    # الامتداد: قواعد الروابط والترويسات والماسح المتقدم والمكتبات.
    # بدونه تظهر نتائج هذه الماسحات بلا تصنيف CWE ولا درجة CVSS محددة.
    if not kb_entry:
        try:
            try:
                from .cvss_mapper_ext import get_extended_entry
            except ImportError:
                from cvss_mapper_ext import get_extended_entry
            kb_entry = get_extended_entry(rule_id)
        except Exception:
            kb_entry = None

    if kb_entry:
        vector = kb_entry["cvss_vector"]

        return {
            "cvss_vector": vector,
            "cvss_score": calculate_cvss_score(vector),
            "cwe": kb_entry.get("cwe", ""),
            "owasp": kb_entry.get("owasp", ""),
        }

    severity = str(finding.get("severity") or "info").strip().lower()
    vector = _SEVERITY_FALLBACK_VECTOR.get(severity, "")

    if not vector:
        return {"cvss_vector": "", "cvss_score": 0.0}

    return {
        "cvss_vector": vector,
        "cvss_score": calculate_cvss_score(vector),
    }


def apply_cvss_to_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    يمرّ على قائمة findings ويزوّد كل واحدة بـ cvss_vector و
    cvss_score (وcwe/owasp لو كانت فاضية) بدون تعديل أي حقل
    موجود مسبقًا وله قيمة حقيقية.
    """

    for finding in findings:
        if not isinstance(finding, dict):
            continue

        cvss_data = get_cvss_for_finding(finding)

        if cvss_data.get("cvss_vector"):
            finding["cvss_vector"] = cvss_data["cvss_vector"]
            finding["cvss_score"] = cvss_data["cvss_score"]

        if cvss_data.get("cwe") and not finding.get("cwe"):
            finding["cwe"] = cvss_data["cwe"]

        if cvss_data.get("owasp") and not finding.get("owasp"):
            finding["owasp"] = cvss_data["owasp"]

    return findings
