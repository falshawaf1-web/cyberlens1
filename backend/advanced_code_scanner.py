from pathlib import Path
import re


USER_INPUT_MARKERS = [
    "request.args",
    "request.form",
    "request.values",
    "request.json",
    "request.get_json",
    "request.cookies",
    "input(",
    "$_get",
    "$_post",
    "req.query",
    "req.body",
    "req.params",
]

SQL_WORDS = [
    "select ",
    "insert ",
    "update ",
    "delete ",
    "drop ",
    "union ",
    "where ",
]

HTML_SINKS = [
    "render_template_string",
    "innerhtml",
    "document.write",
    "dangerouslysetinnerhtml",
    "|safe",
    "v-html",
]

AUTH_WORDS = [
    "login_required",
    "require_login",
    "require_admin",
    "admin_required",
    "permission",
    "current_user",
    "jwt",
    "session",
    "authenticated",
]


def short_code(line):
    value = line.strip()
    if len(value) > 220:
        return value[:220] + "..."
    return value


def has_user_input(line):
    low = line.lower()
    return any(marker in low for marker in USER_INPUT_MARKERS)


def make_finding(rule_id, title, severity, description, recommendation, file_name, line_number, code, confidence="medium", metadata=None):
    return {
        "id": rule_id,
        "title": title,
        "severity": severity,
        "description": description,
        "recommendation": recommendation,
        "source": "CyberLens Advanced SAST",
        "file": file_name,
        "line": line_number,
        "code": short_code(code),
        "confidence": confidence,
        "metadata": metadata or {"engine": "CyberLens Advanced Code Analysis", "rule_id": rule_id},
    }


def run_advanced_code_checks(file_path, language=None):
    path = Path(file_path)
    text = path.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()
    file_name = path.name

    findings = []
    tainted_vars = set()

    for index, line in enumerate(lines, start=1):
        low = line.lower()

        assignment = re.search(r"\b([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*(.+)", line)
        if assignment and has_user_input(assignment.group(2)):
            tainted_vars.add(assignment.group(1))

        tainted_used = any(
            re.search(r"\b" + re.escape(var_name) + r"\b", line)
            for var_name in tainted_vars
        )

        has_sql = any(word in low for word in SQL_WORDS)
        dynamic_build = (
            "f\"" in line
            or "f'" in line
            or ".format(" in low
            or " + " in line
            or "%" in line
            or "request." in low
            or tainted_used
        )

        if has_sql and dynamic_build and (has_user_input(line) or tainted_used or "{" in line):
            findings.append(
                make_finding(
                    "CL-ADV-SQLI-001",
                    "احتمال SQL Injection بسبب بناء Query ديناميكي",
                    "high",
                    "تم اكتشاف SQL query يتم بناؤه بطريقة ديناميكية وقد يرتبط بمدخلات المستخدم.",
                    "استخدم Parameterized Queries ولا تدمج مدخلات المستخدم مباشرة داخل SQL.",
                    file_name,
                    index,
                    line,
                    "medium",
                )
            )

        if any(marker in low for marker in HTML_SINKS) and (has_user_input(line) or tainted_used or " + " in line):
            findings.append(
                make_finding(
                    "CL-ADV-XSS-001",
                    "احتمال XSS بسبب إدخال المستخدم داخل HTML",
                    "high",
                    "تم اكتشاف نمط قد يعرض مدخلات المستخدم داخل HTML بدون تعقيم كاف.",
                    "استخدم escaping/sanitization وتجنب render_template_string مع مدخلات مباشرة.",
                    file_name,
                    index,
                    line,
                    "medium",
                )
            )

        if "secret_key" in low and "=" in line and ("\"" in line or "'" in line) and "environ" not in low and "getenv" not in low:
            findings.append(
                make_finding(
                    "CL-ADV-SECRET-001",
                    "Secret Key ثابت داخل الكود",
                    "high",
                    "تم اكتشاف Secret Key مكتوب مباشرة داخل الكود.",
                    "انقل Secret Key إلى Environment Variables أو Secret Manager.",
                    file_name,
                    index,
                    line,
                    "medium",
                )
            )

        if "shell=true" in low or "os.system(" in low or "popen(" in low:
            findings.append(
                make_finding(
                    "CL-ADV-CMD-001",
                    "احتمال Command Injection",
                    "high",
                    "تم اكتشاف تنفيذ أوامر نظام بطريقة قد تصبح خطرة عند دخول مدخلات غير موثوقة.",
                    "تجنب shell=True ولا تمرر مدخلات المستخدم لأوامر النظام مباشرة.",
                    file_name,
                    index,
                    line,
                    "medium",
                )
            )

        if "pickle.loads" in low or ("yaml.load(" in low and "safe_load" not in low):
            findings.append(
                make_finding(
                    "CL-ADV-DESER-001",
                    "استخدام Deserialization غير آمن محتمل",
                    "high",
                    "تم اكتشاف استخدام قد يؤدي إلى deserialization غير آمن.",
                    "تجنب pickle مع بيانات غير موثوقة واستخدم safe_load عند التعامل مع YAML.",
                    file_name,
                    index,
                    line,
                    "medium",
                )
            )

    sensitive_paths = [
        "/admin",
        "/delete",
        "/users",
        "/settings",
        "/api/admin",
    ]

    for index, line in enumerate(lines, start=1):
        low = line.lower()

        is_route = (
            "@app.route" in low
            or "@blueprint.route" in low
            or ".route(" in low
        )

        if is_route and any(path_part in low for path_part in sensitive_paths):
            block = "\n".join(lines[index:index + 14]).lower()

            if not any(word in block for word in AUTH_WORDS):
                findings.append(
                    make_finding(
                        "CL-ADV-AUTH-001",
                        "Route حساس بدون تحقق صلاحيات واضح",
                        "high",
                        "تم اكتشاف مسار حساس مثل admin/delete/users دون ظهور تحقق صلاحيات واضح في بداية الدالة.",
                        "أضف login_required و/أو require_admin وتحقق من صلاحيات المستخدم قبل تنفيذ العملية.",
                        file_name,
                        index,
                        line,
                        "medium",
                    )
                )

    return findings
