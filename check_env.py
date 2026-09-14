"""
=========================================================
CyberLens - تشخيص ملف .env
=========================================================
شغّله من جذر المشروع:  python check_env.py
=========================================================
"""

import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

REQUIRED = [
    "CYBERLENS_SECRET_KEY",
    "CYBERLENS_ADMIN_USERNAME",
    "CYBERLENS_ADMIN_PASSWORD",
]

problems = []

print("=" * 58)
print("  تشخيص إعدادات CyberLens")
print("=" * 58)
print(f"\nمجلد المشروع: {BASE_DIR}")

# ---------------------------------------------------------
# 1) هل نحن في جذر المشروع أصلًا؟
# ---------------------------------------------------------

if not (BASE_DIR / "wsgi.py").exists():
    print("\n[خطأ] هذا ليس جذر المشروع (لا يوجد wsgi.py).")
    sys.exit(1)

# ---------------------------------------------------------
# 2) البحث عن الملف وأخطاء التسمية الشائعة
# ---------------------------------------------------------

env_path = BASE_DIR / ".env"

print("\n--- 1. وجود الملف ---")

if not env_path.exists():
    print("  [خطأ] لا يوجد ملف .env في جذر المشروع.")
    problems.append("الملف غير موجود")

    # أخطاء تسمية يخفيها ويندوز
    for wrong in [".env.txt", "env", "env.txt", ".env.example"]:
        if (BASE_DIR / wrong).exists():
            if wrong == ".env.example":
                print(f"  [تنبيه] يوجد {wrong} فقط. انسخه وسمّه .env")
            else:
                print(f"  [السبب] وجدت ملفًا اسمه '{wrong}'.")
                print(f"          غيّر اسمه إلى '.env' بالضبط.")

    # هل أُنشئ في مجلد فرعي بالخطأ؟
    for sub in ["backend", "frontend"]:
        if (BASE_DIR / sub / ".env").exists():
            print(f"  [السبب] الملف موجود داخل مجلد {sub}/")
            print(f"          انقله إلى الجذر بجانب wsgi.py")

    print("\n" + "=" * 58)
    print("  النتيجة: أنشئ ملف .env في الجذر ثم أعد التشخيص")
    print("=" * 58)
    sys.exit(1)

size = env_path.stat().st_size
print(f"  [موجود] .env — الحجم {size} بايت")

if size == 0:
    print("  [خطأ] الملف فارغ.")
    problems.append("الملف فارغ")

# ---------------------------------------------------------
# 3) فحص علامة BOM الخفية
# ---------------------------------------------------------

print("\n--- 2. الترميز ---")

raw = env_path.read_bytes()

if raw.startswith(b"\xef\xbb\xbf"):
    print("  [خطأ] الملف يبدأ بعلامة BOM خفية.")
    print("         هذا يجعل اسم أول متغير غير مقروء.")
    print("         الحل: في VS Code اضغط على كلمة UTF-8 with BOM")
    print("         أسفل يمين النافذة، واختر Save with Encoding")
    print("         ثم UTF-8 (بدون BOM).")
    problems.append("علامة BOM")
else:
    print("  [سليم] لا توجد علامة BOM.")

# ---------------------------------------------------------
# 4) قراءة المتغيرات
# ---------------------------------------------------------

print("\n--- 3. المتغيرات ---")

try:
    from dotenv import dotenv_values
except ImportError:
    print("  [خطأ] مكتبة python-dotenv غير مثبّتة.")
    print("         نفّذ: pip install -r requirements.txt")
    sys.exit(1)

values = dotenv_values(env_path)

for key in REQUIRED:
    value = values.get(key)

    if value is None:
        print(f"  [ناقص] {key} غير موجود في الملف")
        problems.append(f"{key} ناقص")

    elif not value.strip():
        print(f"  [فارغ] {key} موجود لكن بلا قيمة بعد علامة =")
        problems.append(f"{key} فارغ")

    else:
        shown = value[:6] + "..." if len(value) > 10 else "(قصيرة)"
        print(f"  [سليم] {key} = {shown}")

debug_value = (values.get("FLASK_DEBUG") or "").strip().lower()

if debug_value == "true":
    print("  [سليم] FLASK_DEBUG = true (وضع التطوير المحلي)")
else:
    print("  [تنبيه] FLASK_DEBUG ليس true.")
    print("          محليًا هذا يمنع وصول كوكي الجلسة عبر http،")
    print("          فلن ينجح تسجيل الدخول في المتصفح.")
    problems.append("FLASK_DEBUG ليس true")

# كلمة مرور المدير يجب ألا تقل عن 12 محرفًا
admin_password = values.get("CYBERLENS_ADMIN_PASSWORD") or ""

if admin_password and len(admin_password) < 12:
    print(f"  [خطأ] كلمة مرور المدير {len(admin_password)} محرفًا،")
    print("         والحد الأدنى 12.")
    problems.append("كلمة المرور قصيرة")

# ---------------------------------------------------------
# 5) النتيجة
# ---------------------------------------------------------

print("\n" + "=" * 58)

if problems:
    print(f"  وجدت {len(problems)} مشكلة:")
    for item in problems:
        print(f"    - {item}")
else:
    print("  كل شيء سليم. شغّل المشروع بالأمر:")
    print("      python wsgi.py")

print("=" * 58)
