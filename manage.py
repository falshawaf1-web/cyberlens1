"""
manage.py — أداة إدارة CyberLens من سطر الأوامر
=========================================================

تُستخدم عندما لا تستطيع الدخول إلى الواجهة: نسيت كلمة المرور،
أو تحتاج إنشاء حساب على خادم إنتاج لا واجهة تفاعلية له.

الاستخدام:

    python manage.py create-admin
        إنشاء حساب مدير جديد بكلمة مرور تُدخَل بشكل مخفي.

    python manage.py reset-password <username>
        إعادة تعيين كلمة مرور مستخدم قائم.

    python manage.py list-users
        عرض الحسابات الموجودة.

    python manage.py gen-secret
        توليد مفتاح جلسة آمن لمتغير CYBERLENS_SECRET_KEY.

ملاحظة أمنية: كلمات المرور تُدخَل عبر getpass فلا تظهر على الشاشة
ولا تُحفظ في تاريخ الأوامر (bash history) — بخلاف تمريرها كوسيط.
"""

from __future__ import annotations

import getpass
import secrets
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR / "backend"))

from werkzeug.security import generate_password_hash  # noqa: E402

from database import (  # noqa: E402
    create_user,
    get_user_by_username,
    init_database,
    list_users_with_stats,
    update_user_password,
)


MIN_PASSWORD_LENGTH = 12


def _read_password(prompt: str = "كلمة المرور الجديدة: ") -> str | None:
    """قراءة كلمة المرور مرتين مع التحقق من الطول والتطابق."""
    password = getpass.getpass(prompt)

    if len(password) < MIN_PASSWORD_LENGTH:
        print(f"خطأ: الحد الأدنى {MIN_PASSWORD_LENGTH} محرفًا.")
        return None

    confirm = getpass.getpass("أعد إدخال كلمة المرور: ")

    if password != confirm:
        print("خطأ: كلمتا المرور غير متطابقتين.")
        return None

    return password


def create_admin() -> int:
    username = input("اسم المستخدم: ").strip()

    if not username:
        print("خطأ: اسم المستخدم مطلوب.")
        return 1

    if get_user_by_username(username):
        print(f"خطأ: المستخدم '{username}' موجود مسبقًا.")
        print("لتغيير كلمة مروره استخدم: python manage.py reset-password " + username)
        return 1

    password = _read_password()
    if not password:
        return 1

    create_user(username, generate_password_hash(password), is_admin=1, is_active=1)
    print(f"تم إنشاء حساب المدير '{username}' بنجاح.")
    return 0


def reset_password(username: str) -> int:
    user = get_user_by_username(username)

    if not user:
        print(f"خطأ: المستخدم '{username}' غير موجود.")
        return 1

    password = _read_password()
    if not password:
        return 1

    if update_user_password(int(user["id"]), generate_password_hash(password)):
        print(f"تم تغيير كلمة مرور '{username}' بنجاح.")
        return 0

    print("خطأ: فشل تحديث كلمة المرور.")
    return 1


def list_users() -> int:
    users = list_users_with_stats() or []

    if not users:
        print("لا توجد حسابات.")
        return 0

    print(f"{'المعرّف':<8}{'المستخدم':<24}{'مدير':<8}{'نشط':<8}")
    print("-" * 48)

    for user in users:
        print(
            f"{user.get('id', ''):<8}"
            f"{str(user.get('username', '')):<24}"
            f"{'نعم' if user.get('is_admin') else 'لا':<8}"
            f"{'نعم' if user.get('is_active') else 'لا':<8}"
        )

    return 0


def gen_secret() -> int:
    print("أضف هذا السطر إلى ملف .env أو إلى متغيرات البيئة في Render:\n")
    print(f"CYBERLENS_SECRET_KEY={secrets.token_hex(32)}")
    return 0


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 1

    command = sys.argv[1].strip().lower()

    if command == "gen-secret":
        return gen_secret()

    init_database()

    if command == "create-admin":
        return create_admin()

    if command == "list-users":
        return list_users()

    if command == "reset-password":
        if len(sys.argv) < 3:
            print("الاستخدام: python manage.py reset-password <username>")
            return 1
        return reset_password(sys.argv[2].strip())

    print(f"أمر غير معروف: {command}")
    print(__doc__)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
