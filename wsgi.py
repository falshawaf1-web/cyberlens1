"""
=========================================================
CyberLens - WSGI Entry Point
=========================================================
نقطة الدخول للإنتاج:  gunicorn wsgi:app
وللتشغيل المحلي:      python wsgi.py
=========================================================
"""

import os
import sys
from pathlib import Path

# المسارات تُشتق من موقع الملف لا من مجلد العمل الحالي،
# حتى يعمل التشغيل من أي مجلد ومع أي مدير عمليات.
BASE_DIR = Path(__file__).resolve().parent

if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))


# =========================================================
# تحميل متغيرات البيئة من .env قبل استيراد التطبيق،
# لأن app.py يقرأ CYBERLENS_SECRET_KEY وقت الاستيراد.
# =========================================================

try:
    from dotenv import load_dotenv

    load_dotenv(BASE_DIR / ".env")

except Exception as exc:
    print("[CyberLens] .env not loaded:", str(exc)[:200])


# init_database تُستدعى داخل app.py وقت الاستيراد،
# فتعمل مع gunicorn ومع التشغيل المباشر على السواء.
from backend.app import app  # noqa: E402


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

    app.run(host=host, port=port, debug=debug_mode)
