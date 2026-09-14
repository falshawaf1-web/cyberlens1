import json
import os


def groq_error_name(exc):
    value = str(type(exc))
    value = value.replace("<class '", "")
    value = value.replace("'>", "")
    return value.split(".")[-1]


def _max_tokens() -> int:
    """
    حد المخرجات لكل استدعاء.

    الافتراضي 6000 يكفي لتحليل أربع نتائج بكل حقولها التفصيلية مع
    هامش لتفكير النموذج الداخلي. يمكن خفضه عبر CYBERLENS_AI_MAX_TOKENS
    عند الحاجة لتسريع الاستجابة.
    """
    try:
        value = int(os.environ.get("CYBERLENS_AI_MAX_TOKENS", "3000"))
    except (ValueError, TypeError):
        return 3000

    # =====================================================
    # السقف مقيّد بحد المزوّد لا بحاجة النموذج
    # =====================================================
    #
    # حساب Groq المجاني محدود بـ 8000 توكن في الدقيقة (TPM)، وهذا
    # الحد يشمل المدخلات والمخرجات معًا. وبطلب مخرجات 8000 توكن يصبح
    # إجمالي الطلب نحو 9500 — فيُرفض بالرمز 413 قبل أن يبدأ التنفيذ.
    #
    # السقف 3000 يترك مساحة كافية للتعليمات والمدخلات ضمن الحد.
    # ارفعيه فقط إن رُقّي الحساب إلى خطة أعلى.
    return max(1000, min(value, 7000))


def try_groq_ai(
    findings,
    target_name,
    scan_type,
    build_ai_payload,
    build_external_instructions,
    extract_json_object,
):
    api_key = os.getenv("GROQ_API_KEY", "").strip()
    model = os.getenv(
        "GROQ_MODEL",
        "llama-3.3-70b-versatile",
    ).strip()

    if not api_key:
        print("[CyberLens AI] GROQ_API_KEY is missing")
        return None

    try:
        from openai import OpenAI
    except Exception as exc:
        print(
            "[CyberLens AI] Groq client import failed:",
            groq_error_name(exc),
            str(exc)[:300],
        )
        return None

    payload = build_ai_payload(
        findings=findings,
        target_name=target_name,
        scan_type=scan_type,
    )

    try:
        client = OpenAI(
            api_key=api_key,
            base_url="https://api.groq.com/openai/v1",
        )

        response = client.chat.completions.create(
            model=model,
            response_format={"type": "json_object"},
            messages=[
                {
                    "role": "system",
                    "content": build_external_instructions(),
                },
                {
                    "role": "user",
                    "content": (
                        "Return valid JSON only.\n\n"
                        + json.dumps(
                            payload,
                            ensure_ascii=False,
                        )
                    ),
                },
            ],
            temperature=0.2,

            # =====================================================
            # حد المخرجات
            # =====================================================
            #
            # المشكلة التي عالجها رفع هذا الحد:
            #
            #   نماذج gpt-oss تستهلك جزءًا من ميزانية المخرجات في
            #   تفكير داخلي قبل إنتاج الإجابة. وبحد 1400 توكن كانت
            #   الميزانية تنفد قبل اكتمال حقل detailed_analysis،
            #   فتصل استجابة مقطوعة تحتوي summary فقط.
            #
            #   والأثر أن النظام يعتبر التحليل فاشلًا ويسقط للمحلل
            #   المحلي، رغم أن الاستدعاء نجح فعلًا.
            #
            #   الدليل التشخيصي: عند max_tokens منخفض جدًا يعود المحتوى
            #   فارغًا تمامًا — لأن كامل الميزانية استُهلك في التفكير.
            #
            # القيمة قابلة للضبط من البيئة لموازنة الجودة مقابل التكلفة.
            max_tokens=_max_tokens(),

            # =====================================================
            # مهلة صريحة — ضرورية لا اختيارية
            # =====================================================
            #
            # بدون هذه المهلة تستخدم المكتبة القيمة الافتراضية البالغة
            # عشر دقائق. ومع تعدد الدفعات يتجاوز الطلب مهلة Gunicorn
            # (120 ثانية) فيُقتَل العامل بإشارة SIGKILL، ويُظهر السجل
            # الرسالة المضللة "Perhaps out of memory" بينما السبب
            # الحقيقي هو انتهاء المهلة لا نفاد الذاكرة.
            timeout=45.0,
        )

        response_text = (
            response.choices[0].message.content
            or ""
        )

        # طباعة مختصرة فقط: 3000 محرف لكل دفعة تُثقل سجلات Render
        # وتبطئ الاستجابة دون فائدة تشخيصية حقيقية.
        print(
            "[CyberLens AI] استجابة Groq:",
            len(response_text),
            "محرف",
        )
        parsed = extract_json_object(
            response_text
        )

        if not parsed:
            print(
                "[CyberLens AI] Groq returned no valid JSON"
            )
            return None

        # تشخيص صريح عند نقص الحقل الجوهري.
        #
        # بدون هذا التحذير كان الفشل صامتًا: الاستدعاء ينجح، ثم يُهمَل
        # الناتج في طبقة أعلى، فتعرض الواجهة الوضع المحلي دون أي مؤشر
        # على السبب — وهو أصعب أنواع الأخطاء في التتبّع.
        if not parsed.get("detailed_analysis"):
            print(
                "[CyberLens AI] تحذير: استجابة Groq بلا detailed_analysis",
                f"(الطول {len(response_text)} محرف)",
                "— قد يكون max_tokens غير كافٍ.",
            )

        parsed["provider"] = "Groq"
        parsed["model"] = model

        print(
            "[CyberLens AI] External AI used: Groq",
            model,
        )

        return parsed

    except Exception as exc:
        print(
            "[CyberLens AI] Groq call failed:",
            groq_error_name(exc),
            str(exc)[:600],
        )
        return None
