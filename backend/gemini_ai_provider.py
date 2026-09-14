import json
import os
import urllib.error
import urllib.parse
import urllib.request


def error_name(exc):
    value = str(type(exc))
    value = value.replace("<class '", "")
    value = value.replace("'>", "")
    return value.split(".")[-1]


def extract_text(data):
    candidates = data.get("candidates") or []
    if not candidates:
        return ""

    content = candidates[0].get("content") or {}
    parts = content.get("parts") or []

    texts = []
    for part in parts:
        text = part.get("text") or ""
        if text:
            texts.append(text)

    return "\n".join(texts).strip()


def call_model(api_key, model, prompt, extract_json_object):
    endpoint = (
        "https://generativelanguage.googleapis.com/v1beta/models/"
        + urllib.parse.quote(model, safe="-_.")
        + ":generateContent"
    )

    body = {
        "contents": [
            {
                "role": "user",
                "parts": [
                    {
                        "text": prompt
                    }
                ],
            }
        ],
        "generationConfig": {
            "temperature": 0.2,
            "maxOutputTokens": 1200,
        },
    }

    request = urllib.request.Request(
        endpoint,
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "x-goog-api-key": api_key
        },
        method="POST",
    )

    with urllib.request.urlopen(request, timeout=25) as response:
        raw = response.read().decode("utf-8", errors="replace")
        data = json.loads(raw)

    response_text = extract_text(data)
    return extract_json_object(response_text)


def try_gemini_ai(
    findings,
    target_name,
    scan_type,
    build_ai_payload,
    build_external_instructions,
    extract_json_object,
):
    api_key = os.getenv("GEMINI_API_KEY", "").strip()

    if not api_key:
        print("[CyberLens AI] GEMINI_API_KEY is missing")
        return None

    configured_model = os.getenv("GEMINI_MODEL", "").strip()

    models = []
    if configured_model:
        models.append(configured_model)

    for fallback_model in [
        "gemini-2.0-flash",
        "gemini-1.5-flash",
        "gemini-1.5-flash-latest",
    ]:
        if fallback_model not in models:
            models.append(fallback_model)

    payload = build_ai_payload(
        findings=findings,
        target_name=target_name,
        scan_type=scan_type,
    )

    prompt = (
        build_external_instructions()
        + "\n\nReturn valid JSON only. Analyze this CyberLens scan payload:\n"
        + json.dumps(payload, ensure_ascii=False)
    )

    for model in models:
        try:
            parsed = call_model(
                api_key,
                model,
                prompt,
                extract_json_object,
            )

            if not parsed:
                print("[CyberLens AI] Gemini returned no valid JSON for model:", model)
                continue

            parsed["provider"] = "Gemini"
            parsed["model"] = model

            print("[CyberLens AI] External AI used: Gemini", model)
            return parsed

        except urllib.error.HTTPError as exc:
            try:
                details = exc.read().decode("utf-8", errors="replace")
            except Exception:
                details = str(exc)

            print("[CyberLens AI] Gemini HTTP error:", exc.code, model, details[:400])

            if exc.code in (401, 403):
                return None

            continue

        except Exception as exc:
            print("[CyberLens AI] Gemini call failed:", error_name(exc), model, str(exc)[:400])
            continue

    print("[CyberLens AI] Gemini unavailable, using local analyzer")
    return None


def check_gemini_status():
    api_key = os.getenv("GEMINI_API_KEY", "").strip()
    model = os.getenv("GEMINI_MODEL", "gemini-2.0-flash").strip()

    if not api_key:
        return {
            "ok": False,
            "reason": "missing_gemini_api_key",
            "model": model,
            "has_key": False,
        }

    endpoint = (
        "https://generativelanguage.googleapis.com/v1beta/models/"
        + urllib.parse.quote(model, safe="-_.")
        + ":generateContent"
    )

    body = {
        "contents": [
            {
                "role": "user",
                "parts": [
                    {
                        "text": "Return JSON only: {\\\"ok\\\": true, \\\"source\\\": \\\"gemini\\\"}"
                    }
                ],
            }
        ],
        "generationConfig": {
            "temperature": 0,
            "maxOutputTokens": 100,
        },
    }

    request = urllib.request.Request(
        endpoint,
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "x-goog-api-key": api_key,
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            raw = response.read().decode("utf-8", errors="replace")
            data = json.loads(raw)

        text = extract_text(data)

        return {
            "ok": True,
            "reason": "gemini_connection_success",
            "model": model,
            "has_key": True,
            "response_preview": text[:300],
        }

    except urllib.error.HTTPError as exc:
        try:
            details = exc.read().decode("utf-8", errors="replace")
        except Exception:
            details = str(exc)

        return {
            "ok": False,
            "reason": "gemini_http_error",
            "http_status": exc.code,
            "model": model,
            "has_key": True,
            "details": details[:700],
        }

    except Exception as exc:
        return {
            "ok": False,
            "reason": "gemini_exception",
            "error_type": error_name(exc),
            "model": model,
            "has_key": True,
            "details": str(exc)[:700],
        }
