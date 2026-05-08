"""Gemini client for ticket note generation."""
from __future__ import annotations

import requests

from config import Settings


GEMINI_BASE = "https://generativelanguage.googleapis.com"


def gemini_list_models(settings: Settings) -> tuple[list[str], str]:
    if not settings.gemini_key:
        return [], "Missing GEMINI_KEY"
    version = settings.gemini_api_version or "v1beta"
    url = f"{GEMINI_BASE}/{version}/models"
    try:
        r = requests.get(
            url,
            headers={"x-goog-api-key": settings.gemini_key},
            timeout=15,
        )
    except requests.RequestException:
        return [], "Network error"
    if r.status_code != 200:
        return [], f"HTTP {r.status_code}: {r.text[:300]}"
    data = r.json()
    models = []
    for m in data.get("models", []):
        name = m.get("name")
        methods = m.get("supportedGenerationMethods", [])
        if name and "generateContent" in methods:
            models.append(name.replace("models/", ""))
    return models, ""


def gemini_generate(prompt: str, settings: Settings, use_backup: bool = False) -> tuple[str, str]:
    key = settings.gemini_key_backup if use_backup else settings.gemini_key
    if not key:
        return "", "Missing GEMINI_KEY"
    version = settings.gemini_api_version or "v1beta"
    model = settings.gemini_model or "gemini-1.5-flash"
    url = f"{GEMINI_BASE}/{version}/models/{model}:generateContent"
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {
            "temperature": 0.2,
            "topP": 0.9,
            "maxOutputTokens": 8192,
        },
    }
    try:
        r = requests.post(
            url,
            headers={"x-goog-api-key": key, "Content-Type": "application/json"},
            json=payload,
            timeout=20,
        )
    except requests.RequestException:
        return "", "Network error"
    if r.status_code != 200:
        return "", f"HTTP {r.status_code}: {r.text[:300]}"
    data = r.json()
    candidates = data.get("candidates", [])
    if not candidates:
        return "", "No candidates in response"
    parts = candidates[0].get("content", {}).get("parts", [])
    texts = [p.get("text", "") for p in parts if p.get("text")]
    return "\n".join(texts).strip(), ""
