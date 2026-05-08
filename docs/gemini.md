# Google Gemini

Google Gemini is a large language model used by IOC Router to generate human-readable incident ticket narratives. Given a structured summary of threat flags, raw provider logs, and IOC metadata, Gemini produces a SOC-ready incident description that can be pasted directly into a ticketing system.

---

## How It Works (Technical)

### Endpoint Used

[`providers/gemini.py`](../providers/gemini.py) calls the Gemini Generative Language API:

```
POST https://generativelanguage.googleapis.com/{version}/models/{model}:generateContent
```

The `version` and `model` are configurable via `.env` (see below). The default values are `v1` and `gemini-2.5-flash`.

### Authentication

API key sent via the `x-goog-api-key` HTTP header:

```
x-goog-api-key: <GEMINI_KEY>
```

### Model Listing

A secondary function `gemini_list_models()` ([`providers/gemini.py:12`](../providers/gemini.py#L12)) calls:

```
GET https://generativelanguage.googleapis.com/{version}/models
```

This is used by the UI to populate the model selector dropdown. Only models that support the `generateContent` method are listed.

### Request Payload

[`providers/gemini.py:37`](../providers/gemini.py#L37) sends a JSON payload structured as:

```json
{
  "contents": [
    { "parts": [{ "text": "<prompt>" }] }
  ],
  "generationConfig": {
    "temperature": 0.2,
    "topP": 0.9,
    "maxOutputTokens": 8192
  }
}
```

Low temperature (`0.2`) is used to keep outputs factual and deterministic. `maxOutputTokens` is capped at 8 192 to stay within free-tier limits.

### Prompt Construction

The prompt is assembled in [`ui/components/ai_panel.py`](../ui/components/ai_panel.py) from:
- IOC value, type, and final verdict
- Extracted threat flags (with severity levels)
- Raw provider responses (JSON excerpts)
- Analyst-provided context (asset name, business impact, initial notes)

### Response Parsing

[`providers/gemini.py:64`](../providers/gemini.py#L64) extracts the generated text from:

```
response.candidates[0].content.parts[].text
```

Multiple parts are joined with newlines if the model splits the output.

### Backup Key Support

A second API key (`GEMINI_KEY_BACKUP`) can be configured. If the primary key fails, the UI can retry with the backup key by calling `gemini_generate(prompt, settings, use_backup=True)` ([`providers/gemini.py:37`](../providers/gemini.py#L37)).

### Timeout

- Timeout: **20 seconds** per request

---

## Getting an API Key

1. Go to [https://aistudio.google.com/](https://aistudio.google.com/) and sign in with a Google account.
2. Click **Get API key** in the left sidebar (or navigate to [https://aistudio.google.com/app/apikey](https://aistudio.google.com/app/apikey)).
3. Click **Create API key in new project** (or select an existing Google Cloud project).
4. Copy the generated key.
5. Add it to `.env`:
   ```env
   GEMINI_KEY=your_api_key_here
   GEMINI_KEY_BACKUP=your_backup_key_here   # optional
   GEMINI_MODEL=gemini-2.5-flash            # optional, this is the default
   GEMINI_API_VERSION=v1                    # optional, this is the default
   ```

**Free tier:** Google AI Studio provides a free quota for Gemini API calls (rate-limited by requests per minute and tokens per day). The `gemini-2.5-flash` model is the recommended default for speed and cost efficiency. For higher throughput, a Google Cloud billing account is required.
