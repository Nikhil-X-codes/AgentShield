# Groq integration check

**Status:** Verified locally on 2026-11-04 with synthetic prompts and `openai/gpt-oss-20b`.

## Results

- AgentShield loaded `GROQ_API_KEY`, `GROQ_ATTACK_MODEL`, and `GROQ_JUDGE_MODEL` from the local `.env` file. No key value or prefix is recorded here.
- The standalone Groq SDK `models.list()` call succeeded and returned 11 models.
- The opt-in AgentShield Groq test file completed with 3 passed tests: missing-key handling, one bounded synthetic attack generation request, and one synthetic semantic-judge request.
- The full local suite completed with 39 passed and 2 optional Groq checks skipped by default. The live checks were run separately with `AGENTSHIELD_RUN_GROQ_TESTS=1`.

## Request handling

AgentShield now uses Groq's official Python SDK. The shared client disables automatic retries and redirects and applies the configured timeout. Generated attack and judge requests retain their existing token budgets and strict output validation.

During diagnosis, a raw `urllib` request received an HTTP 403 plain-text response from a Cloudflare edge. The SDK's read-only models request succeeded. An initial SDK generation request returned HTTP 400 with code `json_validate_failed` and an empty `failed_generation`; GPT-OSS requests now set `reasoning_format: hidden` and `reasoning_effort: low`. The subsequent bounded generation and judge checks passed.

The Groq tests send only synthetic fixture text. This check does not establish coverage against a live agent target. `.env` is local and is not committed.

## Re-run

From the repository root in PowerShell:

```powershell
$env:AGENTSHIELD_RUN_GROQ_TESTS = "1"
python -m pytest -q tests/unit/test_groq_optional.py
```
