# Project Hunt — API keys: what actually works (verified 2026-10-09)

Checked against the deployed codebase (`lib/tools/`, `lib/config.ts`, `lib/tools/registry.ts`).
TL;DR: **only 2 of the 8 README "key-gated modules" have real implementations.**
The other 6 are stubs — setting their env vars flips the catalogue chip but
no upstream call is ever made. Do not pay for keys (e.g. HIBP) until those
modules are implemented.

## Keys that do something TODAY

### 1. FACTCHECKTOOLS_API_KEY — Google Fact Check Tools (REAL, needs key)
- The only key-gated module with a working implementation (`lib/tools/factcheck.ts`).
- Without the key the module is hidden from hunts entirely.
- Free. Get it: Google Cloud Console → create/select a project → enable
  "Fact Check Tools API" → Credentials → Create API key.
  Docs: https://developers.google.com/fact-check/tools/api
- This is the single key worth setting tonight.

### 2. IPINFO_API_KEY — IPinfo (REAL, optional)
- Module already works WITHOUT a key (free tier, keyless).
- Setting the key raises limits to 50k requests/month.
- Free. Get it: https://ipinfo.io → sign up → dashboard token.
  Docs: https://ipinfo.io/developers

## Keys that currently do NOTHING (stub modules)

Setting these env vars is accepted by config and flips the catalogue chip,
but the module emits a "key required" finding and makes no upstream call.
Verified in `lib/tools/*.ts` — each is `extends StubTool`.

| Env var | Status | What it would need if implemented later |
|---|---|---|
| SHODAN_API_KEY | stub | Free account at shodan.io → My Account → API key (~100 query credits/mo free) |
| VIRUSTOTAL_API_KEY | stub | Free signup at virustotal.com → profile → API key (500 req/day, 4/min free) |
| HIBP_API_KEY | stub | **PAID** — account/email lookups need a paid key (~$4.39/mo, haveibeenpwned.com/API/Key). Free no-key alternatives exist: Pwned Passwords range API + breach catalogue endpoints |
| GREYNOISE_API_KEY | stub | **Free community keys discontinued 2026** — no longer issued to new accounts. Public `GET /v3/community/{ip}` works keyless but throttled per source IP. Key only matters with paid Enterprise |
| SECURITYTRAILS_API_KEY | stub | Free tier: 50 queries/mo — https://securitytrails.com/app/signup |
| MALTEGO_API_KEY | stub | No standard public REST API-key model — needs a design decision before any key helps |

## How keys reach the live Vercel deployment

- `.env` is local-dev only. Vercel serverless ignores it at runtime.
- Set each key in Vercel: Project Settings → Environment Variables →
  add for Production + Preview + Development, mark Sensitive.
- Then **redeploy** — serverless functions read env at deploy time.
- `DATABASE_URL` is already set this way (that's how the deploy works).
- Never commit keys to the repo. Never paste them into the app UI.

## Suggested order (your call)

1. `FACTCHECKTOOLS_API_KEY` — free, unlocks a real module tonight.
2. `IPINFO_API_KEY` — free, raises limits on a module that already works.
3. Hold the other six until their modules get real implementations
   (port from the Python original's `api/core/hunt/ingestion/`).

## Notes

- `GEMINI_API_KEY` exists in `lib/config.ts` but is unused anywhere — dead config.
- Free, no-key modules working out of the box: DNS, WHOIS, crt.sh,
  Wayback, IPinfo, Indian Kanoon, eCourts, TAFCOP, myNeta/ADR.
