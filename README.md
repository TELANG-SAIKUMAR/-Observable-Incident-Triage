# Incident agent (ga5-incident-agent/v2)

Zero-dependency Node 18+ service. Files: `server.js` (the whole agent), `sim.js` (local mock-LLM + simulated grader).

## Configure (env vars)
- `LLM_API_KEY` – key for any OpenAI-compatible chat endpoint (required)
- `LLM_BASE_URL` – default `https://generativelanguage.googleapis.com/v1beta/openai` (Gemini free tier). Groq: `https://api.groq.com/openai/v1`, OpenRouter: `https://openrouter.ai/api/v1`
- `LLM_MODEL` – default `gemini-2.5-flash-lite`; use any cheap model your provider offers (needs JSON mode and ~30k+ context)
- `DATA_DIR` – where run state is stored (default `./data`); `PORT` – default 8080

## Test locally (no real model, no Check used)
    node sim.js

## Deploy
Any host that gives a public HTTPS URL without redirects works (Render, Fly.io, Railway, Cloud Run). Use the Dockerfile or `node server.js`. Set the env vars above, then submit the base URL (e.g. `https://your-app.onrender.com`) with no trailing path.
Free hosts may sleep: hit `/healthz` first so a Check doesn't hit a cold start (18 s limit per request).

## Design notes
- One model call per new runId (planner). Receipts, retries, GET, replay and OTLP are built from stored state only.
- The `sensitive` object is never sent to the model and never stored.
- If the model call fails, a weak keyword heuristic keeps the run valid, and the chat span gets `error.type`.
- `suppressed` entries are objects: `{toolName, reason}` (plus `actionId` for denied approvals).
