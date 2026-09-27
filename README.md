# AI EDR Assistant — Prototype

Suggests new EDR detection rules (Sigma format) by comparing existing rules
against observed activity, using a **local** LLM. Every suggestion requires
human approval before it's written to disk.

## Setup (do this once, before the demo, on good wifi)

```bash
# 1. Install Ollama: https://ollama.com
ollama pull llama3.1:8b     # or a smaller model if your laptop is weak: phi3, mistral:7b
ollama pull nomic-embed-text  # local embedding model, used for correction memory

# 2. Python deps
pip install -r requirements.txt
```

If you pull a different model, update `MODEL_NAME` at the top of `llm_generator.py`.

## Run it

```bash
ollama serve          # if not already running as a background service
streamlit run app.py  # opens http://localhost:8501
```

## Demo flow

1. **Section 1** — show the existing Sigma rules already in place (3 rules).
2. **Section 2** — click "Run gap analysis". This is plain Python, no LLM:
   it scans the sample logs against a MITRE ATT&CK technique map and finds
   activity (LSASS dumping, suspicious RDP logon, local account creation)
   that isn't covered by any existing rule.
3. **Section 3** — for each gap, click "Generate suggestion". This is the
   only step that calls the local model. You'll get back:
   - a draft Sigma rule, rationale, and estimated false-positive risk
   - **a one-time self-test**, generated automatically before you see the
     final answer: synthetic attack variants (to check the rule
     generalizes) and synthetic benign look-alikes (to check it doesn't
     over-fire on normal activity) — run once, not a retry loop
   - a live test-fire count against the real sample logs
   - if past corrections exist for a similar gap, a note showing they were
     used as guidance for this draft
4. **Not quite right?** Type feedback in plain English (e.g. "narrow this
   to exclude svchost.exe") and click **Refine with feedback** — one more
   LLM pass, not manual YAML editing. You can also just hand-edit the YAML
   directly in the text box.
5. Click **Approve** (writes the rule to `approved_rules/`, logs the
   decision, and — if your final version differs from the AI's first
   draft — stores that diff in correction memory) or **Reject** (nothing
   written). Nothing reaches `approved_rules/` without this explicit step.
6. **Section 4** — correction memory: every analyst fix that changed the
   AI's first draft, embedded and stored locally. Generate a suggestion for
   a similar gap later and watch it get pulled in as guidance automatically.
7. **Section 5** — audit log: every approve/reject decision, timestamped.

## Proving the "runs locally" claim live

Turn off wifi before clicking "Generate suggestion" — it still works,
because the only thing it talks to is `localhost:11434` (Ollama).

## Files

- `sample_data/existing_rules.yaml` — fixture: the EDR's current ruleset
- `sample_data/sample_logs.json` — fixture: synthetic Sysmon-style events
- `sample_data/technique_map.json` — MITRE technique → log-pattern map
- `gap_analysis.py` — deterministic gap detection (no LLM)
- `llm_generator.py` — calls Ollama: generate, refine (feedback), self-test
- `test_fire.py` — runs a candidate rule against a set of logs
- `corrections_store.py` — local embedding-based memory of analyst corrections
- `app.py` — Streamlit UI wiring it all together
- `corrections_memory.json` — created at runtime, holds correction history
- `audit_log.json` — created at runtime, holds approve/reject decisions

## Path to a real MVP (say this in your pitch)

- Ingest a real EDR's exported rules/logs instead of fixtures
- Expand the MITRE technique map beyond the demo's ~6 techniques
- Swap the naive test-fire matcher for a real Sigma backend (pySigma + a
  target backend) for accurate query translation
- Handle malformed/unexpected input without crashing
