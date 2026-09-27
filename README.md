# AI EDR Assistant — Prototype

Suggests new EDR detection rules (Sigma format) by comparing existing rules
against observed activity, using a **local** LLM. Every suggestion requires
human approval before it's written to disk.

## Setup
```bash
# 1. Install Ollama: https://ollama.com
ollama pull llama3.1:8b
ollama pull nomic-embed-text

# 2. Python deps
pip install -r requirements.txt
```

## Run it

```bash
ollama serve
streamlit run app.py
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

