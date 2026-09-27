import json
import re

import ollama
import yaml as _yaml

MODEL_NAME = "llama3.1:8b"

SYSTEM_PROMPT = """You are a detection engineering assistant helping a security \
analyst write Sigma rules. You only draft suggestions - a human always reviews \
and approves before anything is deployed. Follow the Sigma rule format exactly.

CRITICAL output format:
- Start your reply with a fenced code block: ```yaml on its own line, then the rule, \
then ``` on its own line.
- The code block must contain exactly ONE Sigma rule document.
- Do NOT use --- YAML document separators inside the code block.
- Quote description values that contain colons, e.g. description: "Detects X: Y".
- After the closing ```, add plain text sections: "Rationale:" and \
"Estimated false-positive risk:" (Low/Medium/High with one sentence why)."""

SELF_TEST_SYSTEM_PROMPT = """You generate synthetic test log events to validate a \
draft Sigma detection rule, matching the same JSON log schema as the examples shown \
(fields like timestamp, host, EventType, Image, CommandLine, TargetObject, \
DestinationPort, User, etc). Respond with ONLY a single JSON object, no prose, no \
markdown fences, with exactly two keys:
"malicious_variants": 2-3 log events showing plausible different-looking ways the \
same attack technique could appear, that a GOOD rule should still catch.
"benign_lookalikes": 2-3 log events from ordinary legitimate admin/IT activity that \
superficially resembles the attack pattern but is NOT malicious, to check the rule \
doesn't over-fire on normal activity."""


def _build_prompt(gap: dict, style_examples: str, past_corrections: list[dict] | None = None) -> str:
    log_sample = "\n".join(str(log) for log in gap["matching_logs"][:3])

    correction_context = ""
    if past_corrections:
        blocks = []
        for c in past_corrections:
            blocks.append(
                f"- For a similar past gap ({c['gap_description']}), a first draft was:\n"
                f"  {c['original_yaml'].strip()}\n"
                f"  The analyst corrected it to:\n"
                f"  {c['corrected_yaml'].strip()}\n"
                f"  Analyst's note: {c.get('note') or '(no note given)'}"
            )
        correction_context = (
            "\n\nIMPORTANT - apply lessons from past analyst corrections on similar gaps:\n"
            + "\n".join(blocks)
            + "\nMake sure your new draft reflects these corrections where relevant.\n"
        )

    return f"""Existing rules in this environment (for style/format reference only):

{style_examples}
{correction_context}
---

A detection gap has been found. Logs show activity matching MITRE ATT&CK \
technique {gap['technique_id']} - {gap['name']}, but no existing rule covers it.

Sample matching log events:
{log_sample}

Write ONE new Sigma rule to detect this technique, in the same style as the \
existing rules above. Give it a new random UUID for the id field, tag it with \
"{gap['tag']}", and set an appropriate level. Then explain your rationale and \
estimated false-positive risk."""


_SIGMA_START = re.compile(r"^(?:---\s*\n)?title\s*:", re.MULTILINE | re.IGNORECASE)
_TRAILING_SECTION = re.compile(
    r"\n\s*(?:Rationale|Estimated false-positive risk)\s*:",
    re.IGNORECASE,
)


def _looks_like_sigma_rule(text: str) -> bool:
    return bool(_SIGMA_START.search(text.strip()))


def _trim_trailing_prose(text: str) -> str:
    match = _TRAILING_SECTION.search(text)
    return text[: match.start()].strip() if match else text.strip()


def _sanitize_yaml_for_parsing(yaml_text: str) -> str:
    """Fix common LLM YAML mistakes before parsing."""
    lines: list[str] = []
    for line in yaml_text.splitlines():
        desc = re.match(r"^(\s*description\s*:\s*)(.+)$", line)
        if desc and ":" in desc.group(2) and not re.match(r'^["\']', desc.group(2)):
            value = desc.group(2).replace('"', '\\"')
            line = f'{desc.group(1)}"{value}"'
        lines.append(line)
    return "\n".join(lines)


def _extract_yaml_block(text: str) -> str | None:
    """Extract Sigma rule YAML from fenced blocks or bare model output."""
    for pattern in (
        r"```(?:yaml|yml)\s*\n(.*?)```",
        r"```\s*\n(.*?)```",
        r"```(?:yaml|yml)?\s*(.*?)```",
    ):
        for match in re.finditer(pattern, text, re.DOTALL | re.IGNORECASE):
            candidate = _trim_trailing_prose(match.group(1).strip())
            if _looks_like_sigma_rule(candidate):
                return candidate

    # Some local models omit markdown fences and return raw YAML.
    stripped = text.strip()
    if _looks_like_sigma_rule(stripped):
        return _trim_trailing_prose(stripped)

    match = re.search(r"(title\s*:.*)", stripped, re.DOTALL | re.IGNORECASE)
    if match:
        candidate = _trim_trailing_prose(match.group(1).strip())
        if _looks_like_sigma_rule(candidate):
            return candidate
    return None


def _extract_json_block(text: str) -> str:
    match = re.search(r"```(?:json)?\s*(.*?)```", text, re.DOTALL)
    return match.group(1).strip() if match else text.strip()


def _extract_section(text: str, label: str) -> str:
    pattern = rf"{label}:?\s*(.*?)(?:\n\s*\n|\Z)"
    match = re.search(pattern, text, re.DOTALL | re.IGNORECASE)
    return match.group(1).strip() if match else "(not provided)"


def _parse_yaml_document(yaml_text: str):
    """Parse one Sigma rule from model output; tolerate extra --- documents."""

    last_error: _yaml.YAMLError | None = None
    for candidate in (yaml_text, _sanitize_yaml_for_parsing(yaml_text)):
        try:
            parsed = _yaml.safe_load(candidate)
            if parsed is not None:
                return parsed
        except _yaml.YAMLError as e:
            if "found another document" in str(e):
                docs = [doc for doc in _yaml.safe_load_all(candidate) if doc]
                if docs:
                    return docs[0]
            last_error = e
    if last_error is not None:
        raise last_error
    return None


def _parse_model_response(raw_text: str) -> dict:
    yaml_text = _extract_yaml_block(raw_text)
    parsed_rule = None
    parse_error = None
    if yaml_text:
        try:
            parsed_rule = _parse_yaml_document(yaml_text)
            if parsed_rule is None:
                parse_error = "YAML block was empty"
        except _yaml.YAMLError as e:
            parse_error = str(e)
    else:
        parse_error = "no YAML code block found in model response"

    if parsed_rule is not None:
        yaml_text = _yaml.dump(parsed_rule, sort_keys=False).strip()

    return {
        "rule_yaml_text": yaml_text or "",
        "parsed_rule": parsed_rule,
        "rationale": _extract_section(raw_text, "Rationale"),
        "fp_risk": _extract_section(raw_text, "Estimated false-positive risk"),
        "raw_response": raw_text,
        "parse_error": parse_error,
    }


def generate_rule_suggestion(
    gap: dict,
    style_examples: str,
    past_corrections: list[dict] | None = None,
    retry_note: str = "",
) -> dict:
    """Calls the local model and returns a parsed suggestion dict."""
    prompt = _build_prompt(gap, style_examples, past_corrections)
    if retry_note:
        prompt += (
            f"\n\nNote: a previous attempt failed to parse ({retry_note}). "
            "You MUST wrap the rule in a ```yaml fenced code block, quote any "
            "description values that contain colons, and ensure the YAML is valid."
        )

    response = ollama.chat(
        model=MODEL_NAME,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
    )
    result = _parse_model_response(response["message"]["content"])

    if result["parsed_rule"] is None and not retry_note:
        return generate_rule_suggestion(
            gap, style_examples, past_corrections,
            retry_note=result["parse_error"] or "unknown error",
        )
    return result


def refine_rule_suggestion(gap: dict, current_yaml: str, feedback: str, style_examples: str) -> dict:
    """
    Applies ONE round of human feedback to an existing draft. This is a
    single call, not a loop - the analyst decides if/when to click again.
    """
    prompt = f"""Existing rules in this environment (for style/format reference only):

{style_examples}

---

Here is a draft Sigma rule for MITRE ATT&CK technique {gap['technique_id']} - {gap['name']}:

{current_yaml}

The security analyst reviewing this draft has this feedback on what to improve:
"{feedback}"

Revise the rule to address this feedback. Keep the same id if one was already \
set. Then briefly restate the rationale and estimated false-positive risk."""

    response = ollama.chat(
        model=MODEL_NAME,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
    )
    return _parse_model_response(response["message"]["content"])


def generate_self_test_logs(gap: dict, parsed_rule: dict) -> dict:
    rule_yaml = _yaml.dump(parsed_rule, sort_keys=False)
    prompt = f"""Technique: {gap['technique_id']} - {gap['name']}

Draft Sigma rule to validate:
{rule_yaml}

Example of the log schema in use:
{gap['matching_logs'][0]}

Generate the test log events now, as a single JSON object with the two keys described."""

    response = ollama.chat(
        model=MODEL_NAME,
        messages=[
            {"role": "system", "content": SELF_TEST_SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
    )
    raw = response["message"]["content"]
    try:
        data = json.loads(_extract_json_block(raw))
        return {
            "malicious_variants": data.get("malicious_variants", []),
            "benign_lookalikes": data.get("benign_lookalikes", []),
            "raw_response": raw,
            "error": None,
        }
    except (json.JSONDecodeError, AttributeError) as e:
        return {"malicious_variants": [], "benign_lookalikes": [], "raw_response": raw, "error": str(e)}
