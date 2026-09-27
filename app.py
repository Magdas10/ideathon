import yaml
from pathlib import Path

import streamlit as st

import gap_analysis
import policy_store
import test_fire
import corrections_store
import database
from llm_generator import generate_rule_suggestion, refine_rule_suggestion, generate_self_test_logs

APPROVED_DIR = Path(__file__).parent / "approved_rules"
APPROVED_DIR.mkdir(exist_ok=True)
database.init_db()

st.set_page_config(page_title="AI EDR Assistant", layout="wide")

st.title("🛡️ AI EDR Assistant — Prototype")
st.caption(
    "Runs entirely on this machine via a local LLM (Ollama). "
    "No log data or rules ever leave this device. "
    "Every suggested rule requires human approval before it is written to disk."
)

st.header("1. Current EDR rule coverage")

col1, col2 = st.columns(2)
with col1:
    st.subheader("Existing rules")
    for rule in gap_analysis.load_existing_rules():
        with st.expander(rule["title"]):
            st.code(yaml.dump(rule, sort_keys=False), language="yaml")

with col2:
    st.subheader("Techniques already covered")
    for t in gap_analysis.covered_techniques():
        st.success(f"{t['technique_id']} — {t['name']}")

st.subheader("Security policies")
st.caption(
    "Organization policies define what must be detected. The assistant uses these "
    "when drafting rules and flags gaps that leave a policy requirement unmet."
)
for policy in policy_store.load_policies():
    techniques = ", ".join(policy.get("techniques", []))
    with st.expander(f"{policy['id']} — {policy['title']} ({techniques})"):
        st.markdown(policy["description"])
        for req in policy.get("requirements", []):
            st.markdown(f"- {req}")

st.header("2. Gap analysis (deterministic, no LLM)")
st.caption(
    "This step scans the sample logs against a MITRE ATT&CK technique map and "
    "flags techniques with matching activity but no existing rule. This logic "
    "is plain Python so the reasoning is fully auditable."
)

if "gaps" not in st.session_state:
    st.session_state.gaps = None

if st.button("Run gap analysis"):
    st.session_state.gaps = gap_analysis.analyze()

if st.session_state.gaps is not None:
    if not st.session_state.gaps:
        st.info("No gaps found.")
    for gap in st.session_state.gaps:
        st.warning(
            f"**Gap: {gap['technique_id']} — {gap['name']}** "
            f"({len(gap['matching_logs'])} matching log events, no rule covers this)"
        )
        for policy in gap.get("policies", []):
            st.error(
                f"📋 **Policy gap:** {policy['id']} — {policy['title']} requires "
                f"detection for {gap['technique_id']}, but no rule exists yet."
            )
        with st.expander("View matching log events"):
            st.json(gap["matching_logs"])

st.header("3. AI-suggested rules (human approval required)")

if st.session_state.gaps:
    style_examples = yaml.dump_all(gap_analysis.load_existing_rules(), sort_keys=False)
    logs = gap_analysis.load_logs()

    for gap in st.session_state.gaps:
        key = gap["technique_id"]
        gap_description = f"{gap['technique_id']} - {gap['name']}"
        st.subheader(f"{gap['technique_id']} — {gap['name']}")

        suggestion_key = f"suggestion_{key}"
        selftest_key = f"selftest_{key}"
        used_corrections_key = f"used_corrections_{key}"
        if suggestion_key not in st.session_state:
            st.session_state[suggestion_key] = None
        if selftest_key not in st.session_state:
            st.session_state[selftest_key] = None
        if used_corrections_key not in st.session_state:
            st.session_state[used_corrections_key] = []

        if gap.get("policies"):
            with st.expander(f"📋 {len(gap['policies'])} policy/policies will guide this draft"):
                for policy in gap["policies"]:
                    st.markdown(f"**{policy['id']} — {policy['title']}**")
                    st.caption(policy["description"])

        if st.button(f"Generate suggestion for {key}", key=f"gen_{key}"):
            past = corrections_store.find_similar_corrections(
                gap_description, technique_id=gap["technique_id"]
            )
            st.session_state[used_corrections_key] = past

            with st.spinner("Asking local model (Ollama) to draft a rule..."):
                suggestion = generate_rule_suggestion(gap, style_examples, past_corrections=past)
                st.session_state[suggestion_key] = suggestion

            if suggestion["parsed_rule"] is not None:
                with st.spinner("Running a one-time self-check (generalization + false-positive test)..."):
                    self_test = generate_self_test_logs(gap, suggestion["parsed_rule"])
                    st.session_state[selftest_key] = self_test

        suggestion = st.session_state[suggestion_key]
        if suggestion:
            if st.session_state[used_corrections_key]:
                with st.expander(
                    f"ℹ️ Used {len(st.session_state[used_corrections_key])} past analyst "
                    f"correction(s) as guidance for this draft"
                ):
                    for c in st.session_state[used_corrections_key]:
                        st.markdown(f"**From:** {c['gap_description']} · *{c['timestamp']}*")
                        st.markdown(f"**Analyst's note:** {c.get('note') or '(none)'}")
                        st.code(c["corrected_yaml"], language="yaml")

            if suggestion["parsed_rule"] is None:
                st.error(
                    f"Model output could not be parsed as valid YAML after retry: "
                    f"{suggestion['parse_error']}"
                )
                with st.expander("Raw model response"):
                    st.text(suggestion["raw_response"])
                continue

            edited_yaml = st.text_area(
                "Candidate Sigma rule (editable before approval)",
                value=suggestion["rule_yaml_text"],
                height=260,
                key=f"yaml_{key}",
            )

            st.markdown(f"**Rationale:** {suggestion['rationale']}")
            st.markdown(f"**Estimated false-positive risk:** {suggestion['fp_risk']}")

            self_test = st.session_state[selftest_key]
            if self_test:
                try:
                    current_parsed_for_test = yaml.safe_load(edited_yaml)
                except yaml.YAMLError:
                    current_parsed_for_test = None

                st.markdown("**🔍 Self-test (generated automatically, one pass, before you review):**")
                if self_test["error"]:
                    st.caption(f"Self-test generation didn't parse cleanly ({self_test['error']}); skipping.")
                elif current_parsed_for_test:
                    variants = self_test["malicious_variants"]
                    lookalikes = self_test["benign_lookalikes"]
                    variant_hits = test_fire.test_fire(current_parsed_for_test, variants) if variants else []
                    lookalike_hits = test_fire.test_fire(current_parsed_for_test, lookalikes) if lookalikes else []

                    sc1, sc2 = st.columns(2)
                    with sc1:
                        st.metric(
                            "Generalization check",
                            f"{len(variant_hits)}/{len(variants)} variants caught",
                        )
                        with st.expander("View synthetic attack variants used"):
                            st.json(variants)
                    with sc2:
                        fp_count = len(lookalike_hits)
                        st.metric(
                            "False-positive check",
                            f"{fp_count}/{len(lookalikes)} benign look-alikes incorrectly flagged",
                            delta="lower is better",
                            delta_color="inverse",
                        )
                        with st.expander("View synthetic benign look-alikes used"):
                            st.json(lookalikes)

            # Test-fire against real sample logs
            try:
                current_parsed = yaml.safe_load(edited_yaml)
                matches = test_fire.test_fire(current_parsed, logs)
                st.info(
                    f"Test-fire against {len(logs)} real sample log events: "
                    f"**{len(matches)} match(es)**"
                )
                if matches:
                    with st.expander("View test-fire matches"):
                        st.json(matches)
            except yaml.YAMLError as e:
                st.error(f"Edited YAML is invalid: {e}")
                current_parsed = None

            st.markdown("**✏️ Not quite right? Tell the AI what to improve instead of editing by hand:**")
            feedback = st.text_area(
                "e.g. \"narrow this to exclude svchost.exe\" or \"this is too broad, only match when run as SYSTEM\"",
                key=f"feedback_{key}",
                height=80,
            )
            if st.button(f"🔁 Refine with feedback", key=f"refine_{key}"):
                if feedback.strip():
                    with st.spinner("Applying your feedback (one pass)..."):
                        refined = refine_rule_suggestion(gap, edited_yaml, feedback, style_examples)
                        st.session_state[suggestion_key] = refined
                        # feedback text carried forward for correction-memory note
                        st.session_state[f"last_feedback_{key}"] = feedback
                    st.rerun()
                else:
                    st.caption("Enter feedback above first.")

            approve_col, reject_col = st.columns(2)
            with approve_col:
                if st.button("✅ Approve & write rule", key=f"approve_{key}"):
                    if current_parsed is None:
                        st.error("Cannot approve invalid YAML.")
                    else:
                        filename = f"{gap['technique_id']}.yml"
                        (APPROVED_DIR / filename).write_text(edited_yaml)

                        database.log_audit_event(
                            action="approved",
                            technique_id=gap["technique_id"],
                            rule_title=current_parsed.get("title"),
                            file_path=str(APPROVED_DIR / filename),
                        )

                        original_first_draft = suggestion.get("rule_yaml_text", "")
                        note = st.session_state.get(f"last_feedback_{key}", "")
                        learned = corrections_store.add_correction(
                            gap_description=gap_description,
                            original_yaml=original_first_draft,
                            corrected_yaml=edited_yaml,
                            note=note,
                            technique_id=gap["technique_id"],
                        )

                        st.success(f"Approved and written to {APPROVED_DIR / filename}")
                        if gap.get("policies"):
                            policy_ids = ", ".join(p["id"] for p in gap["policies"])
                            st.info(
                                f"📋 Policy compliance: approved rule addresses "
                                f"{policy_ids} for {gap['technique_id']}."
                            )
                        if learned:
                            st.info(
                                "📚 Your changes were saved to correction memory "
                                f"({database.DB_PATH.name})."
                            )
                            if not corrections_store.resolve_embed_model():
                                st.caption(
                                    "Same-technique recall works now. For cross-technique similarity, "
                                    "run `ollama pull nomic-embed-text`."
                                )

            with reject_col:
                if st.button("❌ Reject", key=f"reject_{key}"):
                    database.log_audit_event(
                        action="rejected",
                        technique_id=gap["technique_id"],
                    )
                    st.session_state[suggestion_key] = None
                    st.session_state[selftest_key] = None
                    st.info("Rejected. Nothing written to disk.")
else:
    st.caption("Run gap analysis above first.")

st.header("4. Correction memory")
st.caption(
    "Every time an analyst's final approved rule differs from the AI's first draft, "
    "that correction is stored in the local SQLite database. Future suggestions for "
    "the same technique (or similar gaps, with an embedding model) reuse past fixes."
)
history = corrections_store.all_corrections()
if history:
    for c in history:
        with st.expander(f"{c['gap_description']} · {c['timestamp']}"):
            st.markdown(f"**Analyst's note:** {c.get('note') or '(none)'}")
            d1, d2 = st.columns(2)
            with d1:
                st.markdown("*AI's original draft:*")
                st.code(c["original_yaml"], language="yaml")
            with d2:
                st.markdown("*Analyst's corrected version:*")
                st.code(c["corrected_yaml"], language="yaml")
else:
    st.caption("No corrections recorded yet.")

st.header("5. Audit log")
audit = database.all_audit_events()
if audit:
    st.json(audit)
else:
    st.caption("No decisions recorded yet.")
