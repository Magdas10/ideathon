"""Load security policies and map them to MITRE techniques for the prototype."""

import json
from pathlib import Path

DATA_DIR = Path(__file__).parent / "sample_data"
POLICIES_PATH = DATA_DIR / "security_policies.json"


def load_policies() -> list[dict]:
    with open(POLICIES_PATH) as f:
        return json.load(f)


def policies_for_technique(technique_id: str) -> list[dict]:
    """Return active policies that require detection for this technique."""
    return [
        policy
        for policy in load_policies()
        if policy.get("status") == "active" and technique_id in policy.get("techniques", [])
    ]


def format_policies_for_prompt(policies: list[dict]) -> str:
    if not policies:
        return ""
    blocks = []
    for policy in policies:
        reqs = "\n".join(f"  - {req}" for req in policy.get("requirements", []))
        blocks.append(
            f"Policy {policy['id']} — {policy['title']}\n"
            f"  {policy['description']}\n"
            f"  Requirements:\n{reqs}"
        )
    return (
        "\n\nORGANIZATION SECURITY POLICIES that apply to this gap (you MUST follow these):\n"
        + "\n\n".join(blocks)
    )
