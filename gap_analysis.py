import json
import yaml
from pathlib import Path

DATA_DIR = Path(__file__).parent / "sample_data"


def load_existing_rules():
    with open(DATA_DIR / "existing_rules.yaml") as f:
        return list(yaml.safe_load_all(f))


def load_logs():
    with open(DATA_DIR / "sample_logs.json") as f:
        return json.load(f)


def load_technique_map():
    with open(DATA_DIR / "technique_map.json") as f:
        return json.load(f)


def _log_matches(log: dict, match_spec: dict) -> bool:
    """Very small matcher supporting equals / endswith / contains checks."""
    for key, expected in match_spec.items():
        if key.endswith("_endswith"):
            field = key[: -len("_endswith")]
            actual = str(log.get(field, ""))
            if not actual.lower().endswith(str(expected).lower()):
                return False
        elif key.endswith("_contains"):
            field = key[: -len("_contains")]
            actual = str(log.get(field, ""))
            if str(expected).lower() not in actual.lower():
                return False
        else:
            if log.get(key) != expected:
                return False
    return True


def _covered_tags(rules: list[dict]) -> set[str]:
    tags = set()
    for rule in rules:
        for tag in rule.get("tags", []):
            tags.add(tag)
    return tags


def analyze() -> list[dict]:
    """
    Returns a list of gap dicts:
      {technique_id, name, tag, matching_logs: [...]}
    for every technique that appears in the logs but has no existing
    rule tagged with it.
    """
    rules = load_existing_rules()
    logs = load_logs()
    technique_map = load_technique_map()
    covered = _covered_tags(rules)

    gaps = []
    for tech_id, info in technique_map.items():
        if info["tag"] in covered:
            continue  # already have a rule for this technique

        matching_logs = [log for log in logs if _log_matches(log, info["match"])]
        if matching_logs:
            gaps.append(
                {
                    "technique_id": tech_id,
                    "name": info["name"],
                    "tag": info["tag"],
                    "matching_logs": matching_logs,
                }
            )
    return gaps


def covered_techniques() -> list[dict]:
    """For display: which techniques already have a rule."""
    rules = load_existing_rules()
    technique_map = load_technique_map()
    covered = _covered_tags(rules)
    return [
        {"technique_id": tid, "name": info["name"], "tag": info["tag"]}
        for tid, info in technique_map.items()
        if info["tag"] in covered
    ]


if __name__ == "__main__":
    for gap in analyze():
        print(f"GAP: {gap['technique_id']} - {gap['name']} "
              f"({len(gap['matching_logs'])} matching log events, no rule covers this)")
