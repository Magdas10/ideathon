import difflib

import database


def yaml_diff(before: str, after: str) -> str:
    """Unified diff between two YAML strings (empty if identical)."""
    if before.strip() == after.strip():
        return ""
    return "".join(
        difflib.unified_diff(
            before.splitlines(keepends=True),
            after.splitlines(keepends=True),
            fromfile="before",
            tofile="after",
        )
    )


def has_changes(before: str, after: str) -> bool:
    return before.strip() != after.strip()


def record_edit(
    *,
    technique_id: str,
    gap_description: str,
    before_yaml: str,
    after_yaml: str,
    source: str = "manual",
    approved: bool = False,
) -> int | None:
    """
    Persist a manual edit snapshot. Returns the new row id, or None if
    before and after are identical (nothing worth recording).
    """
    if not has_changes(before_yaml, after_yaml):
        return None

    return database.insert_rule_edit(
        technique_id=technique_id,
        gap_description=gap_description,
        source=source,
        before_yaml=before_yaml,
        after_yaml=after_yaml,
        diff_text=yaml_diff(before_yaml, after_yaml),
        approved=approved,
    )


def all_edits() -> list[dict]:
    return database.fetch_all_rule_edits()


def edits_for_technique(technique_id: str) -> list[dict]:
    return database.fetch_rule_edits_for_technique(technique_id)
