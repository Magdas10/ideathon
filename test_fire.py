
def _field_matches(value: str, condition) -> bool:
    if isinstance(condition, list):
        return any(_field_matches(value, c) for c in condition)
    return str(condition).lower() in str(value).lower()


def _selection_matches(log: dict, selection: dict) -> bool:
    for key, expected in selection.items():
        if "|contains" in key:
            field = key.split("|")[0]
            if not _field_matches(log.get(field, ""), expected):
                return False
        elif "|endswith" in key:
            field = key.split("|")[0]
            actual = str(log.get(field, "")).lower()
            values = expected if isinstance(expected, list) else [expected]
            if not any(actual.endswith(str(v).lower()) for v in values):
                return False
        else:
            if log.get(key) != expected:
                return False
    return True


def test_fire(parsed_rule: dict, logs: list[dict]) -> list[dict]:
    """Returns the subset of logs that the rule's selection would match."""
    detection = parsed_rule.get("detection", {})
    selection = detection.get("selection", {})
    if not selection:
        return []
    return [log for log in logs if _selection_matches(log, selection)]
