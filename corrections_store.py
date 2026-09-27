import math

import ollama

import database

PREFERRED_EMBED_MODELS = (
    "nomic-embed-text",
    "nomic-embed-text:latest",
    "mxbai-embed-large",
    "mxbai-embed-large:latest",
    "all-minilm",
    "all-minilm:latest",
)


def _technique_id_from_description(gap_description: str) -> str:
    return gap_description.split(" - ", 1)[0].strip()


def _available_ollama_models() -> set[str]:
    try:
        listed = ollama.list()
    except Exception:
        return set()

    models = listed.get("models") if isinstance(listed, dict) else getattr(listed, "models", [])
    names: set[str] = set()
    for model in models or []:
        name = model.get("name") if isinstance(model, dict) else getattr(model, "model", None)
        if name:
            names.add(name)
    return names


def resolve_embed_model() -> str | None:
    """Pick an installed Ollama embedding model (not the Python client package)."""
    installed = _available_ollama_models()
    if not installed:
        return None

    for candidate in PREFERRED_EMBED_MODELS:
        if candidate in installed:
            return candidate

    for name in sorted(installed):
        if "embed" in name.lower():
            return name
    return None


def _embed(text: str) -> list[float] | None:
    model = resolve_embed_model()
    if not model:
        return None
    resp = ollama.embeddings(model=model, prompt=text)
    return resp["embedding"]


def _cosine(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(y * y for y in b))
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a * norm_b)


def add_correction(
    gap_description: str,
    original_yaml: str,
    corrected_yaml: str,
    note: str = "",
    technique_id: str | None = None,
) -> bool:
    """
    Records a correction. Returns False (and stores nothing) if the human
    approved the AI's draft unchanged - there's nothing to learn from that.
    """
    if original_yaml.strip() == corrected_yaml.strip():
        return False

    tid = technique_id or _technique_id_from_description(gap_description)
    embedding = _embed(gap_description)
    database.insert_correction(
        technique_id=tid,
        gap_description=gap_description,
        original_yaml=original_yaml,
        corrected_yaml=corrected_yaml,
        note=note,
        embedding=embedding,
    )
    return True


def find_similar_corrections(
    gap_description: str,
    technique_id: str | None = None,
    top_k: int = 2,
    min_similarity: float = 0.55,
) -> list[dict]:
    """
    Finds past corrections relevant to a new gap.

    Always checks exact technique id first (no embedding model required).
    If an embedding model is available, also pulls semantically similar
    corrections from other techniques.
    """
    tid = technique_id or _technique_id_from_description(gap_description)
    results: list[dict] = []
    seen_ids: set[int] = set()

    for entry in database.fetch_corrections_for_technique(tid):
        results.append(entry)
        seen_ids.add(entry["id"])

    query_vec = _embed(gap_description)
    if query_vec:
        scored: list[tuple[float, dict]] = []
        for entry in database.fetch_corrections_with_embeddings():
            if entry["id"] in seen_ids:
                continue
            sim = _cosine(query_vec, entry["embedding"])
            if sim >= min_similarity:
                scored.append((sim, entry))
        scored.sort(key=lambda item: (item[0], item[1]["timestamp"]), reverse=True)
        for _, entry in scored:
            results.append(entry)
            seen_ids.add(entry["id"])

    return results[:top_k]


def all_corrections() -> list[dict]:
    return database.fetch_all_corrections()
