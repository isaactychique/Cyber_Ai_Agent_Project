import json
import re
from pathlib import Path

DOCUMENT_ROOT = (
    Path(__file__).resolve().parents[3]
    / "data"
    / "documents"

).resolve()


def read_document(filename: str) -> str : 
    """
    Read a document located inside the approved directory  
    """
    if not filename or Path(filename).name != filename : 
        raise ValueError("Invalid filename")

    path = (DOCUMENT_ROOT / filename).resolve()

    if path.parent != DOCUMENT_ROOT : 
        raise PermissionError("Access outside document directory")

    if not path.is_file(): 
        raise FileNotFoundError(filename)
    
    if path.stat().st_size > 100_000 : 
        raise ValueError("Document too large")

    return path.read_text(encoding ="utf-8")


def search_documents(query: str) -> str:
    """Search approved top-level text documents and return bounded excerpts as JSON."""
    if not isinstance(query, str) or not query.strip():
        raise ValueError("Search query is required")
    if len(query) > 200:
        raise ValueError("Search query too long")

    terms = {term.casefold() for term in re.findall(r"[\w-]+", query) if len(term) > 1}
    if not terms:
        raise ValueError("Search query must contain a searchable term")

    matches = []
    for candidate in DOCUMENT_ROOT.glob("*.txt"):
        if candidate.is_symlink():
            continue

        path = candidate.resolve()
        if path.parent != DOCUMENT_ROOT or not path.is_file():
            continue
        if path.stat().st_size > 100_000:
            continue

        content = path.read_text(encoding="utf-8")
        matching_lines = []
        score = 0
        for line_number, line in enumerate(content.splitlines(), start=1):
            normalized_line = line.casefold()
            line_score = sum(normalized_line.count(term) for term in terms)
            if line_score:
                score += line_score
                matching_lines.append({
                    "line": line_number,
                    "text": line[:500],
                })

        if score:
            matches.append({
                "filename": path.name,
                "score": score,
                "excerpts": matching_lines[:3],
            })

    matches.sort(key=lambda item: (-item["score"], item["filename"]))
    return json.dumps(matches[:5], ensure_ascii=False)
