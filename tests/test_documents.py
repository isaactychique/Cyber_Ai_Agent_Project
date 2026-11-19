import json

import pytest

from sentinel.tools import documents


def test_read_document_reads_only_from_document_root(tmp_path, monkeypatch):
    monkeypatch.setattr(documents, "DOCUMENT_ROOT", tmp_path)
    (tmp_path / "architecture.txt").write_text("Approved content", encoding="utf-8")

    assert documents.read_document("architecture.txt") == "Approved content"


@pytest.mark.parametrize("filename", ["", "../outside.txt", "/etc/passwd"])
def test_read_document_rejects_invalid_paths(filename, tmp_path, monkeypatch):
    monkeypatch.setattr(documents, "DOCUMENT_ROOT", tmp_path)

    with pytest.raises(ValueError):
        documents.read_document(filename)


def test_read_document_rejects_symlink_outside_root(tmp_path, monkeypatch):
    document_root = tmp_path / "documents"
    document_root.mkdir()
    outside_file = tmp_path / "outside.txt"
    outside_file.write_text("private", encoding="utf-8")
    (document_root / "escape.txt").symlink_to(outside_file)
    monkeypatch.setattr(documents, "DOCUMENT_ROOT", document_root.resolve())

    with pytest.raises(PermissionError):
        documents.read_document("escape.txt")


def test_read_document_rejects_oversized_file(tmp_path, monkeypatch):
    monkeypatch.setattr(documents, "DOCUMENT_ROOT", tmp_path)
    (tmp_path / "large.txt").write_text("x" * 100_001, encoding="utf-8")

    with pytest.raises(ValueError, match="Document too large"):
        documents.read_document("large.txt")


def test_search_documents_returns_ranked_matching_excerpts(tmp_path, monkeypatch):
    monkeypatch.setattr(documents, "DOCUMENT_ROOT", tmp_path)
    (tmp_path / "a.txt").write_text(
        "Zero Trust checks every action.\nThe agent has scoped permissions.",
        encoding="utf-8",
    )
    (tmp_path / "b.txt").write_text("Zero Trust is a policy model.", encoding="utf-8")
    (tmp_path / "unrelated.txt").write_text("A fishing simulator.", encoding="utf-8")

    results = json.loads(documents.search_documents("Zero Trust"))

    assert [result["filename"] for result in results] == ["a.txt", "b.txt"]
    assert results[0]["score"] == 2
    assert results[0]["excerpts"][0]["text"] == "Zero Trust checks every action."


@pytest.mark.parametrize("query", ["", "   ", "!", "x" * 201])
def test_search_documents_rejects_invalid_queries(query, tmp_path, monkeypatch):
    monkeypatch.setattr(documents, "DOCUMENT_ROOT", tmp_path)

    with pytest.raises(ValueError):
        documents.search_documents(query)


def test_search_documents_skips_external_symlinks_and_oversized_files(tmp_path, monkeypatch):
    document_root = tmp_path / "documents"
    document_root.mkdir()
    outside_file = tmp_path / "outside.txt"
    outside_file.write_text("Zero Trust outside", encoding="utf-8")
    (document_root / "escape.txt").symlink_to(outside_file)
    (document_root / "large.txt").write_text("Zero Trust " * 10_000, encoding="utf-8")
    (document_root / "inside.txt").write_text("Zero Trust inside", encoding="utf-8")
    monkeypatch.setattr(documents, "DOCUMENT_ROOT", document_root.resolve())

    results = json.loads(documents.search_documents("Zero Trust"))

    assert [result["filename"] for result in results] == ["inside.txt"]
