"""The docs stay lean, and no link in them points to a file that does not exist."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs"
ALLOWED = {
    "AGENTS.md",
    "ARCHITECTURE.md",
    "DATA-SOURCES.md",
    "ISSUES.md",
    "PERFORMANCE.md",
    "PRD.md",
    "RESPONSIBLE-USE.md",
    "SCAN.md",
    "SYMBOLS.md",
}
LINK = re.compile(r"\]\(([^)\s]+)\)")


def test_docs_folder_holds_only_the_agreed_pages() -> None:
    assert {p.name for p in DOCS.iterdir()} == ALLOWED


def test_claude_file_is_short_and_imports_the_shared_instructions() -> None:
    memory = (ROOT / "CLAUDE.md").read_text(encoding="utf-8").splitlines()
    assert len(memory) <= 150  # an agent reads it all at the start of each session
    assert "@docs/AGENTS.md" in memory
    assert len((DOCS / "AGENTS.md").read_text(encoding="utf-8").splitlines()) <= 200


def test_no_markdown_link_points_to_a_missing_file() -> None:
    pages = [*DOCS.glob("*.md"), *ROOT.glob("*.md"), ROOT / "notebooks" / "README.md"]
    missing = []
    for page in pages:
        text = page.read_text(encoding="utf-8")
        for target in LINK.findall(text):
            if target.startswith(("http://", "https://", "mailto:", "#")):
                continue
            path = target.split("#", 1)[0]
            if path and not (page.parent / path).exists():
                missing.append(f"{page.relative_to(ROOT)} -> {target}")
    assert not missing, "\n".join(missing)


def test_no_doc_has_a_secret_or_a_machine_path() -> None:
    for page in [*DOCS.glob("*.md"), ROOT / "CLAUDE.md"]:
        text = page.read_text(encoding="utf-8")
        assert "sk-or-v1" not in text, page
        assert "/Users/" not in text, page
