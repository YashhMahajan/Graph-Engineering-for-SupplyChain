"""The HTML report: self-contained, and hostile lockfile text cannot add markup."""

from __future__ import annotations

from html.parser import HTMLParser

from scgraph.scan.engine import Finding, ScanResult
from scgraph.scan.render import to_html

ALLOWED_TAGS = {
    "html", "head", "meta", "title", "style", "body", "h1", "h2", "p", "div", "span",
    "a", "code", "details", "summary", "pre", "ul", "li",
}  # fmt: skip


class Tags(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.tags: list[str] = []
        self.attrs: list[tuple[str, str | None]] = []

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        self.attrs += attrs


def parsed(page: str) -> Tags:
    p = Tags()
    p.feed(page)
    return p


def finding(id_="MAL-2025-1", pkg="chalk", ver="5.6.1", path=None, fix="remove it"):
    return Finding(
        id=id_, ids=[id_], aliases=[], summary="s", package=pkg, version=ver, ecosystem="npm",
        purl=f"pkg:npm/{pkg}@{ver}", score=None, severity="malicious", malicious=True,
        withdrawn=False, kev=False, epss=None, epss_percentile=None,
        path=path or ["app", f"{pkg}@{ver}"], dev_only=False, fixed_in=None, fix=fix,
        alert=True, reason="alert", priority="P0",
    )  # fmt: skip


def result(*findings, path="package-lock.json"):
    return ScanResult(
        path=path, format="package-lock.json", ecosystem="npm", n_packages=3, n_direct=1,
        findings=list(findings), remediation=[], unpinned=[], source="osv", signals={},
        merged_duplicates=0, seconds=0.01,
    )  # fmt: skip


def test_the_page_is_self_contained_with_a_strict_csp() -> None:
    page = to_html([result(finding())])
    assert page.startswith("<!doctype html>")
    assert "default-src 'none'" in page and "style-src 'unsafe-inline'" in page
    t = parsed(page)
    assert "script" not in t.tags and "link" not in t.tags and "img" not in t.tags
    assert not [k for k, _ in t.attrs if k in ("src", "srcset")]  # nothing loads remotely


def test_an_alert_shows_its_advisory_link_path_and_fix() -> None:
    page = to_html([result(finding(path=["app", "express@4.21.2", "chalk@5.6.1"]))])
    assert "href='https://osv.dev/vulnerability/MAL-2025-1'" in page
    assert "app → express@4.21.2 → chalk@5.6.1" in page
    assert "fix: remove it" in page and "P0 MALICIOUS" in page
    assert "1 alert across 1 lockfile(s)" in page


def test_a_clean_scan_says_so() -> None:
    page = to_html([result()])
    assert "0 alerts across 1 lockfile(s)" in page and "No alert survived the gates" in page


def test_hostile_lockfile_text_cannot_add_markup_or_break_an_attribute() -> None:
    evil = "<script>alert(1)</script>\"'><img src=//evil/x.png onerror=alert(2)>"
    f = finding(id_=evil, pkg=evil, ver=evil, path=["</pre><script>x()</script>", evil], fix=evil)
    page = to_html([result(f, path=evil)])
    t = parsed(page)
    assert set(t.tags) <= ALLOWED_TAGS, set(t.tags) - ALLOWED_TAGS
    assert "<script>alert" not in page and "onerror=alert(2)>" not in page
    assert "&lt;script&gt;" in page
    hrefs = [v for k, v in t.attrs if k == "href"]
    assert len(hrefs) == 1 and hrefs[0].startswith("https://osv.dev/vulnerability/")
    assert "<" not in hrefs[0] and "'" not in hrefs[0] and '"' not in hrefs[0]  # percent-encoded
    assert not [k for k, _ in t.attrs if k.startswith("on") or k in ("src", "srcset")]
