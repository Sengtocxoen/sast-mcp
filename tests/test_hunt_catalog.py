"""
Catalog tests. The committed TSVs are the ground truth: 297 repos, 62 parsers.

docs/hunt-pipeline/catalog/ holds the exact population the campaign gated, so
the loader is checked against it rather than against a hand-written fixture.
The two survivors (dmc_unrar, tinyply) and the notable rejects (stb, tiffloader)
must all be present and correctly tagged, because every gating run starts here.
"""
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "server"))

from hunt import catalog  # noqa: E402

CATALOG_DIR = os.path.join(ROOT, "docs", "hunt-pipeline", "catalog")
ALL_297 = os.path.join(CATALOG_DIR, "catalog_all_297.tsv")
PARSERS_62 = os.path.join(CATALOG_DIR, "catalog_parsers_62.tsv")

README_FIXTURE = """
# Single-file libraries

## Images and image processing

library | description | license
--- | --- | ---
[stb_image](https://github.com/nothings/stb) | image loader | public domain
[tiffloader](https://github.com/MalcolmMcLean/tiffloader) | TIFF reader | MIT

## Compression and archives

library | description | license
--- | --- | ---
[dmc_unrar](https://github.com/DrMcCoy/dmc_unrar) | RAR decoder | GPL
[lightmapper](https://github.com/ands/lightmapper#lightmapper) | lightmapper | MIT

## Meshes

[tinyply](https://github.com/ddiakopoulos/tinyply.git) | PLY loader | BSD

## Graphics (2D)

[cgl](https://github.com/Jaysmito101/cgl) | game library | MIT
[selfhosted](https://example.com/lib.h) | not on github | MIT
"""


# -- repo slug normalisation ----------------------------------------------

@pytest.mark.parametrize("raw,expected", [
    ("https://github.com/DrMcCoy/dmc_unrar", "DrMcCoy/dmc_unrar"),
    ("https://github.com/ddiakopoulos/tinyply.git", "ddiakopoulos/tinyply"),
    ("https://github.com/ands/lightmapper#lightmapper", "ands/lightmapper"),
    ("http://www.github.com/nothings/stb/tree/master/docs", "nothings/stb"),
    ("ands/seamoptimizer", "ands/seamoptimizer"),
    ("ands/lightmapper#lightmapper", "ands/lightmapper"),
    ("https://example.com/lib.h", None),
    ("", None),
    ("notaslug", None),
])
def test_normalize_repo(raw, expected):
    assert catalog.normalize_repo(raw) == expected


# -- README parsing -------------------------------------------------------

def test_parse_readme_extracts_repos_and_tags():
    entries = catalog.parse_readme(README_FIXTURE)
    by_repo = {e["repo"]: e for e in entries}
    assert "nothings/stb" in by_repo
    assert by_repo["nothings/stb"]["tag"] == "image"
    assert by_repo["DrMcCoy/dmc_unrar"]["tag"] == "pack"
    assert by_repo["ddiakopoulos/tinyply"]["tag"] == "mesh"
    assert by_repo["Jaysmito101/cgl"]["tag"] == "2d"


def test_parse_readme_skips_non_github_rows():
    entries = catalog.parse_readme(README_FIXTURE)
    assert all("example.com" not in e["repo"] for e in entries)


def test_parse_readme_deduplicates_repos():
    doubled = README_FIXTURE + "\n## Audio\n[stb_vorbis](https://github.com/nothings/stb)\n"
    entries = catalog.parse_readme(doubled)
    stb = [e for e in entries if e["repo"] == "nothings/stb"]
    assert len(stb) == 1, "a repo in several categories must be gated once"
    assert "audio" in stb[0]["also_tagged"]


def test_parse_readme_handles_empty_input():
    assert catalog.parse_readme("") == []


# -- tag filtering --------------------------------------------------------

def test_filter_tags_keeps_only_parser_categories():
    entries = catalog.parse_readme(README_FIXTURE)
    parsers = catalog.filter_tags(entries)
    repos = {e["repo"] for e in parsers}
    assert "nothings/stb" in repos          # image
    assert "DrMcCoy/dmc_unrar" in repos     # pack
    assert "Jaysmito101/cgl" not in repos   # 2d is not gated by default


def test_filter_tags_can_reach_the_known_gap():
    """Section 7: the 2d, json and net tags were never gated but hold parsers."""
    entries = catalog.parse_readme(README_FIXTURE)
    widened = catalog.filter_tags(entries, catalog.PARSER_TAGS | catalog.UNGATED_PARSER_TAGS)
    assert "Jaysmito101/cgl" in {e["repo"] for e in widened}


# -- the committed catalogs ----------------------------------------------

@pytest.mark.skipif(not os.path.isfile(PARSERS_62), reason="catalog TSV not present")
def test_load_the_62_parser_catalog():
    entries = catalog.load_tsv(PARSERS_62)
    assert len(entries) == 62
    repos = {e["repo"] for e in entries}
    # The two survivors that both yielded findings.
    assert "DrMcCoy/dmc_unrar" in repos
    assert "ddiakopoulos/tinyply" in repos
    # Notable rejects, which must be in the population to be rejected.
    assert "nothings/stb" in repos
    assert "MalcolmMcLean/tiffloader" in repos


@pytest.mark.skipif(not os.path.isfile(ALL_297), reason="catalog TSV not present")
def test_load_the_full_297_catalog():
    entries = catalog.load_tsv(ALL_297)
    assert len(entries) == 297
    assert all("/" in e["repo"] for e in entries)


@pytest.mark.skipif(not os.path.isfile(ALL_297), reason="catalog TSV not present")
def test_parser_filter_over_the_full_catalog_is_in_the_right_range():
    """Filtering 297 by parser tag produced 62 in the campaign."""
    entries = catalog.load_tsv(ALL_297)
    parsers = catalog.filter_tags(entries)
    assert 55 <= len(parsers) <= 70, f"expected ~62 parser repos, got {len(parsers)}"


def test_load_tsv_on_a_missing_file_raises():
    with pytest.raises(FileNotFoundError):
        catalog.load_tsv(os.path.join(CATALOG_DIR, "nope.tsv"))


def test_repos_of_extracts_slugs():
    entries = catalog.parse_readme(README_FIXTURE)
    assert all("/" in r for r in catalog.repos_of(entries))
