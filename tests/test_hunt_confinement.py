"""
Path-confinement and cache-integrity tests for server/hunt/.

Three defects, all in code that shipped:

* harness_source is documented as inline TEXT but _as_text sniffed any short
  string for a path and read it, with no mount-root check - unlike its sibling
  harness_path. Confirmed by reading a file outside every allowed mount root and
  getting its matching lines back in hits[*].text.
* DiskCache defaulted into tempfile.gettempdir(). /tmp is world-writable on a
  shared host, so another local user could plant the entries that Stage A's gate
  verdicts are computed from.
* find_local_checkout joined local_root with segments taken from a repo slug and
  returned whatever isdir() accepted. Traversal was blocked only incidentally,
  by normalize_repo stripping dots.
"""
import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault("USE_MULTIPROCESSING", "0")
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "server"))

from hunt import evidence, gating  # noqa: E402
from hunt.ghclient import DiskCache, _default_cache_dir  # noqa: E402

HARNESS_WITH_IO = """
int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) {
    FILE *f = fopen("/tmp/in.bin", "wb");
    fwrite(d, 1, n, f);
    return 0;
}
"""


# -- harness_source must not read files ----------------------------------

def test_a_path_in_harness_source_is_not_read(tmp_path):
    """The exact defect: a path passed as inline source got read."""
    secret = tmp_path / "secret.conf"
    secret.write_text('SECRET=abc123\nfopen("/etc/shadow", "r");\nunlink("/x");\n')
    r = evidence.check_harness_filesystem_io(str(secret))
    assert r["filesystem_io"] is False, "the file was read"
    assert r["hits"] == []


def test_inline_harness_text_still_works():
    r = evidence.check_harness_filesystem_io(HARNESS_WITH_IO)
    assert r["filesystem_io"] is True
    assert any(h["call"] == "fopen" for h in r["hits"])


def test_a_confined_caller_can_still_opt_into_path_reading(tmp_path):
    """Library/CLI callers that already validated the path keep the behaviour."""
    h = tmp_path / "harness.c"
    h.write_text(HARNESS_WITH_IO)
    assert evidence.check_harness_filesystem_io(str(h), allow_path=True)["filesystem_io"] is True


def test_assert_source_does_not_read_a_path(tmp_path):
    src = tmp_path / "code.c"
    src.write_text("void f(void) {\n    assert(x > 0);\n    memcpy(a, b, x);\n}\n")
    r = evidence.classify_assert_crash(str(src), line=2)
    # Treated as one line of text, so line 2 does not exist -> unknown, no read.
    assert r["verdict"] == "unknown"
    assert "memcpy" not in json.dumps(r)


def test_assert_source_with_allow_path_reads_as_before(tmp_path):
    src = tmp_path / "code.c"
    src.write_text("void f(void) {\n    assert(x > 0);\n    memcpy(a, b, x);\n}\n")
    r = evidence.classify_assert_crash(str(src), line=2, allow_path=True)
    assert r["verdict"] == "reportable"


def test_assess_never_turns_harness_source_into_a_file_read(tmp_path):
    secret = tmp_path / "s.conf"
    secret.write_text('fopen("/etc/shadow","r");\n')
    out = evidence.assess(log="#2\tINITED cov: 500 exec/s: 900\n", harness_source=str(secret))
    assert out["evidence"]["harness"]["filesystem_io"] is False


# -- cache directory integrity -------------------------------------------

def test_default_cache_dir_is_not_world_writable_tmp():
    d = _default_cache_dir()
    import tempfile as _t
    shared = os.path.realpath(_t.gettempdir())
    if os.path.realpath(d).startswith(shared):
        # Only acceptable when there is no home dir, and then it must be
        # qualified by uid so it cannot be pre-created by another user.
        assert os.path.basename(d) != "sast-mcp-hunt-cache"
        assert "sast-mcp-hunt-cache-" in os.path.basename(d)
    else:
        assert "sast-mcp" in d


def test_cache_dir_is_created_private(tmp_path):
    d = tmp_path / "cache"
    cache = DiskCache(str(d))
    assert cache.enabled is True
    if hasattr(os, "geteuid"):
        assert not (os.stat(str(d)).st_mode & 0o022), "group/other writable"


def test_cache_refuses_a_symlinked_directory(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    try:
        os.symlink(str(real), str(link), target_is_directory=True)
    except (OSError, NotImplementedError, AttributeError):
        pytest.skip("symlinks not available")
    cache = DiskCache(str(link))
    assert cache.enabled is False
    assert cache.get("https://api.github.com/x") is None  # must not raise


def test_a_disabled_cache_degrades_quietly(tmp_path):
    blocker = tmp_path / "afile"
    blocker.write_text("x")
    cache = DiskCache(str(blocker / "sub"))
    assert cache.enabled is False
    cache.put("https://api.github.com/x", 200, "{}", {})  # must not raise
    assert cache.get("https://api.github.com/x") is None


# -- checkout confinement -------------------------------------------------

def test_checkout_lookup_finds_a_legitimate_repo(tmp_path):
    (tmp_path / "DrMcCoy" / "dmc_unrar").mkdir(parents=True)
    got = gating.find_local_checkout("DrMcCoy/dmc_unrar", str(tmp_path))
    assert got and os.path.realpath(got) == os.path.realpath(
        str(tmp_path / "DrMcCoy" / "dmc_unrar"))


@pytest.mark.parametrize("slug", [
    "../../etc/passwd", "../..", "./x", "o/..", "../o/r", ".git/config",
    "/absolute/path", "o/r/../../..",
])
def test_traversal_slugs_are_refused(tmp_path, slug):
    assert gating.find_local_checkout(slug, str(tmp_path)) is None


def test_a_symlink_out_of_the_root_is_refused(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    root = tmp_path / "root"
    root.mkdir()
    try:
        os.symlink(str(outside), str(root / "escape"), target_is_directory=True)
    except (OSError, NotImplementedError, AttributeError):
        pytest.skip("symlinks not available")
    assert gating.find_local_checkout("o/escape", str(root)) is None


def test_missing_root_is_handled():
    assert gating.find_local_checkout("o/r", None) is None
    assert gating.find_local_checkout("o/r", "/nonexistent/xyz") is None
