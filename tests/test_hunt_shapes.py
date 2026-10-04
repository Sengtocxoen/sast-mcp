"""
Shape-scanner tests, including the measured negative results.

Section 2 of docs/hunt-pipeline/ARCHITECTURE.md is a measured argument that this
whole stage is nearly worthless: 60 hits across two scanners produced exactly
one real bug, and that one was already known. scan3 produced 53 hits and zero
real findings. The verdict was "keep scan2 as a cheap sweep over a NEW codebase;
retire scan3".

So these tests check two different things:

1. The scanners still fire on the shapes they were derived from - scan2 must
   find the assetsys shape, because that known-positive is the only reason to
   believe anything it says (section 5: validate the tool before believing a
   negative).
2. The measured verdicts are enforced in code - scan3 does not run unless the
   caller explicitly asks for a retired scanner, and a zero-hit result is not
   reported as clean unless the self-test proved the scanner works.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "server"))

from hunt import shapes  # noqa: E402

# The assetsys shape: a parsed size narrowed to int, then used as a signed bound.
# This is the hit that proved scan2 works (assetsys.h:6204).
ASSETSYS_SHAPE = """
static int read_entry(assetsys_t* sys, FILE* f) {
    int size = (int) header_size_field;
    unsigned char* buf = sys->buf;
    if (size > sys->capacity) {
        return 0;
    }
    memcpy(buf, sys->src, size);
    return 1;
}
"""

# The paldither shape: malloc(X), then a copy to an offset destination with
# length X - so the tail of the copy lands past the end.
PALDITHER_SHAPE = """
void build(int count) {
    unsigned char* pixels = (unsigned char*) malloc(size);
    memcpy(pixels + offset, src, size);
}
"""

# The scan3 shape: an allocation size from a multiplication of int-width operands.
MUL_ALLOC_SHAPE = """
void load(void) {
    int width = read_int();
    int height = read_int();
    unsigned char* data = malloc(width * height * 4);
}
"""

# The m3d.h / stb_image false positive: the same multiplication, but the
# function exists precisely to prevent the overflow and is guarded.
GUARDED_MUL_ALLOC = """
static void* _m3dstbi__malloc_mad3(int a, int b, int c, int add) {
    if (!_m3dstbi__mad3sizes_valid(a, b, c, add)) return NULL;
    return _m3dstbi__malloc(a * b * c + add);
}
"""


def write_tree(tmp_path, files):
    for name, body in files.items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body)
    return str(tmp_path)


# -- self-tests: the scanners must find their own known-positives ---------

def test_scan2_selftest_passes():
    """The only reason to trust a scan2 negative."""
    r = shapes.selftest("scan2")
    assert r["passed"] is True
    assert r["hits"] >= 1


def test_every_shape_has_a_mechanical_selftest():
    for name in shapes.SHAPES:
        r = shapes.selftest(name)
        assert r["passed"] is True, f"{name} cannot find its own known-positive"


def test_scan2_is_the_only_field_validated_scanner():
    """scan1 never produced a finding; scan3 produced 53 hits and no bugs."""
    assert shapes.SHAPES["scan2"]["field_validated"] is True
    assert shapes.SHAPES["scan1"]["field_validated"] is False
    assert shapes.SHAPES["scan3"]["field_validated"] is False


# -- scan2 ----------------------------------------------------------------

def test_scan2_finds_the_assetsys_shape(tmp_path):
    root = write_tree(tmp_path, {"assetsys.h": ASSETSYS_SHAPE})
    out = shapes.scan(root, shapes_wanted=["scan2"])
    assert out["hit_count"] == 1
    hit = out["hits"][0]
    assert hit["shape"] == "scan2"
    assert hit["line"] == 3
    assert "capacity" in hit["bound"]


def test_scan2_ignores_unsigned_casts(tmp_path):
    root = write_tree(tmp_path, {"ok.c": """
    size_t size = (size_t) header_size_field;
    if (size > cap) return 0;
    """})
    out = shapes.scan(root, shapes_wanted=["scan2"])
    assert out["hit_count"] == 0


# -- scan1 ----------------------------------------------------------------

def test_scan1_finds_the_paldither_offset_copy(tmp_path):
    root = write_tree(tmp_path, {"paldither.h": PALDITHER_SHAPE})
    out = shapes.scan(root, shapes_wanted=["scan1"])
    assert out["hit_count"] == 1
    assert out["hits"][0]["shape"] == "scan1"


def test_scan1_result_is_labelled_unvalidated(tmp_path):
    root = write_tree(tmp_path, {"paldither.h": PALDITHER_SHAPE})
    out = shapes.scan(root, shapes_wanted=["scan1"])
    assert out["shapes_run"]["scan1"]["field_validated"] is False
    assert "unvalidated" in out["shapes_run"]["scan1"]["caution"].lower()


# -- scan3: retired ------------------------------------------------------

def test_scan3_is_refused_by_default(tmp_path):
    root = write_tree(tmp_path, {"load.c": MUL_ALLOC_SHAPE})
    out = shapes.scan(root, shapes_wanted=["scan3"])
    assert out["hit_count"] == 0
    assert "scan3" in out["refused"]
    assert "53" in out["refused"]["scan3"]


def test_scan3_runs_when_explicitly_allowed(tmp_path):
    root = write_tree(tmp_path, {"load.c": MUL_ALLOC_SHAPE})
    out = shapes.scan(root, shapes_wanted=["scan3"], allow_retired=True)
    assert out["hit_count"] == 1
    assert out["hits"][0]["shape"] == "scan3"
    assert "0 of 53" in out["shapes_run"]["scan3"]["caution"]


def test_guarded_allocation_is_marked_a_likely_false_positive(tmp_path):
    """m3d.h's malloc_mad3 exists to PREVENT this and is guarded one line up.

    The document's own explanation for scan3's <2% precision is that the scanner
    cannot see the guard three lines up. It can see this one.
    """
    root = write_tree(tmp_path, {"m3d.h": GUARDED_MUL_ALLOC})
    out = shapes.scan(root, shapes_wanted=["scan3"], allow_retired=True)
    assert out["hit_count"] == 1
    hit = out["hits"][0]
    assert hit["likely_false_positive"] is True
    assert "guard" in " ".join(hit["fp_reasons"]).lower()


# -- scan mechanics ------------------------------------------------------

def test_default_shape_set_is_scan2_only(tmp_path):
    root = write_tree(tmp_path, {"a.h": ASSETSYS_SHAPE, "b.c": MUL_ALLOC_SHAPE})
    out = shapes.scan(root)
    assert list(out["shapes_run"]) == ["scan2"]
    assert out["hit_count"] == 1


def test_zero_hits_is_admissible_only_with_a_passing_selftest(tmp_path):
    root = write_tree(tmp_path, {"clean.c": "int main(void){return 0;}"})
    out = shapes.scan(root, shapes_wanted=["scan2"])
    assert out["hit_count"] == 0
    assert out["selftest_passed"] is True
    assert out["clean_claim_admissible"] is True


def test_broken_scanner_cannot_report_clean(tmp_path, monkeypatch):
    """If the pattern stops matching its known-positive, the negative is void."""
    import re as _re
    monkeypatch.setitem(shapes._PATTERNS, "scan2",
                        _re.compile(r"this_will_never_match_anything"))
    root = write_tree(tmp_path, {"clean.c": "int main(void){return 0;}"})
    out = shapes.scan(root, shapes_wanted=["scan2"])
    assert out["selftest_passed"] is False
    assert out["clean_claim_admissible"] is False


def test_duplicate_hits_are_collapsed(tmp_path):
    root = write_tree(tmp_path, {"dup.c": ASSETSYS_SHAPE + ASSETSYS_SHAPE})
    out = shapes.scan(root, shapes_wanted=["scan2"])
    assert out["hit_count"] == 1
    assert out["hits"][0]["occurrences"] == 2


def test_skip_dirs_and_non_c_files_are_ignored(tmp_path):
    root = write_tree(tmp_path, {
        "corpus/seed.c": ASSETSYS_SHAPE,
        ".git/objects/x.c": ASSETSYS_SHAPE,
        "notes.md": ASSETSYS_SHAPE,
        "real.c": ASSETSYS_SHAPE,
    })
    out = shapes.scan(root, shapes_wanted=["scan2"])
    assert out["hit_count"] == 1
    assert out["hits"][0]["file"] == "real.c"


def test_oversized_files_are_skipped(tmp_path):
    root = write_tree(tmp_path, {"huge.c": ASSETSYS_SHAPE + ("\n// pad" * 50)})
    out = shapes.scan(root, shapes_wanted=["scan2"], max_file_bytes=50)
    assert out["hit_count"] == 0
    assert out["files_skipped_size"] == 1


def test_missing_root_is_an_error_not_an_empty_clean_result():
    out = shapes.scan("/nonexistent/path/xyz", shapes_wanted=["scan2"])
    assert out.get("error")
    assert out["clean_claim_admissible"] is False


def test_scan_reports_the_stage_precision_so_hits_are_not_over_trusted(tmp_path):
    root = write_tree(tmp_path, {"a.h": ASSETSYS_SHAPE})
    out = shapes.scan(root, shapes_wanted=["scan2"])
    assert "precision" in out["stage_note"].lower()
    assert "target" in out["stage_note"].lower()
