"""
Tests for staging a scan target to local disk before scanning it.

Measured on the Kali host (vmhgfs share, Deca/IPS trees, ~24k files):

    scan the share in place   ~240s per repo; the largest repos never finished
                              inside a 300s cap
    tar-stream then scan      ~50s per repo (stage ~45s + scan ~5-17s)

/api/repo-scan always staged; the per-tool endpoints handed the share path
straight to the scanner, which is why they were so much slower. Two traps the
tests pin down: staging excludes .git, so a git-history tool must never be
staged, and findings from a staged scan have to be mapped back to the caller's
path or every file reference is wrong.
"""
import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault("USE_MULTIPROCESSING", "0")
os.environ.setdefault("MOUNT_POINT", ROOT)
os.environ.setdefault("WINDOWS_BASE", ROOT)
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "server"))

import staging  # noqa: E402


# -- when to stage --------------------------------------------------------

def test_local_source_is_not_staged(tmp_path):
    """The copy is pure cost when the target is already on local disk."""
    (tmp_path / "a.py").write_text("x = 1\n")
    st = staging.stage(str(tmp_path), mode="auto")
    assert st.staged is False
    assert st.path == os.path.abspath(str(tmp_path))
    assert "local disk" in st.reason


def test_slow_source_is_staged(tmp_path, monkeypatch):
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.py").write_text("x = 1\n")
    monkeypatch.setattr(staging, "is_slow", lambda p: True)
    monkeypatch.setattr(staging, "fstype", lambda p: "fuse.vmhgfs-fuse")
    calls = []

    def fake_exec(cmd, timeout=None):
        calls.append(cmd)
        dest = cmd.split("tar -C ")[2].split(" ")[0].strip("'\"")
        with open(os.path.join(dest, "a.py"), "w") as f:
            f.write("x = 1\n")
        return {"return_code": 0, "stderr": ""}

    # The staging root is a SIBLING of the source: a root inside the target
    # would have tar copying the destination into itself.
    st = staging.stage(str(src), mode="auto", base_dir=str(tmp_path / "stage"),
                       executor=fake_exec)
    try:
        assert st.staged is True
        assert st.path != st.source
        assert "tar -C" in calls[0] and "--exclude=.git" in calls[0]
        assert os.path.isfile(os.path.join(st.path, "a.py"))
    finally:
        st.cleanup()


def test_mode_never_scans_in_place(tmp_path, monkeypatch):
    monkeypatch.setattr(staging, "is_slow", lambda p: True)
    st = staging.stage(str(tmp_path), mode="never")
    assert st.staged is False


def test_mode_always_stages_a_local_source(tmp_path, monkeypatch):
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.py").write_text("x = 1\n")

    def fake_exec(cmd, timeout=None):
        dest = cmd.split("tar -C ")[2].split(" ")[0].strip("'\"")
        with open(os.path.join(dest, "a.py"), "w") as f:
            f.write("x = 1\n")
        return {"return_code": 0, "stderr": ""}

    st = staging.stage(str(src), mode="always", base_dir=str(tmp_path / "s"),
                       executor=fake_exec)
    try:
        assert st.staged is True
    finally:
        st.cleanup()


def test_a_single_file_target_is_not_staged(tmp_path):
    f = tmp_path / "a.py"
    f.write_text("x = 1\n")
    st = staging.stage(str(f), mode="always")
    assert st.staged is False


# -- git-history tools must never be staged ------------------------------

@pytest.mark.parametrize("tool", ["gitleaks", "trufflehog", "/usr/bin/gitleaks"])
def test_git_history_tools_are_never_staged(tmp_path, tool, monkeypatch):
    """Staging excludes .git, so a staged gitleaks would scan no history and
    report no leaks - a false clean caused by an optimisation."""
    monkeypatch.setattr(staging, "is_slow", lambda p: True)
    st = staging.stage(str(tmp_path), mode="always", tool=tool)
    assert st.staged is False
    assert "git history" in st.reason


@pytest.mark.parametrize("tool", ["opengrep", "semgrep", "bandit", "gosec", ""])
def test_source_walking_tools_are_stageable(tool):
    assert staging.needs_git(tool) is False


def test_git_is_excluded_from_the_copy():
    assert ".git" in staging.SKIP_DIRS


# -- path remapping -------------------------------------------------------

def test_findings_are_remapped_to_the_callers_path():
    st = staging.Staged("/tmp/sast-stage/repo-ab12", "/mnt/share/repo", True)
    out = st.remap('{"path": "/tmp/sast-stage/repo-ab12/src/a.c", "line": 5}')
    assert "/mnt/share/repo/src/a.c" in out
    assert "sast-stage" not in out


def test_remap_walks_nested_structures():
    st = staging.Staged("/tmp/stage/x", "/mnt/repo", True)
    payload = {"results": [{"path": "/tmp/stage/x/a.c", "extra": {"p": ["/tmp/stage/x/b.c"]}}]}
    out = st.remap(payload)
    assert out["results"][0]["path"] == "/mnt/repo/a.c"
    assert out["results"][0]["extra"]["p"][0] == "/mnt/repo/b.c"


def test_remap_is_a_noop_when_not_staged():
    st = staging.Staged("/mnt/repo", "/mnt/repo", False)
    assert st.remap("/mnt/repo/a.c") == "/mnt/repo/a.c"


def test_remap_leaves_non_strings_alone():
    st = staging.Staged("/tmp/stage/x", "/mnt/repo", True)
    assert st.remap(7) == 7
    assert st.remap(None) is None


# -- failure modes --------------------------------------------------------

def test_staging_that_copies_nothing_falls_back_to_scanning_in_place(tmp_path, monkeypatch):
    """Staging must never be the reason a scan finds nothing."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.py").write_text("x = 1\n")
    monkeypatch.setattr(staging, "is_slow", lambda p: True)
    st = staging.stage(str(src), mode="auto", base_dir=str(tmp_path / "s"),
                       executor=lambda cmd, timeout=None: {"return_code": 127, "stderr": "no tar"})
    assert st.staged is False
    assert st.path == os.path.abspath(str(src))
    assert "exited 127" in st.reason


def test_unusable_staging_dir_degrades_to_in_place(tmp_path, monkeypatch):
    monkeypatch.setattr(staging, "is_slow", lambda p: True)
    blocker = tmp_path / "afile"
    blocker.write_text("x")
    st = staging.stage(str(tmp_path), mode="auto", base_dir=str(blocker / "sub"),
                       executor=lambda cmd, timeout=None: {"return_code": 0})
    assert st.staged is False


def test_cleanup_removes_the_copy_but_never_the_source(tmp_path, monkeypatch):
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.py").write_text("x = 1\n")

    def fake_exec(cmd, timeout=None):
        dest = cmd.split("tar -C ")[2].split(" ")[0].strip("'\"")
        with open(os.path.join(dest, "a.py"), "w") as f:
            f.write("x\n")
        return {"return_code": 0}

    st = staging.stage(str(src), mode="always", base_dir=str(tmp_path / "s"),
                       executor=fake_exec)
    copy = st.path
    assert os.path.isdir(copy)
    st.cleanup()
    assert not os.path.isdir(copy)
    assert os.path.isfile(str(src / "a.py")), "the source must survive"


def test_cleanup_of_an_unstaged_target_is_a_noop(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n")
    st = staging.stage(str(tmp_path), mode="never")
    st.cleanup()
    assert os.path.isfile(str(tmp_path / "a.py"))


def test_context_manager_cleans_up(tmp_path):
    def fake_exec(cmd, timeout=None):
        dest = cmd.split("tar -C ")[2].split(" ")[0].strip("'\"")
        with open(os.path.join(dest, "a.py"), "w") as f:
            f.write("x\n")
        return {"return_code": 0}

    src = tmp_path / "src"
    src.mkdir()
    (src / "a.py").write_text("x\n")
    with staging.stage(str(src), mode="always", base_dir=str(tmp_path / "s"),
                       executor=fake_exec) as st:
        copy = st.path
        assert os.path.isdir(copy)
    assert not os.path.isdir(copy)


def test_info_reports_what_happened(tmp_path):
    (tmp_path / "a.py").write_text("x\n")
    info = staging.stage(str(tmp_path), mode="never").info()
    assert info["staged"] is False
    assert info["source_path"] == os.path.abspath(str(tmp_path))
    assert "scan_path" in info


def test_fstype_never_raises_on_a_platform_without_proc_mounts():
    # Windows has no /proc/mounts; this must report local, not explode.
    assert isinstance(staging.fstype(ROOT), str)
    assert staging.is_slow(ROOT) is False


# -- the opengrep route uses it ------------------------------------------

def test_opengrep_scans_the_staged_copy_and_reports_source_paths(monkeypatch, tmp_path):
    from routes import sast as sast_routes

    (tmp_path / "a.py").write_text("import os\n")
    fake_stage = tmp_path / "staged"
    fake_stage.mkdir()
    st = staging.Staged(str(fake_stage), str(tmp_path), True, reason="test")
    monkeypatch.setattr(sast_routes.staging, "stage", lambda *a, **k: st)
    monkeypatch.setattr(sast_routes, "validate_scan_target", lambda p: str(tmp_path))

    seen = {}

    def fake_exec(command, cwd=None, timeout=None):
        seen["cmd"] = command
        finding = {"results": [{"check_id": "x", "path": str(fake_stage / "a.py"),
                                "start": {"line": 1}, "extra": {"severity": "ERROR"}}],
                   "paths": {"scanned": ["a.py"]}}
        return {"return_code": 1, "stdout": json.dumps(finding), "stderr": "", "success": True}

    monkeypatch.setattr(sast_routes, "execute_command", fake_exec)
    out = sast_routes._opengrep_scan({"target": str(tmp_path), "config": "p/default"})

    assert str(fake_stage) in seen["cmd"], "the staged copy should be scanned"
    # Assert on the parsed structure, not a substring of JSON: a Windows path is
    # backslash-escaped inside JSON, so a raw substring check passes vacuously.
    reported = json.loads(out["stdout"])["results"][0]["path"]
    assert reported == str(tmp_path / "a.py"), reported
    assert out["staged"] is True
    assert out["source_path"] == str(tmp_path)


# -- a PARTIAL copy must never be used (fail-closed) ---------------------

def _staging_exec(dest_files, rc=0, stderr="", timed_out=False):
    """Simulate tar producing a given set of files in the destination."""
    def fake_exec(cmd, timeout=None):
        dest = cmd.split("tar -C ")[2].split(" ")[0].strip("'\"")
        for name in dest_files:
            p = os.path.join(dest, name)
            os.makedirs(os.path.dirname(p), exist_ok=True) if os.path.dirname(p) else None
            with open(p, "w") as f:
                f.write("x\n")
        return {"return_code": rc, "stderr": stderr, "timed_out": timed_out}
    return fake_exec


@pytest.fixture
def slow_src(tmp_path, monkeypatch):
    monkeypatch.setattr(staging, "is_slow", lambda p: True)
    monkeypatch.setattr(staging, "fstype", lambda p: "fuse.vmhgfs-fuse")
    src = tmp_path / "repo"
    src.mkdir()
    for n in ("a.py", "b.py", "c.py"):
        (src / n).write_text("x = 1\n")
    return src


def test_a_truncated_copy_is_rejected(slow_src, tmp_path):
    """Disk full mid-copy leaves a NON-EMPTY dest. Using it means scanning an
    incomplete tree and reporting fewer findings with no error."""
    st = staging.stage(str(slow_src), mode="auto", base_dir=str(tmp_path / "s"),
                       executor=_staging_exec(["a.py"]))  # 1 of 3
    assert st.staged is False
    assert st.path == os.path.abspath(str(slow_src)), "must fall back to in place"
    assert "1 of 3" in st.reason


def test_a_complete_copy_is_accepted(slow_src, tmp_path):
    st = staging.stage(str(slow_src), mode="auto", base_dir=str(tmp_path / "s"),
                       executor=_staging_exec(["a.py", "b.py", "c.py"]))
    try:
        assert st.staged is True
    finally:
        st.cleanup()


def test_nonzero_tar_exit_is_rejected(slow_src, tmp_path):
    st = staging.stage(str(slow_src), mode="auto", base_dir=str(tmp_path / "s"),
                       executor=_staging_exec(["a.py", "b.py", "c.py"], rc=2))
    assert st.staged is False
    assert "exited 2" in st.reason


@pytest.mark.parametrize("msg", [
    "tar: /tmp/x: Cannot write: No space left on device",
    "tar: Error exit delayed from previous errors",
    "tar: Unexpected EOF in archive",
    "tar: a.py: Permission denied",
])
def test_tar_errors_on_stderr_are_rejected_even_at_exit_zero(slow_src, tmp_path, msg):
    """A shell pipeline's status is the LAST command's, so a failure in the
    sending tar exits 0 and is only visible in the text."""
    st = staging.stage(str(slow_src), mode="auto", base_dir=str(tmp_path / "s"),
                       executor=_staging_exec(["a.py", "b.py", "c.py"], rc=0, stderr=msg))
    assert st.staged is False
    assert "tar reported" in st.reason


def test_a_timed_out_copy_is_rejected(slow_src, tmp_path):
    st = staging.stage(str(slow_src), mode="auto", base_dir=str(tmp_path / "s"),
                       executor=_staging_exec(["a.py", "b.py", "c.py"], timed_out=True))
    assert st.staged is False
    assert "timed out" in st.reason


# -- staging root must not be a shared directory -------------------------

def test_default_base_dir_is_per_user():
    import tempfile as _t
    d = staging._default_base_dir()
    if os.path.realpath(d).startswith(os.path.realpath(_t.gettempdir())):
        assert os.path.basename(d) != "sast-stage", "a fixed name in shared /tmp"
        assert "sast-stage-" in os.path.basename(d)
    else:
        assert "sast-mcp" in d


def test_base_dir_is_created_private(slow_src, tmp_path):
    base = tmp_path / "s"
    st = staging.stage(str(slow_src), mode="auto", base_dir=str(base),
                       executor=_staging_exec(["a.py", "b.py", "c.py"]))
    try:
        if hasattr(os, "geteuid"):
            assert not (os.stat(str(base)).st_mode & 0o022), "group/other writable"
    finally:
        st.cleanup()


def test_a_symlinked_staging_root_is_refused(slow_src, tmp_path):
    real = tmp_path / "elsewhere"
    real.mkdir()
    link = tmp_path / "base"
    try:
        os.symlink(str(real), str(link), target_is_directory=True)
    except (OSError, NotImplementedError, AttributeError):
        pytest.skip("symlinks not available")
    st = staging.stage(str(slow_src), mode="auto", base_dir=str(link),
                       executor=_staging_exec(["a.py", "b.py", "c.py"]))
    assert st.staged is False
    assert "symlink" in st.reason


# -- excluded directories must be visible --------------------------------

def test_a_staged_scan_declares_what_it_did_not_cover(slow_src, tmp_path):
    """Staging skips vendor/node_modules/etc, so a staged scan covers less than
    an in-place one. Reduced coverage is acceptable; silent reduction is not."""
    st = staging.stage(str(slow_src), mode="auto", base_dir=str(tmp_path / "s"),
                       executor=_staging_exec(["a.py", "b.py", "c.py"]))
    try:
        info = st.info()
        assert "node_modules" in info["not_scanned_dirs"]
        assert "vendor" in info["not_scanned_dirs"]
        assert "NOT scanned" in info["coverage_note"]
    finally:
        st.cleanup()


def test_an_in_place_scan_claims_no_exclusions(tmp_path):
    (tmp_path / "a.py").write_text("x\n")
    info = staging.stage(str(tmp_path), mode="never").info()
    assert "not_scanned_dirs" not in info


def test_exclusions_are_overridable(monkeypatch):
    monkeypatch.setenv("STAGE_EXCLUDE", "node_modules")
    skip = staging._exclude_dirs()
    assert skip == frozenset({"node_modules", ".git"}), "vendor etc. now included"


def test_git_cannot_be_un_excluded(monkeypatch):
    monkeypatch.setenv("STAGE_EXCLUDE", "")
    assert ".git" in staging._exclude_dirs()
