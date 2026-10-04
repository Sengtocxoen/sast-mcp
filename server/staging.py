"""
staging.py - get a scan target onto fast local disk before scanning it.

Scanning in place across a VMware/NFS/CIFS share is pathologically slow, because
a SAST tool walks thousands of files and every open is a round trip. Measured on
the Kali host against the Deca/IPS trees (vmhgfs share, ~24k files):

    scan the share directly      ~240s per repo, and the biggest repos never
                                 finished inside a 300s cap at all
    tar-stream to /tmp, scan     ~50s per repo (stage ~45s + scan ~5-17s)

The copy looks like pure overhead and is not: a streamed `tar` pipe moves the
tree in one sequential read, whereas the scan's own access pattern is thousands
of random per-file opens. That is the whole trick.

This logic started inside routes/repo_scan.py, which is why /api/repo-scan was
always fast while the per-tool endpoints (which hand the share path straight to
the scanner) were not. It lives here so both use one implementation.

Two things to know before using it:

* **.git is excluded.** Staging is for tools that walk source files. A tool that
  reads git history - gitleaks in its default mode, trufflehog's git mode - must
  scan in place or it will silently find nothing. stage() refuses to help there;
  see needs_git().
* **Paths must be mapped back.** Findings from a staged scan point at the
  staging directory, which means nothing to the caller. Staged.remap() rewrites
  them to the original path; run it over raw tool output before parsing.
"""
import logging
import os
import shlex
import shutil
import tempfile
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

# Filesystems where per-file access is a network round trip.
SLOW_FSTYPES = {
    "fuse", "fuse.vmhgfs-fuse", "vmhgfs", "vboxsf", "cifs", "smb3", "smbfs",
    "nfs", "nfs4", "9p", "fuseblk", "sshfs", "fuse.sshfs", "afpfs",
}

# Directories never worth copying. .git is here deliberately - see the module
# docstring - which is exactly why git-history tools must not be staged.
SKIP_DIRS = {
    ".git", ".svn", ".hg", "node_modules", "vendor", "dist", "build", ".next",
    ".venv", "venv", "__pycache__", ".terraform", "coverage", ".mypy_cache",
    ".pytest_cache", ".gradle", "target",
}

# Tools that read git history rather than the working tree.
GIT_HISTORY_TOOLS = {"gitleaks", "trufflehog"}

STAGE_TIMEOUT = int(os.environ.get("STAGE_TIMEOUT", 900))
STAGE_BASE_DIR = os.environ.get("STAGE_BASE_DIR", "")


def _default_base_dir() -> str:
    """A per-user staging root, not a shared one.

    A staged copy is the caller's entire source tree, so the directory it lands
    in matters. A fixed name under a world-writable /tmp can be pre-created or
    symlinked by another local user, who would then receive the copy.
    """
    base = os.environ.get("XDG_CACHE_HOME")
    if not base:
        home = os.path.expanduser("~")
        if home and home != "~" and os.path.isdir(home):
            base = os.path.join(home, ".cache")
    if base:
        return os.path.join(base, "sast-mcp", "stage")
    uid = getattr(os, "geteuid", lambda: "nouid")()
    return os.path.join(tempfile.gettempdir(), f"sast-stage-{uid}")


def _base_dir_defect(path: str) -> str:
    """'' when the staging root is safe to write a source copy into."""
    try:
        if os.path.islink(path):
            return "it is a symlink"
        st = os.stat(path)
        geteuid = getattr(os, "geteuid", None)
        if geteuid is not None:  # POSIX only; st_uid is meaningless on Windows
            if st.st_uid != geteuid():
                return f"it is owned by uid {st.st_uid}, not {geteuid()}"
            if st.st_mode & 0o022:
                try:
                    os.chmod(path, 0o700)
                except OSError:
                    return "it is writable by other users"
    except OSError as e:
        return f"it cannot be inspected ({e})"
    return ""


def fstype(path: str) -> str:
    """Filesystem type of the mount backing `path` ('' when undeterminable)."""
    try:
        target = os.path.abspath(path)
        best, best_type = "", ""
        with open("/proc/mounts") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) < 3:
                    continue
                mnt, fs = parts[1], parts[2]
                if (target == mnt or target.startswith(mnt.rstrip("/") + "/")) and len(mnt) > len(best):
                    best, best_type = mnt, fs
        return best_type
    except Exception:
        # No /proc/mounts (Windows, container): treat as local and scan in place.
        return ""


def is_slow(path: str) -> bool:
    return fstype(path) in SLOW_FSTYPES


def needs_git(tool: str) -> bool:
    """True when the tool reads git history, so staging would blind it."""
    return os.path.basename(str(tool or "")).lower() in GIT_HISTORY_TOOLS


class Staged:
    """A scan target, possibly copied to local disk. Use as a context manager."""

    def __init__(self, path: str, source: str, staged: bool, reason: str = "",
                 stderr: str = "", excluded: Optional[frozenset] = None):
        self.path = path          # scan this
        self.source = source      # the caller's original path
        self.staged = staged
        self.reason = reason
        self.stderr = stderr
        # What the copy left out. Only meaningful when staged; reported either
        # way so coverage is never assumed.
        self.excluded = frozenset(excluded or ())

    def remap(self, value: Any) -> Any:
        """Rewrite staged paths back to the original, in strings or structures.

        Run this over tool output before parsing it: a finding at
        /tmp/sast-stage/repo/src/a.c has to be reported at the caller's path, or
        the result is unusable and looks like it came from somewhere else.
        """
        if not self.staged or self.path == self.source:
            return value
        if isinstance(value, str):
            out = value.replace(self.path, self.source)
            # Inside JSON, a Windows path arrives backslash-escaped
            # ("C:\\stage\\x"), so the raw form never matches. Harmless on
            # POSIX, where the escaped and raw forms are identical.
            esc_from = self.path.replace("\\", "\\\\")
            if esc_from != self.path:
                out = out.replace(esc_from, self.source.replace("\\", "\\\\"))
            return out
        if isinstance(value, dict):
            return {k: self.remap(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self.remap(v) for v in value]
        return value

    def info(self) -> Dict[str, Any]:
        out = {
            "staged": self.staged,
            "scan_path": self.path,
            "source_path": self.source,
            "source_fstype": fstype(self.source),
        }
        if self.reason:
            out["stage_reason"] = self.reason
        if self.stderr:
            out["stage_stderr"] = self.stderr[:200]
        if self.staged and self.excluded:
            # A staged scan does NOT cover these, while an in-place scan of the
            # same target would. Saying so in the result is the difference
            # between reduced coverage and silently reduced coverage - code
            # vendored under one of these names is simply not examined.
            out["not_scanned_dirs"] = sorted(self.excluded)
            out["coverage_note"] = (
                "staged scan: the directories in not_scanned_dirs were excluded from the "
                "copy and were NOT scanned. Set STAGE_EXCLUDE, or stage='never' to scan "
                "the target in place with full coverage.")
        return out

    def cleanup(self) -> None:
        if self.staged and self.path != self.source and os.path.isdir(self.path):
            shutil.rmtree(self.path, ignore_errors=True)

    def __enter__(self) -> "Staged":
        return self

    def __exit__(self, *exc) -> None:
        self.cleanup()


def stage(path: str, mode: str = "auto", tool: str = "",
          base_dir: Optional[str] = None, executor: Any = None) -> Staged:
    """Copy `path` to local disk when that will make the scan faster.

    mode: "auto"   - stage only when the source is on a slow (network/fuse) FS
          "always" - stage regardless
          "never"  - scan in place
    `tool` lets a git-history tool opt out automatically.
    """
    src = os.path.abspath(path)
    if not os.path.isdir(src):
        # A single-file target has no per-file walk to amortise.
        return Staged(src, src, False, reason="target is not a directory")
    if mode == "never":
        return Staged(src, src, False, reason="staging disabled for this call")
    if tool and needs_git(tool):
        return Staged(src, src, False,
                      reason=f"{tool} reads git history; staging excludes .git")
    if mode == "auto" and not is_slow(src):
        return Staged(src, src, False, reason="source is already on local disk")

    if executor is None:
        from core import execute_command as executor  # late import: avoids a cycle

    base = base_dir or STAGE_BASE_DIR or _default_base_dir()
    # A staging root inside the scan target would have tar copying the
    # destination into itself, which inflates the copy and corrupts the
    # completeness check. Scan in place instead.
    base_real, src_real = os.path.realpath(base), os.path.realpath(src)
    if base_real == src_real or base_real.startswith(src_real + os.sep):
        logger.warning("staging dir %s is inside the target %s; scanning in place", base, src)
        return Staged(src, src, False, reason="staging dir is inside the scan target")
    try:
        # 0o700, and refuse a base somebody else controls: a staged copy is a
        # full copy of the caller's source tree, so a pre-created or symlinked
        # /tmp/sast-stage would hand it to another local user.
        os.makedirs(base, mode=0o700, exist_ok=True)
        problem = _base_dir_defect(base)
        if problem:
            logger.warning("staging base %s rejected (%s); scanning in place", base, problem)
            return Staged(src, src, False, reason=f"staging dir rejected: {problem}")
        dest = tempfile.mkdtemp(prefix=os.path.basename(src.rstrip("/\\"))[:40] + "-", dir=base)
    except OSError as e:
        logger.warning("staging unavailable (%s); scanning in place: %s", base, e)
        return Staged(src, src, False, reason=f"staging dir unusable: {e}")

    skip = _exclude_dirs()
    excludes = " ".join(f"--exclude={shlex.quote(d)}" for d in sorted(skip))
    cmd = (f"tar -C {shlex.quote(src)} {excludes} -cf - . | "
           f"tar -C {shlex.quote(dest)} -xf -")
    res = executor(cmd, timeout=STAGE_TIMEOUT) or {}

    # A PARTIAL copy is the dangerous outcome, not an empty one. If the disk
    # fills or tar errors mid-stream, dest is non-empty and a naive check calls
    # the copy good - so the scanner examines an incomplete tree and reports
    # fewer findings with no error. That is the same false-clean shape as a
    # crashed scanner, so the copy has to be proven complete before it is used.
    problem = _copy_defect(src, dest, res, skip)
    if problem:
        logger.warning("staging rejected for %s (%s); scanning in place", src, problem)
        shutil.rmtree(dest, ignore_errors=True)
        return Staged(src, src, False, reason=f"staging rejected: {problem}",
                      stderr=(res.get("stderr") or ""), excluded=skip)

    return Staged(dest, src, True, reason=f"source on {fstype(src) or 'unknown'} filesystem",
                  stderr=(res.get("stderr") or ""), excluded=skip)


def _exclude_dirs() -> frozenset:
    """Directories left out of the copy. STAGE_EXCLUDE overrides the default."""
    override = os.environ.get("STAGE_EXCLUDE")
    if override is None:
        return frozenset(SKIP_DIRS)
    names = {n.strip() for n in override.split(",") if n.strip()}
    # .git is non-negotiable: a copy of it would be partial and misleading, and
    # git-history tools are never staged anyway.
    names.add(".git")
    return frozenset(names)


# tar reports these on stderr while still exiting 0 in a pipeline, because a
# shell pipeline's status is the LAST command's - the receiving tar - so a
# failure in the sending tar is invisible without reading the text.
_TAR_ERROR_MARKERS = (
    "no space left", "cannot write", "write error", "error exit delayed",
    "unexpected eof", "cannot open", "permission denied", "input/output error",
    "disk quota exceeded", "file changed as we read it",
)


def _top_level(path: str, skip: frozenset) -> Optional[int]:
    try:
        return sum(1 for n in os.listdir(path) if n not in skip)
    except OSError:
        return None


def _copy_defect(src: str, dest: str, res: Dict[str, Any], skip: frozenset) -> str:
    """'' when the staged copy looks complete, else why it cannot be trusted."""
    rc = res.get("return_code")
    if rc not in (0, None):
        return f"tar exited {rc}"
    stderr = (res.get("stderr") or "").lower()
    for marker in _TAR_ERROR_MARKERS:
        if marker in stderr:
            return f"tar reported '{marker}'"
    if res.get("timed_out"):
        return "tar timed out"

    want = _top_level(src, skip)
    got = _top_level(dest, skip)
    if got is None:
        return "staged copy is unreadable"
    if got == 0:
        return "staged copy is empty"
    # One readdir each, no recursion: cheap, and gross truncation (whole
    # subtrees missing) is what a failed copy actually looks like.
    if want is not None and got < want:
        return f"staged copy has {got} of {want} top-level entries"
    return ""
