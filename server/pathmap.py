"""
pathmap.py - the authority on "where do repos live", for any number of mounts.

The server previously understood exactly ONE Windows->Linux mapping
(WINDOWS_BASE -> MOUNT_POINT). Mount a second VMware shared folder and the
client's path for it translated to nothing: resolve_windows_path fell through,
returned the Windows string unchanged, and validate_scan_target then rejected it
as "outside the allowed mount roots". ALLOWED_MOUNTS could authorize the extra
Linux root, but nothing could TRANSLATE a client path into it, so in practice
every repo had to live under one share.

Configuration, in precedence order (later sources add to, not replace, earlier):

1. ``WINDOWS_BASE`` / ``MOUNT_POINT``          - the original single pair, still honored
2. ``PATH_MAPPINGS``                            - "F:/work=/mnt/work,D:/code=/mnt/code"
3. ``MOUNTS_CONFIG`` file (JSON)                - {"mappings": {"F:/work": "/mnt/work"}}
4. ``ALLOWED_MOUNTS``                           - extra Linux roots with no client-side twin
5. auto-discovery of shared-folder mounts       - AUTO_DISCOVER_MOUNTS=1 (default)

Resolution is longest-prefix-first, so "F:/work/deep" wins over "F:/" and the
mapping table can be as granular as the mounts are.
"""
import json
import logging
import os
import re
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


def _env(name: str, default: str = "") -> str:
    return (os.environ.get(name) or default).strip()


def _norm_client(p: str) -> str:
    """Normalize a client-side path for matching: slashes, case, trailing sep.

    Git Bash mangles 'F:/work' into '/f:/work', and Windows clients send either
    separator, so both forms have to collapse to the same key.
    """
    s = (p or "").replace("\\", "/").strip()
    if re.match(r"^/[A-Za-z]:", s):   # git-bash style /f:/work
        s = s[1:]
    return s.rstrip("/")


def _norm_linux(p: str) -> str:
    return os.path.normpath((p or "").strip().replace("\\", "/")).rstrip("/") or "/"


# Mount points under these parents are candidates for auto-discovery. Anything
# else (/, /proc, /usr, ...) is system surface, never a scan target.
_DISCOVER_PARENTS = [d for d in _env(
    "AUTO_DISCOVER_PARENTS", "/mnt,/media,/srv,/data,/shared").split(",") if d.strip()]
# Filesystem types that indicate a shared folder / network mount someone added
# specifically so it could be scanned.
_DISCOVER_FSTYPES = {"fuse", "fuse.vmhgfs-fuse", "vmhgfs", "vboxsf", "cifs",
                     "smb3", "smbfs", "nfs", "nfs4", "9p", "fuseblk", "sshfs",
                     "ext4", "xfs", "btrfs", "overlay"}


def _discover_mounts() -> List[str]:
    """Linux mount points that look like deliberately-mounted scan shares.

    This is what makes "I mounted a new folder in VMware" just work: the share
    shows up as an allowed root without editing .env and restarting.
    """
    found: List[str] = []
    parents = [_norm_linux(p) for p in _DISCOVER_PARENTS]
    try:
        with open("/proc/mounts") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) < 3:
                    continue
                mnt, fstype = parts[1], parts[2]
                # /proc/mounts octal-escapes spaces and friends
                mnt = mnt.replace("\\040", " ").replace("\\011", "\t")
                if fstype not in _DISCOVER_FSTYPES:
                    continue
                m = _norm_linux(mnt)
                if any(m != p and m.startswith(p + "/") for p in parents):
                    found.append(m)
    except Exception as e:
        logger.debug(f"pathmap: mount discovery unavailable: {e}")
    return sorted(set(found))


def _parse_pairs(spec: str) -> List[Tuple[str, str]]:
    """Parse "F:/work=/mnt/work,D:/code=/mnt/code" into normalized pairs."""
    pairs: List[Tuple[str, str]] = []
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        # rsplit: a Windows client path contains ':' but the separator is '='
        if "=" not in chunk:
            logger.warning(f"pathmap: ignoring malformed mapping {chunk!r} (expected CLIENT=LINUX)")
            continue
        client, linux = chunk.split("=", 1)
        client, linux = _norm_client(client), _norm_linux(linux)
        if client and linux:
            pairs.append((client, linux))
    return pairs


def _load_config_file() -> Tuple[List[Tuple[str, str]], List[str]]:
    """Optional JSON file, so mounts can be managed without a giant env string."""
    path = _env("MOUNTS_CONFIG")
    if not path:
        default = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                               "mounts.json")
        path = default if os.path.exists(default) else ""
    if not path or not os.path.exists(path):
        return [], []
    try:
        with open(path) as fh:
            data = json.load(fh)
    except Exception as e:
        logger.warning(f"pathmap: could not read MOUNTS_CONFIG {path}: {e}")
        return [], []
    pairs = [(_norm_client(k), _norm_linux(v))
             for k, v in (data.get("mappings") or {}).items() if k and v]
    roots = [_norm_linux(r) for r in (data.get("allowed_roots") or []) if r]
    logger.info(f"pathmap: loaded {len(pairs)} mapping(s) from {path}")
    return pairs, roots


class PathMap:
    """Bidirectional client<->linux path translation over N mount pairs."""

    def __init__(self) -> None:
        self.mappings: List[Tuple[str, str]] = []
        self.roots: List[str] = []
        self.discovered: List[str] = []
        self._build()

    def _build(self) -> None:
        seen_pairs = set()

        def add_pair(client: str, linux: str) -> None:
            key = (client.lower(), linux)
            if client and linux and key not in seen_pairs:
                seen_pairs.add(key)
                self.mappings.append((client, linux))

        # 1. legacy single pair — still the default for existing installs
        wb, mp = _norm_client(_env("WINDOWS_BASE", "F:/work")), _norm_linux(_env("MOUNT_POINT", "/mnt/work"))
        add_pair(wb, mp)
        # 2. explicit multi-mapping env
        for c, l in _parse_pairs(_env("PATH_MAPPINGS")):
            add_pair(c, l)
        # 3. JSON config file
        file_pairs, file_roots = _load_config_file()
        for c, l in file_pairs:
            add_pair(c, l)

        # Longest client prefix first, so F:/work/sub beats F:/work.
        self.mappings.sort(key=lambda t: -len(t[0]))

        # Allowed roots: every mapping target, plus explicit extras, plus
        # discovered shares. This is the set validate_scan_target enforces.
        roots = [l for _, l in self.mappings]
        roots += [_norm_linux(r) for r in _env("ALLOWED_MOUNTS").split(",") if r.strip()]
        roots += file_roots
        # Legacy: the source-repo root is always scannable.
        src = _env("REPO_SRC_DIR") or _env("RESOLA_SRC_DIR")
        if src:
            roots.append(_norm_linux(src))
        if _env("AUTO_DISCOVER_MOUNTS", "1").lower() in ("1", "true", "yes", "y"):
            self.discovered = _discover_mounts()
            roots += self.discovered

        seen = set()
        self.roots = [r for r in roots if r and not (r in seen or seen.add(r))]

    # -- translation ------------------------------------------------------
    def to_linux(self, path: str) -> str:
        """Client path (Windows/git-bash/Linux) -> server path.

        Unmapped input is returned unchanged; validate_scan_target is what
        decides whether the result is allowed, not this function.
        """
        if not path:
            return path
        candidate = _norm_client(path)
        low = candidate.lower()
        for client, linux in self.mappings:  # longest prefix first
            cl = client.lower()
            if low == cl:
                return linux
            if low.startswith(cl + "/"):
                return linux + candidate[len(client):]
        # Already a server-side path.
        norm = candidate if candidate.startswith("/") else path
        if any(norm == r or norm.startswith(r + "/") for r in self.roots):
            return norm
        if norm.startswith("/") and os.path.exists(norm):
            return norm
        return path

    def to_client(self, linux_path: str) -> str:
        """Server path -> the path the client should display/send back."""
        if not linux_path:
            return linux_path
        norm = _norm_linux(linux_path)
        best: Optional[Tuple[str, str]] = None
        for client, linux in self.mappings:
            if norm == linux or norm.startswith(linux + "/"):
                if best is None or len(linux) > len(best[1]):
                    best = (client, linux)
        if not best:
            return linux_path
        client, linux = best
        tail = norm[len(linux):]
        out = client + tail
        # Windows clients expect backslashes for drive-letter paths.
        return out.replace("/", "\\") if re.match(r"^[A-Za-z]:", client) else out

    def is_allowed(self, linux_path: str) -> bool:
        norm = os.path.normpath(linux_path or "")
        return any(norm == r or norm.startswith(r + os.sep) for r in self.roots)

    def describe(self) -> Dict[str, object]:
        """The active table, for /health and for debugging a mount that won't resolve."""
        return {
            "mappings": [{"client": c, "server": l, "exists": os.path.isdir(l)}
                         for c, l in self.mappings],
            "allowed_roots": [{"path": r, "exists": os.path.isdir(r)} for r in self.roots],
            "auto_discovered": self.discovered,
            "sources": {
                "WINDOWS_BASE/MOUNT_POINT": bool(_env("MOUNT_POINT") or _env("WINDOWS_BASE")),
                "PATH_MAPPINGS": bool(_env("PATH_MAPPINGS")),
                "MOUNTS_CONFIG": bool(_env("MOUNTS_CONFIG")),
                "ALLOWED_MOUNTS": bool(_env("ALLOWED_MOUNTS")),
                "auto_discovery": _env("AUTO_DISCOVER_MOUNTS", "1").lower() in ("1", "true", "yes", "y"),
            },
        }


_pathmap: Optional[PathMap] = None


def get() -> PathMap:
    global _pathmap
    if _pathmap is None:
        _pathmap = PathMap()
        logger.info(f"pathmap: {len(_pathmap.mappings)} mapping(s), "
                    f"{len(_pathmap.roots)} allowed root(s)"
                    + (f", discovered {_pathmap.discovered}" if _pathmap.discovered else ""))
    return _pathmap


def reload() -> PathMap:
    """Re-read config and re-discover mounts (after mounting a new share)."""
    global _pathmap
    _pathmap = None
    return get()
