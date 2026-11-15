"""
Tests that the server still boots under Python 3.14's default start method.

Python 3.14 made "forkserver" the default on Linux ("fork" up to 3.13). forkserver
and spawn both re-import the main module in the child, and sast_server builds its
app and registers every route at import time, so core was imported a second time
inside a bootstrapping child, Manager() raised "An attempt has been made to start
a new process before the current process has finished its bootstrapping phase",
and the parent died with EOFError/ConnectionResetError. The server never started.

core now asks for the "fork" context by name, and falls back to threading
primitives where fork does not exist (Windows) instead of failing to boot.
"""
import multiprocessing
import os
import subprocess
import sys
import tempfile
import textwrap

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SERVER = os.path.join(ROOT, "server")
os.environ.setdefault("USE_MULTIPROCESSING", "0")
os.environ.setdefault("MOUNT_POINT", ROOT)
os.environ.setdefault("WINDOWS_BASE", ROOT)
# Importing core builds a JobManager, which creates DEFAULT_OUTPUT_DIR. Its
# default /var/sast-mcp/scan-results is not writable on a CI runner.
os.environ.setdefault("DEFAULT_OUTPUT_DIR", tempfile.mkdtemp(prefix="sast-mp-boot-"))
sys.path.insert(0, SERVER)

pytest.importorskip("psutil", reason="psutil not installed")

import core  # noqa: E402

HAS_FORK = "fork" in multiprocessing.get_all_start_methods()


def test_effective_flag_tracks_the_shared_state():
    """MULTIPROCESSING_ACTIVE must describe what started, not what was asked for."""
    assert core.MULTIPROCESSING_ACTIVE == (core.mp_manager is not None)
    # conftest sets USE_MULTIPROCESSING=0, so the thread path is in use here.
    assert core.MULTIPROCESSING_ACTIVE is False
    assert isinstance(core.scan_stats, dict)
    assert core.job_manager.executor.__class__.__name__ == "ThreadPoolExecutor"


def test_route_registration_is_skipped_on_a_child_reimport():
    """A spawn/forkserver child imports the entrypoint as __mp_main__."""
    src = open(os.path.join(SERVER, "sast_server.py"), encoding="utf-8").read()
    guard = src.find('if __name__ != "__mp_main__":')
    assert guard != -1, "sast_server must guard its bootstrap against a child re-import"
    assert src.find("register_all(app)", guard) > guard


@pytest.mark.skipif(not HAS_FORK, reason="no fork start method on this platform")
@pytest.mark.parametrize("method", ["forkserver", "spawn"])
def test_boots_when_the_default_start_method_reimports_main(method, tmp_path):
    """Import core at module level with a re-importing default, as the server does."""
    script = textwrap.dedent(
        """
        import multiprocessing, sys
        multiprocessing.set_start_method(%r, force=True)
        sys.path.insert(0, %r)
        import core
        assert core.MULTIPROCESSING_ACTIVE, "expected the fork context to be used"
        print("BOOT_OK")
        """
    ) % (method, SERVER)
    env = dict(
        os.environ,
        USE_MULTIPROCESSING="1",
        DEFAULT_OUTPUT_DIR=str(tmp_path / "out"),
        MOUNT_POINT=str(tmp_path),
        WINDOWS_BASE=str(tmp_path),
    )
    proc = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True, text=True, timeout=300, env=env,
    )
    assert proc.returncode == 0, proc.stderr[-2000:]
    assert "BOOT_OK" in proc.stdout
