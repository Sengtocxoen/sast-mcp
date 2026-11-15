"""Test environment, applied before any test module is imported.

Importing ``core`` builds a JobManager at module scope, and that constructor
creates ``DEFAULT_OUTPUT_DIR``. The default is ``/var/sast-mcp/scan-results``,
which a CI runner cannot write, so collection failed with PermissionError for
every test module that imports ``core``. Point it at a temp directory here,
where pytest reads it before the test modules run.
"""
import os
import tempfile

_TMP = os.path.join(tempfile.gettempdir(), "sast-mcp-tests", "scan-results")
os.environ.setdefault("DEFAULT_OUTPUT_DIR", _TMP)
os.environ.setdefault("USE_MULTIPROCESSING", "0")
