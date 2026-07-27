"""
Route modules: one module per tool category for easier error handling and updates.
Each module has register(app) to attach its endpoints.
"""
from flask import Flask


def register_all(app: Flask) -> None:
    from . import sast, secrets, dependencies, iac, container, kali, util, jobs, analysis, health, results, repo_scan, fuzz
    sast.register(app)
    repo_scan.register(app)
    fuzz.register(app)
    secrets.register(app)
    dependencies.register(app)
    iac.register(app)
    container.register(app)
    kali.register(app)
    util.register(app)
    jobs.register(app)
    analysis.register(app)
    health.register(app)
    results.register(app)
