"""Shared test setup.

CI must run every test. On a developer machine without Node.js or the
Playwright browser, tests that need them are skipped with a clear reason
instead of failing.
"""
import os
import shutil

import pytest

IN_CI = bool(os.environ.get("CI"))
INSTALL_HINT = "run: python -m playwright install chromium --only-shell"


def _browser_installed() -> bool:
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as playwright:
            playwright.chromium.launch(headless=True, args=["--no-sandbox"]).close()
        return True
    except Exception:
        return False


def pytest_configure(config):
    config._daedalus_browser = True if IN_CI else _browser_installed()
    if IN_CI and not shutil.which("node"):
        raise pytest.UsageError("Node.js is required in CI; Node-based UI tests would silently skip.")


def pytest_report_header(config):
    if not config._daedalus_browser:
        return f"Playwright browser missing: PDF/browser tests will be skipped ({INSTALL_HINT})"


# Signs that a failure came only from the missing browser.
_BROWSER_MISSING = ("Executable doesn't exist", "BrowserType.launch", "PDF generation failed")


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    report = outcome.get_result()
    if report.failed and not item.config._daedalus_browser and any(s in str(report.longrepr) for s in _BROWSER_MISSING):
        report.outcome = "skipped"
        report.longrepr = (str(item.path), item.location[1] or 0, f"Skipped: Playwright browser not installed ({INSTALL_HINT})")
