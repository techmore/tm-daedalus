import subprocess
import sys
from pathlib import Path

root = Path(__file__).resolve().parents[1]
css_dir = root / "src/daedalus/static/css"


def test_generated_overrides_match_app_css():
    committed = (css_dir / "elementary-overrides.css").read_text()
    subprocess.run([sys.executable, str(root / "scripts/gen_elementary_overrides.py")], check=True, capture_output=True)
    assert (css_dir / "elementary-overrides.css").read_text() == committed, "re-run scripts/gen_elementary_overrides.py"


def test_every_page_loads_theme_layers_in_cascade_order():
    for name in ("dashboard", "login", "user_keys"):
        html = (root / f"src/daedalus/templates/{name}.html").read_text()
        order = [html.index(f"/static/css/{sheet}") for sheet in ("app.css", "elementary-overrides.css", "elementary.css?")]
        assert order == sorted(order), name


def test_theme_defines_light_and_dark_tokens():
    theme = (css_dir / "elementary.css").read_text()
    assert "prefers-color-scheme: dark" in theme and "--e-accent" in theme
