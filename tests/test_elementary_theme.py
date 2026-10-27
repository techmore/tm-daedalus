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
        order = [html.index(f"/static/css/{sheet}") for sheet in ("app.css", "elementary-overrides.css", "elementary.css?", "daedalus-ui.css?")]
        assert order == sorted(order), name


def test_theme_defines_light_and_dark_tokens():
    theme = (css_dir / "elementary.css").read_text()
    assert "prefers-color-scheme: dark" in theme and "--e-accent" in theme


def test_ui_layer_follows_manual_theme_choice_and_uses_tokens():
    layer = (css_dir / "daedalus-ui.css").read_text()
    theme = (css_dir / "elementary.css").read_text()
    assert ':root[data-theme="dark"]' in theme and ':root[data-theme="dark"]' in layer
    assert "@media (prefers-reduced-motion: reduce)" in layer


def test_theme_script_loads_before_first_paint_without_inline_code():
    for name in ("dashboard", "login", "user_keys"):
        html = (root / f"src/daedalus/templates/{name}.html").read_text()
        head = html[:html.index("</head>")]
        assert '<script src="/static/js/theme.js' in head and "defer" not in head[head.index("theme.js"):head.index("theme.js") + 40], name
