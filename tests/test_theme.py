"""Palette invariants; these checks do not replace rendered browser review."""
from pathlib import Path
import re
import unittest


CSS = Path(__file__).resolve().parents[1] / "src/daedalus/static/css/app.css"


def luminance(color):
    channels = [int(color[index:index + 2], 16) / 255 for index in (1, 3, 5)]
    linear = [value / 12.92 if value <= .04045 else ((value + .055) / 1.055) ** 2.4 for value in channels]
    return sum(value * weight for value, weight in zip(linear, (.2126, .7152, .0722)))


class ThemeTests(unittest.TestCase):
    def test_all_custom_property_references_are_defined(self):
        css = CSS.read_text()
        used = set(re.findall(r"var\((--[\w-]+)", css))
        defined = set(re.findall(r"(--[\w-]+)\s*:", css))
        self.assertEqual(used - defined, set())

    def test_primary_palette_text_pairs_meet_normal_text_contrast(self):
        css = CSS.read_text()
        tokens = dict(re.findall(r"(--[\w-]+)\s*:\s*(#[0-9a-fA-F]{6})\s*;", css))
        pairs = [
            (tokens["--brown-900"], tokens["--card-surface"]),
            (tokens["--olive-900"], tokens["--card-surface"]),
            ("#6b624f", tokens["--card-surface"]),
            ("#6e674f", tokens["--card-surface"]),
            (tokens["--olive-950"], tokens["--selected-surface"]),
            (tokens["--cream-100"], tokens["--olive-800"]),
        ]
        for foreground, background in pairs:
            with self.subTest(foreground=foreground, background=background):
                high, low = sorted([luminance(foreground), luminance(background)], reverse=True)
                self.assertGreaterEqual((high + .05) / (low + .05), 4.5)


if __name__ == "__main__":
    unittest.main()
