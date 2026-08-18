#!/usr/bin/env python3
"""Generate repository-local language and source-line badges."""

from __future__ import annotations

import argparse
import html
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BADGE_DIRECTORY = ROOT / "badges"
LANGUAGES = {
    ".cs": "C#",
    ".css": "CSS",
    ".go": "Go",
    ".html": "HTML",
    ".java": "Java",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".py": "Python",
    ".rs": "Rust",
    ".scss": "SCSS",
    ".sh": "Shell",
    ".sql": "SQL",
    ".svelte": "Svelte",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".vue": "Vue",
}
EXCLUDED_DIRECTORIES = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "badges",
    "build",
    "dist",
    "node_modules",
    "sbom",
    "vendor",
}


def source_line_counts() -> Counter[str]:
    """Return nonblank physical source lines grouped by language."""
    counts: Counter[str] = Counter()
    for path in ROOT.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in LANGUAGES:
            continue
        if any(part in EXCLUDED_DIRECTORIES for part in path.relative_to(ROOT).parts):
            continue
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except UnicodeDecodeError:
            continue
        counts[LANGUAGES[path.suffix.lower()]] += sum(bool(line.strip()) for line in lines)
    return counts


def language_summary(counts: Counter[str]) -> str:
    """Format up to three languages and combine smaller languages into a remainder."""
    total = sum(counts.values())
    if not total:
        return "none"
    ordered = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    displayed = [
        f"{language} {round((line_count / total) * 100)}%"
        for language, line_count in ordered[:3]
    ]
    if len(ordered) > 3:
        displayed.append(f"+{len(ordered) - 3}")
    return " · ".join(displayed)


def badge_svg(label: str, value: str, color: str) -> str:
    """Render a small dependency-free badge compatible with README image rendering."""
    label_width = max(60, len(label) * 7 + 16)
    value_width = max(48, len(value) * 7 + 16)
    total_width = label_width + value_width
    safe_label = html.escape(label)
    safe_value = html.escape(value)
    label_x = label_width / 2
    value_x = label_width + (value_width / 2)
    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{total_width}" height="20" role="img" aria-label="{safe_label}: {safe_value}">
  <title>{safe_label}: {safe_value}</title>
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#fff" stop-opacity=".7"/>
    <stop offset=".1" stop-color="#aaa" stop-opacity=".1"/>
    <stop offset=".9" stop-opacity=".3"/>
    <stop offset="1" stop-opacity=".5"/>
  </linearGradient>
  <clipPath id="r"><rect width="{total_width}" height="20" rx="3"/></clipPath>
  <g clip-path="url(#r)">
    <rect width="{label_width}" height="20" fill="#555"/>
    <rect x="{label_width}" width="{value_width}" height="20" fill="{color}"/>
    <rect width="{total_width}" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">
    <text x="{label_x}" y="15" fill="#010101" fill-opacity=".3">{safe_label}</text>
    <text x="{label_x}" y="14">{safe_label}</text>
    <text x="{value_x}" y="15" fill="#010101" fill-opacity=".3">{safe_value}</text>
    <text x="{value_x}" y="14">{safe_value}</text>
  </g>
</svg>
"""


def update_badges(check: bool) -> int:
    """Write badges or report whether committed badges match calculated metrics."""
    counts = source_line_counts()
    outputs = {
        BADGE_DIRECTORY / "languages.svg": badge_svg(
            "languages", language_summary(counts), "#3572a5"
        ),
        BADGE_DIRECTORY / "lines-of-code.svg": badge_svg(
            "lines of code", f"{sum(counts.values()):,}", "#0b7c3e"
        ),
    }
    stale: list[Path] = []
    for path, content in outputs.items():
        if path.exists() and path.read_text(encoding="utf-8") == content:
            continue
        stale.append(path)
        if not check:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")

    if stale and check:
        for path in stale:
            print(f"stale badge: {path.relative_to(ROOT)}")
        return 1
    for path in outputs:
        print(f"current badge: {path.relative_to(ROOT)}")
    return 0


def main() -> int:
    """Parse command-line arguments and update or check badges."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="fail instead of writing")
    arguments = parser.parse_args()
    return update_badges(arguments.check)


if __name__ == "__main__":
    raise SystemExit(main())
