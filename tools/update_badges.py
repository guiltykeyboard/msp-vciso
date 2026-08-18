#!/usr/bin/env python3
"""Generate repository-local language and source-line badges."""

from __future__ import annotations

import argparse
import hashlib
import html
import re
import subprocess
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BADGE_DIRECTORY = ROOT / "badges"
README_PATH = ROOT / "README.md"
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
README_BADGES = {
    "languages.svg": "Languages",
    "lines-of-code.svg": "Lines of code",
}


def tracked_files() -> list[Path]:
    """Return repository files tracked by Git in stable order."""
    result = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    return [
        ROOT / raw_path.decode("utf-8")
        for raw_path in result.stdout.split(b"\0")
        if raw_path
    ]


def source_line_counts() -> Counter[str]:
    """Return nonblank physical source lines grouped by language."""
    counts: Counter[str] = Counter()
    for path in tracked_files():
        if not path.is_file() or path.suffix.lower() not in LANGUAGES:
            continue
        relative_parts = path.relative_to(ROOT).parts
        if relative_parts[0] == "api":
            continue
        if any(part in EXCLUDED_DIRECTORIES for part in relative_parts):
            continue
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except UnicodeDecodeError:
            continue
        counts[LANGUAGES[path.suffix.lower()]] += sum(bool(line.strip()) for line in lines)
    return counts


def readme_with_cache_keys(badges: dict[Path, str]) -> str:
    """Return README content with badge URLs keyed to generated SVG content."""
    content = README_PATH.read_text(encoding="utf-8")
    for filename, alt_text in README_BADGES.items():
        badge_content = badges[BADGE_DIRECTORY / filename]
        cache_key = hashlib.sha256(badge_content.encode("utf-8")).hexdigest()[:12]
        pattern = re.compile(
            rf"!\[{re.escape(alt_text)}\]\(badges/{re.escape(filename)}(?:\?v=[^)]+)?\)"
        )
        replacement = f"![{alt_text}](badges/{filename}?v={cache_key})"
        content, replacements = pattern.subn(replacement, content, count=1)
        if replacements != 1:
            raise ValueError(f"README badge reference not found: {filename}")
    return content


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
    badges = {
        BADGE_DIRECTORY / "languages.svg": badge_svg(
            "languages", language_summary(counts), "#3572a5"
        ),
        BADGE_DIRECTORY / "lines-of-code.svg": badge_svg(
            "lines of code", f"{sum(counts.values()):,}", "#0b7c3e"
        ),
    }
    outputs = {**badges, README_PATH: readme_with_cache_keys(badges)}
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
        print(f"current generated metadata: {path.relative_to(ROOT)}")
    return 0


def main() -> int:
    """Parse command-line arguments and update or check badges."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="fail instead of writing")
    arguments = parser.parse_args()
    return update_badges(arguments.check)


if __name__ == "__main__":
    raise SystemExit(main())
