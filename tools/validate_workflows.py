#!/usr/bin/env python3
"""Enforce repository security and trust rules for GitHub Actions workflows."""

from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_DIRECTORY = ROOT / ".github" / "workflows"
ACTION_REFERENCE = re.compile(r"^\s*(?:-\s*)?uses:\s*([^\s#]+)")
FULL_COMMIT_SHA = re.compile(r"[0-9a-f]{40}")
FORBIDDEN_TEXT = {
    "[skip ci]": "workflow commits must not bypass validation",
    "pull_request_target": "untrusted pull-request code must not receive repository secrets",
    "permissions: write-all": "workflows must use explicit least-privilege permissions",
    "runs-on: ubuntu-latest": "runner major versions must be explicit",
}
ALWAYS_RUN_WORKFLOWS = {
    "api-docs.yml",
    "api.yml",
    "frameworks.yml",
    "lint.yml",
    "repository-metadata.yml",
}


def workflow_errors() -> list[str]:
    """Return actionable workflow policy violations."""
    errors: list[str] = []
    for path in sorted(WORKFLOW_DIRECTORY.glob("*.yml")):
        content = path.read_text(encoding="utf-8")
        relative_path = path.relative_to(ROOT)
        for forbidden, explanation in FORBIDDEN_TEXT.items():
            if forbidden in content:
                errors.append(f"{relative_path}: {explanation}: {forbidden}")
        if path.name in ALWAYS_RUN_WORKFLOWS and re.search(
            r"^\s+paths(?:-ignore)?:", content, flags=re.MULTILINE
        ):
            errors.append(f"{relative_path}: validation workflows must not use path filters")
        for line_number, line in enumerate(content.splitlines(), start=1):
            match = ACTION_REFERENCE.match(line)
            if match is None or match.group(1).startswith("./"):
                continue
            reference = match.group(1)
            revision = reference.rpartition("@")[2]
            if not FULL_COMMIT_SHA.fullmatch(revision):
                errors.append(
                    f"{relative_path}:{line_number}: action must use a full commit SHA: {reference}"
                )
    return errors


def main() -> int:
    """Print violations and return a nonzero status when policy is violated."""
    errors = workflow_errors()
    if errors:
        for error in errors:
            print(f"workflow policy violation: {error}")
        return 1
    print(f"validated workflow policy: {WORKFLOW_DIRECTORY.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
