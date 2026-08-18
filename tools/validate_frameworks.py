#!/usr/bin/env python3
"""Validate Watchtower framework packs without third-party dependencies."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parents[1]
FRAMEWORKS = ROOT / "frameworks"
SCHEMA_PATH = FRAMEWORKS / "schema" / "framework-pack.schema.json"
ID_PATTERN = re.compile(r"^[A-Z0-9][A-Z0-9._-]*$")
SEMVER_PATTERN = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
REQUIREMENT_TYPES = {"mandatory", "conditional", "guidance", "record_classification"}
EVIDENCE_TYPES = {
    "document",
    "attestation",
    "config_snapshot",
    "device_posture",
    "training_record",
    "incident_record",
    "ticket",
    "log",
    "export",
}
SENSITIVITIES = {"public", "internal", "confidential", "security_record", "cji"}
REQUIRED_TOP_LEVEL = {
    "schema_version",
    "id",
    "slug",
    "title",
    "framework_version",
    "pack_version",
    "authority",
    "published_at",
    "effective_at",
    "sources",
    "applicability",
    "milestones",
    "requirements",
}


class ValidationErrors:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.messages: list[str] = []

    def add(self, location: str, message: str) -> None:
        self.messages.append(f"{self.path.relative_to(ROOT)}:{location}: {message}")

    def require(self, condition: bool, location: str, message: str) -> None:
        if not condition:
            self.add(location, message)


def is_nonempty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def is_https_url(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    parsed = urlparse(value)
    return parsed.scheme == "https" and bool(parsed.netloc)


def validate_pack(path: Path) -> list[str]:
    errors = ValidationErrors(path)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"{path.relative_to(ROOT)}: unable to read valid JSON: {exc}"]

    errors.require(isinstance(data, dict), "$", "pack must be a JSON object")
    if not isinstance(data, dict):
        return errors.messages

    missing = sorted(REQUIRED_TOP_LEVEL - data.keys())
    errors.require(not missing, "$", f"missing required fields: {', '.join(missing)}")
    errors.require(data.get("schema_version") == "1.0", "$.schema_version", "must equal 1.0")
    errors.require(bool(ID_PATTERN.fullmatch(str(data.get("id", "")))), "$.id", "invalid identifier")
    errors.require(bool(SEMVER_PATTERN.fullmatch(str(data.get("pack_version", "")))), "$.pack_version", "must be semantic version x.y.z")

    sources = data.get("sources", [])
    errors.require(isinstance(sources, list) and bool(sources), "$.sources", "must contain at least one source")
    source_ids: set[str] = set()
    if isinstance(sources, list):
        for index, source in enumerate(sources):
            location = f"$.sources[{index}]"
            if not isinstance(source, dict):
                errors.add(location, "must be an object")
                continue
            source_id = source.get("id")
            errors.require(bool(ID_PATTERN.fullmatch(str(source_id or ""))), f"{location}.id", "invalid identifier")
            errors.require(source_id not in source_ids, f"{location}.id", "duplicate source identifier")
            source_ids.add(source_id)
            errors.require(is_nonempty_string(source.get("title")), f"{location}.title", "must be non-empty")
            errors.require(is_https_url(source.get("url")), f"{location}.url", "must be an HTTPS URL")
            errors.require(isinstance(source.get("authoritative"), bool), f"{location}.authoritative", "must be boolean")

    requirements = data.get("requirements", [])
    errors.require(isinstance(requirements, list) and bool(requirements), "$.requirements", "must contain at least one requirement")
    requirement_ids: set[str] = set()
    evidence_ids: set[str] = set()
    check_ids: set[str] = set()

    if isinstance(requirements, list):
        for index, requirement in enumerate(requirements):
            location = f"$.requirements[{index}]"
            if not isinstance(requirement, dict):
                errors.add(location, "must be an object")
                continue
            requirement_id = requirement.get("id")
            errors.require(bool(ID_PATTERN.fullmatch(str(requirement_id or ""))), f"{location}.id", "invalid identifier")
            errors.require(requirement_id not in requirement_ids, f"{location}.id", "duplicate requirement identifier")
            requirement_ids.add(requirement_id)
            requirement_type = requirement.get("type")
            errors.require(requirement_type in REQUIREMENT_TYPES, f"{location}.type", f"must be one of {sorted(REQUIREMENT_TYPES)}")
            if requirement_type == "conditional":
                errors.require(is_nonempty_string(requirement.get("condition")), f"{location}.condition", "conditional requirement must state its condition")
            errors.require(requirement.get("source_id") in source_ids, f"{location}.source_id", "must reference a declared source")
            for field in ("section", "title", "summary", "citation", "test_procedure"):
                errors.require(is_nonempty_string(requirement.get(field)), f"{location}.{field}", "must be non-empty")

            evidence_items = requirement.get("evidence")
            errors.require(isinstance(evidence_items, list), f"{location}.evidence", "must be an array")
            if isinstance(evidence_items, list):
                for evidence_index, evidence in enumerate(evidence_items):
                    evidence_location = f"{location}.evidence[{evidence_index}]"
                    if not isinstance(evidence, dict):
                        errors.add(evidence_location, "must be an object")
                        continue
                    evidence_id = evidence.get("id")
                    errors.require(bool(ID_PATTERN.fullmatch(str(evidence_id or ""))), f"{evidence_location}.id", "invalid identifier")
                    errors.require(evidence_id not in evidence_ids, f"{evidence_location}.id", "duplicate evidence identifier")
                    evidence_ids.add(evidence_id)
                    errors.require(evidence.get("type") in EVIDENCE_TYPES, f"{evidence_location}.type", f"must be one of {sorted(EVIDENCE_TYPES)}")
                    errors.require(evidence.get("sensitivity") in SENSITIVITIES, f"{evidence_location}.sensitivity", f"must be one of {sorted(SENSITIVITIES)}")
                    for field in ("title", "description"):
                        errors.require(is_nonempty_string(evidence.get(field)), f"{evidence_location}.{field}", "must be non-empty")
                    freshness = evidence.get("freshness_days")
                    errors.require(freshness is None or (isinstance(freshness, int) and freshness > 0), f"{evidence_location}.freshness_days", "must be null or a positive integer")

            checks = requirement.get("automated_checks")
            errors.require(isinstance(checks, list), f"{location}.automated_checks", "must be an array")
            if isinstance(checks, list):
                for check_index, check in enumerate(checks):
                    check_location = f"{location}.automated_checks[{check_index}]"
                    if not isinstance(check, dict):
                        errors.add(check_location, "must be an object")
                        continue
                    check_id = check.get("id")
                    errors.require(bool(ID_PATTERN.fullmatch(str(check_id or ""))), f"{check_location}.id", "invalid identifier")
                    errors.require(check_id not in check_ids, f"{check_location}.id", "duplicate automated-check identifier")
                    check_ids.add(check_id)
                    for field in ("collector", "observation", "result_logic", "cadence"):
                        errors.require(is_nonempty_string(check.get(field)), f"{check_location}.{field}", "must be non-empty")
                    result_logic = str(check.get("result_logic", "")).lower()
                    collector = str(check.get("collector", "")).lower()
                    uses_model_as_collector = bool(
                        re.search(r"(^|[._-])(ai|llm)([._-]|$)", collector)
                    )
                    errors.require(not uses_model_as_collector, f"{check_location}.collector", "AI collectors cannot determine compliance status")
                    errors.require(any(term in result_logic for term in ("pass when", "fail", "pending")), f"{check_location}.result_logic", "must express deterministic status conditions")
                    errors.require(isinstance(check.get("review_required"), bool), f"{check_location}.review_required", "must be boolean")

    milestone_ids: set[str] = set()
    milestones = data.get("milestones", [])
    errors.require(isinstance(milestones, list), "$.milestones", "must be an array")
    if isinstance(milestones, list):
        for index, milestone in enumerate(milestones):
            location = f"$.milestones[{index}]"
            if not isinstance(milestone, dict):
                errors.add(location, "must be an object")
                continue
            milestone_id = milestone.get("id")
            errors.require(bool(ID_PATTERN.fullmatch(str(milestone_id or ""))), f"{location}.id", "invalid identifier")
            errors.require(milestone_id not in milestone_ids, f"{location}.id", "duplicate milestone identifier")
            milestone_ids.add(milestone_id)
            errors.require(milestone.get("source_id") in source_ids, f"{location}.source_id", "must reference a declared source")
            for field in ("title", "due_at", "applies_when", "citation"):
                errors.require(is_nonempty_string(milestone.get(field)), f"{location}.{field}", "must be non-empty")

    return errors.messages


def main() -> int:
    if not SCHEMA_PATH.exists():
        print(f"missing schema: {SCHEMA_PATH.relative_to(ROOT)}", file=sys.stderr)
        return 1
    try:
        json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"invalid schema JSON: {exc}", file=sys.stderr)
        return 1

    paths = sorted(
        path
        for path in FRAMEWORKS.rglob("*.json")
        if "schema" not in path.relative_to(FRAMEWORKS).parts
    )
    if not paths:
        print("no framework packs found", file=sys.stderr)
        return 1

    messages = [message for path in paths for message in validate_pack(path)]
    if messages:
        print("Framework validation failed:", file=sys.stderr)
        for message in messages:
            print(f"- {message}", file=sys.stderr)
        return 1

    print(f"Validated {len(paths)} framework pack(s):")
    for path in paths:
        print(f"- {path.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
