#!/usr/bin/env python3
"""Export deterministic OpenAPI, Postman, and Swagger UI artifacts."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
API_SOURCE = ROOT / "apps" / "api"
OPENAPI_PATH = ROOT / "api" / "openapi.json"
POSTMAN_PATH = ROOT / "api" / "postman" / "watchtower.postman_collection.json"
REFERENCE_PATH = ROOT / "api" / "reference" / "index.html"
API_ROOT_PATH = ROOT / "api" / "index.html"
HTTP_METHODS = ("get", "post", "put", "patch", "delete", "head", "options")
SWAGGER_UI_VERSION = "5.30.2"


def load_openapi() -> dict[str, Any]:
    """Load the FastAPI application contract without starting its lifespan."""
    sys.path.insert(0, str(API_SOURCE))
    from watchtower_api.main import app  # pylint: disable=import-outside-toplevel

    return app.openapi()


def _postman_url(path: str, parameters: list[dict[str, Any]]) -> dict[str, Any]:
    """Translate an OpenAPI path and parameters to a Postman URL object."""
    variable_names = {
        parameter["name"]
        for parameter in parameters
        if parameter.get("in") == "path"
    }
    postman_path = [
        f":{part[1:-1]}" if part.startswith("{") and part.endswith("}") else part
        for part in path.strip("/").split("/")
    ]
    variables = [{"key": name, "value": f"<{name}>"} for name in sorted(variable_names)]
    return {
        "raw": "{{baseUrl}}/" + "/".join(postman_path),
        "host": ["{{baseUrl}}"],
        "path": postman_path,
        **({"variable": variables} if variables else {}),
    }


def _example_for_schema(schema: dict[str, Any]) -> Any:
    """Create a small deterministic request example from an OpenAPI schema."""
    if "example" in schema:
        return schema["example"]
    schema_type = schema.get("type")
    if schema_type == "object":
        example: Any = {
            name: _example_for_schema(value)
            for name, value in sorted(schema.get("properties", {}).items())
        }
    elif schema_type == "array":
        example = [_example_for_schema(schema.get("items", {}))]
    elif schema_type == "integer":
        example = 0
    elif schema_type == "number":
        example = 0.0
    elif schema_type == "boolean":
        example = False
    else:
        example = f"<{schema.get('format', 'value')}>"
    return example


def _resolve_schema(specification: dict[str, Any], schema: dict[str, Any]) -> dict[str, Any]:
    """Resolve one local component reference for a Postman example."""
    reference = schema.get("$ref")
    if not reference:
        return schema
    prefix = "#/components/schemas/"
    if not reference.startswith(prefix):
        return schema
    return specification["components"]["schemas"][reference.removeprefix(prefix)]


def build_postman(specification: dict[str, Any]) -> dict[str, Any]:
    """Build a Postman v2.1 collection from the exported OpenAPI operations."""
    groups: dict[str, list[dict[str, Any]]] = {}
    for path, path_item in sorted(specification["paths"].items()):
        path_parameters = path_item.get("parameters", [])
        for method in HTTP_METHODS:
            operation = path_item.get(method)
            if operation is None:
                continue
            parameters = [*path_parameters, *operation.get("parameters", [])]
            headers = [
                {"key": parameter["name"], "value": f"<{parameter['name']}>"}
                for parameter in parameters
                if parameter.get("in") == "header"
            ]
            request: dict[str, Any] = {
                "method": method.upper(),
                "header": headers,
                "url": _postman_url(path, parameters),
                "description": operation.get("description", ""),
            }
            content = operation.get("requestBody", {}).get("content", {})
            json_content = content.get("application/json")
            if json_content:
                schema = _resolve_schema(specification, json_content.get("schema", {}))
                request["header"].append(
                    {"key": "Content-Type", "value": "application/json"}
                )
                request["body"] = {
                    "mode": "raw",
                    "raw": json.dumps(_example_for_schema(schema), indent=2),
                    "options": {"raw": {"language": "json"}},
                }
            tag = operation.get("tags", ["other"])[0]
            groups.setdefault(tag, []).append(
                {"name": operation.get("summary", operation["operationId"]), "request": request}
            )
    return {
        "info": {
            "name": "Watchtower GRC API",
            "description": specification["info"].get("description", ""),
            "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
        },
        "variable": [{"key": "baseUrl", "value": "http://localhost:8000"}],
        "item": [
            {"name": tag, "item": items}
            for tag, items in sorted(groups.items())
        ],
    }


def swagger_reference() -> str:
    """Return a static Swagger UI page pinned to an explicit distribution version."""
    return f"""<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="referrer" content="no-referrer">
    <title>Watchtower GRC API Reference</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@{SWAGGER_UI_VERSION}/swagger-ui.css">
  </head>
  <body>
    <div id="swagger-ui"></div>
    <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@{SWAGGER_UI_VERSION}/swagger-ui-bundle.js"></script>
    <script>
      window.onload = () => SwaggerUIBundle({{
        url: "../openapi.json",
        dom_id: "#swagger-ui",
        deepLinking: true,
        displayRequestDuration: true,
        persistAuthorization: false
      }});
    </script>
  </body>
</html>
"""


def api_root() -> str:
    """Return a small landing redirect for the published API documentation."""
    return """<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta http-equiv="refresh" content="0; url=reference/">
    <title>Watchtower GRC API Reference</title>
  </head>
  <body><p><a href="reference/">Open the Watchtower GRC API reference</a>.</p></body>
</html>
"""


def serialized_outputs() -> dict[Path, str]:
    """Return all generated files and their deterministic contents."""
    specification = load_openapi()
    return {
        OPENAPI_PATH: json.dumps(specification, indent=2, sort_keys=True) + "\n",
        POSTMAN_PATH: json.dumps(build_postman(specification), indent=2) + "\n",
        REFERENCE_PATH: swagger_reference(),
        API_ROOT_PATH: api_root(),
    }


def export(check: bool) -> int:
    """Write artifacts or fail when committed artifacts are stale."""
    outputs = serialized_outputs()
    stale = [
        path
        for path, content in outputs.items()
        if not path.exists() or path.read_text(encoding="utf-8") != content
    ]
    if check:
        for path in stale:
            print(f"stale API artifact: {path.relative_to(ROOT)}")
    else:
        for path in stale:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(outputs[path], encoding="utf-8")
            print(f"updated API artifact: {path.relative_to(ROOT)}")
    for path in outputs.keys() - set(stale):
        print(f"current API artifact: {path.relative_to(ROOT)}")
    return int(check and bool(stale))


def main() -> int:
    """Parse arguments and export API artifacts."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="fail instead of writing")
    return export(parser.parse_args().check)


if __name__ == "__main__":
    raise SystemExit(main())
