"""Contract tests for generated public API artifacts."""

import json

from tools import export_api_artifacts


def test_committed_api_artifacts_are_current() -> None:
    """Every committed API artifact matches the FastAPI source contract."""
    for path, expected in export_api_artifacts.serialized_outputs().items():
        assert path.read_text(encoding="utf-8") == expected


def test_postman_collection_covers_every_openapi_operation() -> None:
    """The generated Postman collection includes every documented operation."""
    specification = json.loads(export_api_artifacts.OPENAPI_PATH.read_text(encoding="utf-8"))
    collection = json.loads(export_api_artifacts.POSTMAN_PATH.read_text(encoding="utf-8"))
    openapi_operations = {
        operation["operationId"]
        for path_item in specification["paths"].values()
        for method, operation in path_item.items()
        if method in export_api_artifacts.HTTP_METHODS
    }
    postman_request_names = {
        item["request"]["url"]["raw"] + " " + item["request"]["method"]
        for group in collection["item"]
        for item in group["item"]
    }

    assert len(postman_request_names) == len(openapi_operations)


def test_public_contract_contains_no_supplied_customer_hostname() -> None:
    """Reference specifications must not leak a supplied private Hudu hostname."""
    assert "docs.itechwv.com" not in export_api_artifacts.OPENAPI_PATH.read_text(
        encoding="utf-8"
    )
