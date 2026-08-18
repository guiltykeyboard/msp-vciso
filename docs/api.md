# API documentation

Watchtower's FastAPI application is the source of truth for its OpenAPI contract. The repository carries deterministic generated artifacts so self-hosters, integrators, and release reviewers do not need a running server to inspect the interface.

- [OpenAPI JSON](../api/openapi.json)
- [Postman collection](../api/postman/watchtower.postman_collection.json)
- [Swagger UI reference](../api/reference/index.html)

When the local stack is running, interactive Swagger UI is available at `http://localhost:8000/docs`, ReDoc at `http://localhost:8000/redoc`, and raw JSON at `http://localhost:8000/openapi.json`.

Regenerate committed artifacts after changing an endpoint:

```bash
python tools/export_api_artifacts.py
```

CI runs the same generator in check mode and fails if an endpoint change is not accompanied by updated OpenAPI and Postman files:

```bash
python tools/export_api_artifacts.py --check
```

The published Swagger reference uses the committed OpenAPI file, not a live production endpoint. The current tenant headers are development-only and are documented as such. They will be replaced by the production OIDC/session security scheme before customer data is used.
