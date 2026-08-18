"""Development entry point for ``python -m watchtower_api``."""

import uvicorn


if __name__ == "__main__":
    uvicorn.run("watchtower_api.main:app", host="0.0.0.0", port=8000)
