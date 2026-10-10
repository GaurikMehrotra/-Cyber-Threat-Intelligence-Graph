"""Run from repository root: python -m app.app."""

import uvicorn

if __name__ == "__main__":
    uvicorn.run("src.api.main:app", host="127.0.0.1", port=8000, workers=1)
