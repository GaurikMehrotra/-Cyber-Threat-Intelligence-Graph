"""Create local credentials once, preserve existing user configuration."""

import os
import secrets
from pathlib import Path


def main() -> None:
    p = Path(".env")
    if p.exists():
        print("Existing .env preserved")
        return
    # Exclusive creation prevents replacing user files during concurrent setup.
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as file:
        file.write(
            "NEO4J_URI=bolt://127.0.0.1:7687\nNEO4J_USER=neo4j\nNEO4J_PASSWORD="
            + secrets.token_hex(24)
            + "\nCTIG_API_KEY="
            + secrets.token_hex(24)
            + "\nCTIG_BACKEND=neo4j\nCTIG_CONFIG=configs/default.yaml\n"
        )
    print("Created private .env with random local credentials; values not printed")


if __name__ == "__main__":
    main()
