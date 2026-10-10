"""Synthetic, deterministic fixtures; tests never fetch public feeds."""

import pytest

from src.config import load_config
from src.graph.serialization import load


@pytest.fixture
def graph():
    return load("data/fixtures/graph.json")


@pytest.fixture
def cfg():
    return load_config("configs/fast_debug.yaml")
