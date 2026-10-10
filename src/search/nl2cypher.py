"""Optional LLM chooses templates; never executes generated Cypher."""

import json
from typing import Protocol

from src.graph.queries import QUERIES
from src.security.cypher_guard import validate
from src.security.sanitize import llm_context


class LLM(Protocol):
    def complete(self, context: dict[str, str]) -> str: ...


class FakeLLM:
    def complete(self, context: dict[str, str]) -> str:
        return json.dumps(
            {"template": "search", "params": {"text": "phishing", "offset": 0, "limit": 10}}
        )


def preview(question: str, llm: LLM) -> dict:
    result = json.loads(llm.complete(llm_context(question)))
    if set(result) != {"template", "params"} or result["template"] not in QUERIES:
        raise ValueError("Invalid LLM result")
    query = QUERIES[result["template"]]
    validate(query, result["params"])
    return {
        "template": result["template"],
        "cypher": query,
        "params": result["params"],
        "executed": False,
        "requires_explicit_execute": True,
    }
