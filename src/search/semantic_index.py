"""Persisted CPU-only embeddings and FAISS; explicit TF-IDF debug fallback."""

import hashlib
import json
from pathlib import Path

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer


class SentenceEncoder:
    def __init__(
        self,
        model: str = "sentence-transformers/all-MiniLM-L6-v2",
        batch_size: int = 16,
        revision: str = "c9745ed1d9f207416be6d2e6f8de32d1f16199bf",
    ):
        import torch
        from sentence_transformers import SentenceTransformer

        torch.set_num_threads(2)
        self.model = SentenceTransformer(
            model, revision=revision, device="cpu", trust_remote_code=False
        )
        self.batch_size = batch_size
        self.identity = model + "@" + revision

    def encode(self, texts: list[str]) -> np.ndarray:
        return np.asarray(
            self.model.encode(
                texts,
                batch_size=self.batch_size,
                normalize_embeddings=True,
                show_progress_bar=False,
            ),
            dtype="float32",
        )


class SemanticIndex:
    def __init__(
        self, directory: str | Path, mode: str = "sentence", max_documents: int = 5000, encoder=None
    ):
        if mode not in {"sentence", "tfidf"}:
            raise ValueError("Unknown index mode")
        self.path = Path(directory)
        self.mode = mode
        self.max_documents = max_documents
        self.encoder = encoder
        self.ids = []
        self.texts = []
        self.vectors = None
        self.vectorizer = None
        self.faiss_index = None

    def build(self, ids: list[str], texts: list[str]) -> None:
        if (
            len(ids) != len(texts)
            or not ids
            or len(ids) > self.max_documents
            or len(set(ids)) != len(ids)
        ):
            raise ValueError("Invalid bounded index dataset")
        texts = [t[:12000] for t in texts]
        self.path.mkdir(parents=True, exist_ok=True)
        if self.mode == "sentence" and self.encoder is None:
            self.encoder = SentenceEncoder()
        identity = (
            getattr(self.encoder, "identity", "tfidf") if self.mode == "sentence" else "tfidf"
        )
        digest = hashlib.sha256(json.dumps([ids, texts, self.mode, identity]).encode()).hexdigest()
        meta_path = self.path / "metadata.json"
        if meta_path.exists() and json.loads(meta_path.read_text()).get("digest") == digest:
            self.load()
            return
        self.ids = ids
        self.texts = texts
        if self.mode == "sentence":
            self.vectors = self.encoder.encode(texts)
        else:
            self.vectorizer = TfidfVectorizer(max_features=10000, dtype=np.float32)
            self.vectors = self.vectorizer.fit_transform(texts).toarray()
        self.vectors = np.asarray(self.vectors, dtype="float32")
        self.vectors /= np.maximum(np.linalg.norm(self.vectors, axis=1, keepdims=True), 1e-12)
        np.save(self.path / "vectors.npy", self.vectors, allow_pickle=False)
        meta_path.write_text(
            json.dumps(
                {
                    "ids": ids,
                    "texts": texts,
                    "mode": self.mode,
                    "digest": digest,
                    "identity": identity,
                }
            )
        )
        self._make_faiss()

    def _make_faiss(self) -> None:
        if self.mode != "sentence":
            return
        import faiss

        self.faiss_index = faiss.IndexFlatIP(self.vectors.shape[1])
        self.faiss_index.add(self.vectors)
        faiss.write_index(self.faiss_index, str(self.path / "index.faiss"))

    def load(self) -> None:
        meta = json.loads((self.path / "metadata.json").read_text())
        if meta["mode"] != self.mode or len(meta["ids"]) > self.max_documents:
            raise ValueError("Index config mismatch")
        self.ids = meta["ids"]
        self.texts = meta["texts"]
        self.vectors = np.load(self.path / "vectors.npy", allow_pickle=False)
        if self.mode == "tfidf":
            self.vectorizer = TfidfVectorizer(max_features=10000, dtype=np.float32)
            self.vectorizer.fit(self.texts)
        else:
            if self.encoder is None:
                self.encoder = SentenceEncoder()
            if getattr(self.encoder, "identity", "") != meta["identity"]:
                raise ValueError("Embedding model revision mismatch")
            self._make_faiss()

    def search(self, query: str, k: int = 10) -> list[dict]:
        if self.vectors is None or not 1 <= k <= 100 or len(query) > 512:
            raise ValueError("Index not loaded or query bounds exceeded")
        vector = (
            self.encoder.encode([query])
            if self.mode == "sentence"
            else self.vectorizer.transform([query]).toarray().astype("float32")
        )
        vector /= np.maximum(np.linalg.norm(vector, axis=1, keepdims=True), 1e-12)
        if self.faiss_index is not None:
            values, positions = self.faiss_index.search(vector, min(k, len(self.ids)))
            scores = values[0]
            indexes = positions[0]
        else:
            values = (self.vectors @ vector.T).ravel()
            indexes = np.argsort(-values, kind="stable")[:k]
            scores = values[indexes]
        return [
            {"id": self.ids[int(i)], "score": float(s), "mode": self.mode}
            for i, s in zip(indexes, scores, strict=True)
        ]
