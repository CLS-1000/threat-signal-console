"""Small TF-IDF cosine similarity, used by the novelty gate.

Pure Python on purpose: results are the same on every run and machine, and the
console needs no numeric libraries.
"""

from __future__ import annotations

import math
import re
from collections import Counter

TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9._-]*[a-z0-9]|[a-z0-9]")
STOPWORDS = frozenset(
    ["a", "an", "and", "are", "as", "at", "be", "by", "for", "from", "has", "have", "in", "is", "it", "its", "of", "on", "or", "that", "the", "this", "to", "was", "were", "which", "with"]
)


def tokenize(text: str) -> Counter[str]:
    return Counter(token for token in TOKEN_RE.findall(text.lower()) if token not in STOPWORDS and len(token) > 1)


class Corpus:
    """Documents keyed by ID, with TF-IDF weights computed over the whole set."""

    def __init__(self, documents: dict[str, str]):
        self._counts = {doc_id: tokenize(text) for doc_id, text in documents.items()}
        document_frequency: Counter[str] = Counter()
        for counts in self._counts.values():
            document_frequency.update(counts.keys())
        total = len(self._counts)
        # Smoothed IDF, the same formula scikit-learn uses by default.
        self._idf = {token: math.log((1 + total) / (1 + df)) + 1.0 for token, df in document_frequency.items()}
        self._vectors: dict[str, dict[str, float]] = {}

    def vector(self, doc_id: str) -> dict[str, float]:
        if doc_id not in self._vectors:
            weights = {token: count * self._idf[token] for token, count in self._counts[doc_id].items()}
            norm = math.sqrt(sum(weight * weight for weight in weights.values()))
            self._vectors[doc_id] = {token: weight / norm for token, weight in weights.items()} if norm else {}
        return self._vectors[doc_id]

    def similarity(self, first: str, second: str) -> float:
        a, b = self.vector(first), self.vector(second)
        if len(a) > len(b):
            a, b = b, a
        return sum(weight * b.get(token, 0.0) for token, weight in a.items())
