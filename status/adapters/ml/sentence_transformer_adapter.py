"""Векторный поиск кандидатов: TF-IDF по символьным триграммам (ONNX не обязателен)."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any

import numpy as np
from numpy.typing import NDArray

from status.adapters.runtime_paths import data_dir
from status.core.constants import EMBEDDING_MODEL_NAME
from status.ports.ml_port import VectorizerPort
from status.core.models import Software

if TYPE_CHECKING:
    import onnxruntime as ort
    from transformers import PreTrainedTokenizerBase

logger = logging.getLogger(__name__)


def _models_dir() -> Path:
    return data_dir() / "models"


class FallbackTfIdfVectorizer:

    def __init__(
        self,
        n_gram: int = 3,
        max_features: int = 2000,
        select_by: str = "frequency",
    ) -> None:
        self.n_gram = n_gram
        self.max_features = max_features
        self.select_by = select_by
        self.vocab: dict[str, int] = {}
        self.idf: NDArray[np.float32] = np.zeros(0, dtype=np.float32)

    def _get_ngrams(self, text: str) -> list[str]:
        val = " " + text.lower().strip() + " "
        return [val[i:i + self.n_gram] for i in range(len(val) - self.n_gram + 1)]

    def fit_transform(self, texts: list[str]) -> NDArray[np.float32]:
        doc_freqs: dict[str, int] = {}
        for text in texts:
            ngrams = set(self._get_ngrams(text))
            for ng in ngrams:
                doc_freqs[ng] = doc_freqs.get(ng, 0) + 1
        
        keep_common = self.select_by != "rarity"
        sorted_ngrams = sorted(
            doc_freqs.items(), key=lambda item: item[1], reverse=keep_common
        )[: self.max_features]
        self.vocab = {ng: idx for idx, (ng, _) in enumerate(sorted_ngrams)}
        
        n_docs = len(texts)
        self.idf = np.zeros(len(self.vocab), dtype=np.float32)
        for ng, idx in self.vocab.items():
            df = doc_freqs[ng]
            self.idf[idx] = np.log((1 + n_docs) / (1 + df)) + 1.0
            
        return self.transform(texts)

    def transform(self, texts: list[str]) -> NDArray[np.float32]:
        vectors = np.zeros((len(texts), len(self.vocab)), dtype=np.float32)
        for i, text in enumerate(texts):
            ngrams = self._get_ngrams(text)
            for ng in ngrams:
                if ng in self.vocab:
                    vectors[i, self.vocab[ng]] += 1.0
            vectors[i] = vectors[i] * self.idf
            
        norms = np.linalg.norm(vectors, axis=1, keepdims=True)
        return vectors / np.clip(norms, a_min=1e-9, a_max=None)


class SentenceTransformerAdapter(VectorizerPort):

    def __init__(
        self,
        model_name: str = EMBEDDING_MODEL_NAME,
        vocab_mode: str = "frequency",
        max_features: int = 2000,
    ) -> None:
        self._model_name = model_name
        self._vocab_mode = vocab_mode
        self._max_features = max_features
        self._session: ort.InferenceSession | None = None
        self._tokenizer: PreTrainedTokenizerBase | None = None
        self._index_embeddings: NDArray[np.float32] | None = None
        self._software_list: list[Software] = []
        model_onnx = _models_dir() / model_name / "model.onnx"
        self._fallback_mode: bool = not model_onnx.is_file()
        self._fallback_vectorizer: FallbackTfIdfVectorizer | None = None
        if self._fallback_mode:
            logger.info("Official vectorizer: NumPy char 3-gram TF-IDF")

    def _ensure_model(self) -> tuple[Any, Any]:
        if self._fallback_mode:
            return None, None

        if self._session is None or self._tokenizer is None:
            try:
                import onnxruntime as ort
                from transformers import AutoTokenizer
            except Exception as exc:
                logger.info("ONNX extras unavailable, using TF-IDF: %s", exc)
                self._fallback_mode = True
                return None, None

            local_path = _models_dir() / self._model_name
            model_onnx_path = local_path / "model.onnx"
            if not model_onnx_path.is_file():
                logger.info("ONNX model not found, using official TF-IDF")
                self._fallback_mode = True
                return None, None
            logger.info("Loading optional ONNX model: %s", local_path)
            self._session = ort.InferenceSession(str(model_onnx_path))
            self._tokenizer = AutoTokenizer.from_pretrained(str(local_path))
            logger.info("ONNX model loaded")
        return self._session, self._tokenizer

    def encode(self, texts: list[str]) -> NDArray[np.float32]:
        if self._fallback_mode:
            if self._fallback_vectorizer is None:
                self._fallback_vectorizer = FallbackTfIdfVectorizer(
                    max_features=self._max_features, select_by=self._vocab_mode
                )
                return self._fallback_vectorizer.fit_transform(texts)
            return self._fallback_vectorizer.transform(texts)
            
        try:
            session, tokenizer = self._ensure_model()
            if self._fallback_mode:
                return self.encode(texts)
        except Exception as e:
            logger.info("ONNX init failed, using TF-IDF: %s", e)
            self._fallback_mode = True
            return self.encode(texts)

        try:
            inputs = tokenizer(
                texts, 
                padding=True, 
                truncation=True, 
                max_length=128, 
                return_tensors="np"
            )
            ort_inputs = {
                "input_ids": inputs["input_ids"].astype(np.int64),
                "attention_mask": inputs["attention_mask"].astype(np.int64)
            }
            if "token_type_ids" in inputs:
                ort_inputs["token_type_ids"] = inputs["token_type_ids"].astype(np.int64)
            else:
                ort_inputs["token_type_ids"] = np.zeros_like(ort_inputs["input_ids"])

            outputs = session.run(None, ort_inputs)
            last_hidden_state = outputs[0]

            attention_mask = inputs["attention_mask"]
            input_mask_expanded = np.expand_dims(attention_mask, -1).astype(np.float32)
            sum_embeddings = np.sum(last_hidden_state * input_mask_expanded, axis=1)
            sum_mask = np.clip(input_mask_expanded.sum(axis=1), a_min=1e-9, a_max=None)
            embeddings = sum_embeddings / sum_mask

            norms = np.linalg.norm(embeddings, axis=1, keepdims=True)
            return (embeddings / np.clip(norms, a_min=1e-9, a_max=None)).astype(np.float32)
        except Exception as e:
            logger.info("ONNX encode failed, using TF-IDF: %s", e)
            self._fallback_mode = True
            if self._fallback_vectorizer is None and self._software_list:
                names = [
                    f"{sw.vendor} {sw.name}".strip() if sw.vendor else sw.name
                    for sw in self._software_list
                ]
                self._fallback_vectorizer = FallbackTfIdfVectorizer(
                    max_features=self._max_features, select_by=self._vocab_mode
                )
                self._index_embeddings = self._fallback_vectorizer.fit_transform(names)
            return self.encode(texts)

    def build_index(self, software_list: list[Software]) -> None:
        self._software_list = list(software_list)
        names = [
            f"{sw.vendor} {sw.name}".strip() if sw.vendor else sw.name
            for sw in software_list
        ]
        logger.info("Encoding %d software entries...", len(names))
        
        try:
            self._ensure_model()
        except Exception as e:
            logger.info("ONNX unavailable, building TF-IDF index: %s", e)
            self._fallback_mode = True

        if self._fallback_mode:
            logger.info("Building NumPy TF-IDF index...")
            self._fallback_vectorizer = FallbackTfIdfVectorizer(
                    max_features=self._max_features, select_by=self._vocab_mode
                )
            self._index_embeddings = self._fallback_vectorizer.fit_transform(names)
        else:
            self._index_embeddings = self.encode(names)
        logger.info("Index built: %d entries", len(self._software_list))

    def search(self, query: str, top_n: int = 10) -> list[tuple[Software, float]]:
        if self._index_embeddings is None or not self._software_list:
            logger.warning("Search called on unbuilt index")
            return []

        query_emb = self.encode([query])
        scores = np.dot(query_emb, self._index_embeddings.T)[0]

        candidate_indices = np.where(scores >= 0.0)[0]
        if len(candidate_indices) == 0:
            return []

        sorted_idx = candidate_indices[np.argsort(scores[candidate_indices])[::-1]][:top_n]
        return [(self._software_list[idx], float(scores[idx])) for idx in sorted_idx]

    def batch_search(
        self,
        queries: list[str],
        top_n: int = 10,
    ) -> list[list[tuple[Software, float]]]:
        if not queries:
            return []

        if self._index_embeddings is None or not self._software_list:
            logger.warning("Batch search called on unbuilt index")
            return [[] for _ in queries]

        query_embs = self.encode(queries)
        all_scores = np.dot(query_embs, self._index_embeddings.T)

        all_results: list[list[tuple[Software, float]]] = []
        for i in range(len(queries)):
            scores = all_scores[i]
            candidate_indices = np.where(scores >= 0.0)[0]
            if len(candidate_indices) == 0:
                all_results.append([])
                continue

            sorted_idx = candidate_indices[np.argsort(scores[candidate_indices])[::-1]][:top_n]
            results = [(self._software_list[idx], float(scores[idx])) for idx in sorted_idx]
            all_results.append(results)

        return all_results
