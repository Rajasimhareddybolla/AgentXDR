"""Pluggable embedding engines for AgentXDR semantic drift detection.

Provides:
- BaseEmbeddingEngine: Abstract base class for embedding providers.
- DeterministicEmbeddingEngine: Ultra-fast offline n-gram hash projection.
- OnnxEmbeddingEngine: Local CPU ONNX inference using live/cached BAAI/bge-small-en-v1.5.
"""

from __future__ import annotations

import abc
import hashlib
import os
import re
from pathlib import Path
from typing import List, Literal, Optional, Tuple, Union

import numpy as np


class BaseEmbeddingEngine(abc.ABC):
    """Abstract base class for semantic embedding engines."""

    @property
    @abc.abstractmethod
    def dimension(self) -> int:
        """Return the vector embedding dimension D."""
        pass

    @abc.abstractmethod
    def encode(self, texts: List[str]) -> np.ndarray:
        """Encode a list of texts into a 2D numpy array of shape (N, D).

        Guarantees:
        - Output dtype is float32.
        - Each row vector is L2-normalized (norm == 1.0 or 0.0 for empty input).
        - If texts is empty, returns array of shape (0, D).
        """
        pass

    def encode_one(self, text: str) -> np.ndarray:
        """Encode a single text string into a 1D numpy array of shape (D,)."""
        return self.encode([text])[0]

    def similarity(self, text_a: str, text_b: str) -> float:
        """Compute cosine similarity between two texts in range [-1.0, 1.0].

        Because vectors are L2-normalized, cosine similarity is the dot product.
        """
        v_a = self.encode_one(text_a)
        v_b = self.encode_one(text_b)
        norm_a = float(np.linalg.norm(v_a))
        norm_b = float(np.linalg.norm(v_b))
        if norm_a < 1e-12 or norm_b < 1e-12:
            return 0.0
        dot = float(np.dot(v_a, v_b))
        return float(max(-1.0, min(1.0, dot)))

    def cosine_distance(self, text_a: str, text_b: str) -> float:
        """Compute cosine distance between two texts bounded in [0.0, 1.0]."""
        sim = self.similarity(text_a, text_b)
        return float(max(0.0, min(1.0, 1.0 - sim)))


class DeterministicEmbeddingEngine(BaseEmbeddingEngine):
    """Ultra-fast offline n-gram hash projection embedding engine.

    Generates deterministic count-sketch projections of word unigrams, word bigrams,
    and character 3-grams into a fixed D-dimensional hypersphere with L2 normalization.
    """

    def __init__(
        self,
        dimension: int = 384,
        seed: int = 42,
    ) -> None:
        self._dimension = dimension
        self.seed = seed

    @property
    def dimension(self) -> int:
        return self._dimension

    def encode(self, texts: List[str]) -> np.ndarray:
        if not texts:
            return np.empty((0, self._dimension), dtype=np.float32)

        vectors = np.zeros((len(texts), self._dimension), dtype=np.float32)
        for idx, text in enumerate(texts):
            features: List[str] = []
            tokens = re.findall(r"\w+", text.lower())
            # Word unigrams
            for t in tokens:
                features.append(t)
            # Word bigrams
            for i in range(len(tokens) - 1):
                features.append(f"{tokens[i]}_{tokens[i + 1]}")
            # Character 3-grams
            cleaned = text.strip().lower()
            for i in range(len(cleaned) - 2):
                features.append(cleaned[i : i + 3])

            if not features:
                continue

            vec = np.zeros(self._dimension, dtype=np.float32)
            for feat in features:
                feat_bytes = f"{feat}_{self.seed}".encode("utf-8")
                digest = hashlib.sha256(feat_bytes).digest()
                dim_idx = int.from_bytes(digest[:4], "little") % self._dimension
                sign = 1.0 if (digest[4] & 1) else -1.0
                vec[dim_idx] += sign

            norm = np.linalg.norm(vec)
            if norm > 1e-12:
                vectors[idx] = vec / norm

        return vectors


class OnnxEmbeddingEngine(BaseEmbeddingEngine):
    """Local CPU embedding engine powered by ONNX Runtime and Hugging Face tokenizers.

    Downloads or loads model weights for BAAI/bge-small-en-v1.5 (or any compatible
    BERT/RoBERTa ONNX model), executes CPU inference, performs mean pooling over
    token embeddings using attention mask (or CLS token pooling), and L2-normalizes the output.
    """

    DEFAULT_MODEL_NAME = "BAAI/bge-small-en-v1.5"

    def __init__(
        self,
        model_name: str = DEFAULT_MODEL_NAME,
        cache_dir: Optional[Union[str, Path]] = None,
        local_files_only: bool = False,
        max_length: int = 512,
        num_threads: int = 0,
        lazy_load: bool = False,
        pooling_strategy: Literal["mean", "cls"] = "mean",
    ) -> None:
        self.model_name = str(model_name)
        self.cache_dir = str(cache_dir) if cache_dir else None
        self.local_files_only = local_files_only
        self.max_length = max_length
        self.num_threads = num_threads
        self.pooling_strategy = pooling_strategy

        self._session = None
        self._tokenizer = None
        self._dimension: int = 384

        if not lazy_load:
            self._ensure_loaded()

    @property
    def dimension(self) -> int:
        return self._dimension

    @property
    def is_loaded(self) -> bool:
        return self._session is not None and self._tokenizer is not None

    def _ensure_loaded(self) -> None:
        if self.is_loaded:
            return

        import onnxruntime as ort
        from tokenizers import Tokenizer

        onnx_path, tok_path = self._resolve_model_files()

        # Initialize Tokenizer with fast Rust backend
        try:
            tokenizer = Tokenizer.from_file(tok_path)
            tokenizer.enable_padding(pad_id=0, pad_token="[PAD]")
            tokenizer.enable_truncation(max_length=self.max_length)
            self._tokenizer = tokenizer
        except Exception as e:
            raise RuntimeError(f"Failed to load tokenizer from {tok_path}: {e}") from e

        # Initialize ONNX Runtime Session on CPU
        try:
            opts = ort.SessionOptions()
            opts.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
            if self.num_threads > 0:
                opts.intra_op_num_threads = self.num_threads
                opts.inter_op_num_threads = self.num_threads

            session = ort.InferenceSession(
                onnx_path,
                sess_options=opts,
                providers=["CPUExecutionProvider"],
            )
            self._session = session

            # Inspect output dimension
            out_shape = session.get_outputs()[0].shape
            if len(out_shape) >= 2 and isinstance(out_shape[-1], int):
                self._dimension = out_shape[-1]
        except Exception as e:
            raise RuntimeError(f"Failed to load ONNX model from {onnx_path}: {e}") from e

    def _resolve_model_files(self) -> Tuple[str, str]:
        p = Path(self.model_name)
        if p.is_dir():
            onnx_path = p / "onnx" / "model.onnx"
            if not onnx_path.exists():
                onnx_path = p / "model.onnx"
            tok_path = p / "tokenizer.json"
            if not onnx_path.is_file():
                raise FileNotFoundError(f"ONNX model file not found in directory: {p}")
            if not tok_path.is_file():
                raise FileNotFoundError(f"tokenizer.json not found in directory: {p}")
            return str(onnx_path), str(tok_path)
        elif p.is_file():
            onnx_path = p
            tok_path = p.parent / "tokenizer.json"
            if not tok_path.is_file():
                raise FileNotFoundError(f"tokenizer.json not found adjacent to model file: {p.parent}")
            return str(onnx_path), str(tok_path)

        # Resolve from Hugging Face Hub
        try:
            from huggingface_hub import hf_hub_download
        except ImportError as e:
            raise ImportError(
                "huggingface_hub is required for downloading ONNX model weights. "
                "Install with 'pip install huggingface-hub'."
            ) from e

        try:
            # First attempt onnx/model.onnx, fallback to model.onnx
            try:
                onnx_path = hf_hub_download(
                    repo_id=self.model_name,
                    filename="onnx/model.onnx",
                    cache_dir=self.cache_dir,
                    local_files_only=self.local_files_only,
                )
            except Exception:
                onnx_path = hf_hub_download(
                    repo_id=self.model_name,
                    filename="model.onnx",
                    cache_dir=self.cache_dir,
                    local_files_only=self.local_files_only,
                )

            tok_path = hf_hub_download(
                repo_id=self.model_name,
                filename="tokenizer.json",
                cache_dir=self.cache_dir,
                local_files_only=self.local_files_only,
            )
            return onnx_path, tok_path
        except Exception as e:
            raise RuntimeError(
                f"Failed to download/locate ONNX model files for '{self.model_name}': {e}. "
                f"Verify network connectivity, repository name, or provide a local cache_dir."
            ) from e

    def encode(self, texts: List[str]) -> np.ndarray:
        if not texts:
            return np.empty((0, self._dimension), dtype=np.float32)

        self._ensure_loaded()

        # Tokenize batch
        encodings = self._tokenizer.encode_batch(texts)
        input_ids = np.array([e.ids for e in encodings], dtype=np.int64)
        attention_mask = np.array([e.attention_mask for e in encodings], dtype=np.int64)
        token_type_ids = np.array([e.type_ids for e in encodings], dtype=np.int64)

        # Bind inputs expected by session
        feed_dict = {}
        for inp in self._session.get_inputs():
            if inp.name == "input_ids":
                feed_dict["input_ids"] = input_ids
            elif inp.name == "attention_mask":
                feed_dict["attention_mask"] = attention_mask
            elif inp.name == "token_type_ids":
                feed_dict["token_type_ids"] = token_type_ids

        # Run inference on CPU
        raw_outputs = self._session.run(None, feed_dict)
        hidden_states = raw_outputs[0]  # shape: (batch_size, seq_len, dimension)

        # Pooling
        if len(hidden_states.shape) == 3:
            if self.pooling_strategy == "cls":
                pooled = hidden_states[:, 0, :]
            else:  # "mean"
                mask_expanded = np.expand_dims(attention_mask, -1).astype(np.float32)
                sum_embeddings = np.sum(hidden_states * mask_expanded, axis=1)
                sum_mask = np.clip(mask_expanded.sum(axis=1), a_min=1e-9, a_max=None)
                pooled = sum_embeddings / sum_mask
        else:
            pooled = hidden_states

        # L2 Normalization
        norms = np.clip(np.linalg.norm(pooled, axis=1, keepdims=True), a_min=1e-12, a_max=None)
        return (pooled / norms).astype(np.float32)
