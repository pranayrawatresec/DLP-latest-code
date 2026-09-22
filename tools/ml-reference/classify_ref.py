"""The torch-free reference implementation of the DLP document classifier.

Why this file exists
--------------------

The detection engine that ships is Rust (``dlp-agent/src/``). Rust cannot be
diffed against a Python notebook, so something has to say authoritatively what
"correct" means for every step the Rust port has to reproduce byte for byte:
truncate -> tokenize -> chunk -> pad -> run -> softmax -> argmax. This module is
that statement. ``gen_golden_vectors.py`` freezes its output into
``dlp-agent/tests/fixtures/ml-golden-vectors.json`` and the Rust tests are gated
against that fixture.

Why it does not simply call ``Document_classification/predict.py``
------------------------------------------------------------------

``predict.py`` imports ``ai_classifier.inference.text``, which imports torch and
transformers on the way in -- a multi-gigabyte dependency tree that does not
belong on an engineer's box, on CI, or anywhere near an air-gapped build. This
file needs onnxruntime, numpy and tokenizers, and nothing else.

What it does NOT reimplement
----------------------------

The chunker. Chunk geometry is the one part of the pipeline where a subtle
disagreement (an off-by-one in the overlap carry, a different sentence regex)
changes the ids the model sees and therefore the answer, silently. So the
AUTHORITATIVE module ``ai_classifier/training/chunking.py`` is loaded DIRECTLY
BY PATH with importlib, deliberately bypassing ``ai_classifier/__init__.py``
which would drag torch in. That module is pure stdlib (re, statistics,
dataclasses, typing), so it imports clean, and this reference therefore chunks
with the same code that trained the model rather than with a copy of it.

The one adapter needed is a shim around ``tokenizers.Tokenizer``: the chunker
calls its tokenizer as ``tok(text, add_special_tokens=..., truncation=...)`` and
reads ``["input_ids"]`` -- the HuggingFace *transformers* calling convention.
``tokenizers.Tokenizer`` (the Rust fast tokenizer, no torch) exposes
``.encode(...).ids`` instead. :class:`FastTokenizerShim` is that one adapter and
is the whole of the difference.

Everything after the chunker -- padding to the longest chunk in the call, int64
feeds, one ``run()`` per document, softmax, argmax -- is done here because the
ONNX graph already performs the encoder pass, the per-chunk [CLS] mean pooling
and the classification head. The graph emits ``logits[1, 29]``: every chunk fed
in one call is one document.

Nothing here logs document text. Ids, counts and scores only -- the same rule
the agent obeys, applied to the tool that gates it.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

import numpy as np

# --------------------------------------------------------------------- #
# Where the artifacts live. This file sits at tools/ml-reference/, so the
# repository root is two directories up. Everything is resolved from there so
# the script works from any working directory.
# --------------------------------------------------------------------- #
REPO_ROOT = Path(__file__).resolve().parents[2]
CLASSIFIER_ROOT = REPO_ROOT / "Document_classification"
CHUNKING_MODULE = CLASSIFIER_ROOT / "ai_classifier" / "training" / "chunking.py"
DEFAULT_MODEL = CLASSIFIER_ROOT / "model" / "model.onnx"
DEFAULT_SIDECAR = CLASSIFIER_ROOT / "model" / "model.onnx.json"
DEFAULT_TOKENIZER = CLASSIFIER_ROOT / "backbone" / "tokenizer.json"

#: Chunk geometry defaults. The sidecar carries these values; they are repeated
#: here so a sidecar missing a key fails loudly at the wrong-answer level rather
#: than silently chunking to some library default.
DEFAULT_CHUNKING = {
    "max_tokens": 512,
    "overlap_tokens": 64,
    "min_tokens": 32,
    "micro_batch_size": 8,
    "aggregation": "mean",
}

#: The character bound applied before a single token exists. Truncating less
#: than training did would feed the model text it was never trained to see.
DEFAULT_MAX_CHARS = 200000

#: The id the batch is padded with. [PAD] in the bundled WordPiece vocabulary.
PAD_ID = 0


class EmptyTextError(ValueError):
    """Raised when the submitted text holds nothing to classify."""


# --------------------------------------------------------------------- #
# The authoritative chunker, loaded without its package
# --------------------------------------------------------------------- #


def load_chunking_module() -> Any:
    """Import ``chunking.py`` by path, bypassing the package ``__init__``.

    ``import ai_classifier.training.chunking`` would execute
    ``ai_classifier/__init__.py`` and ``ai_classifier/training/__init__.py``,
    both of which reach for torch. Loading the file directly gives the same
    module object with none of that: the file itself imports only re,
    statistics, dataclasses and typing.

    Returns:
        The loaded ``chunking`` module.

    Raises:
        FileNotFoundError: If the authoritative chunker is not where it belongs.
        ImportError: If it cannot be executed.
    """
    if not CHUNKING_MODULE.is_file():
        raise FileNotFoundError(
            f"The authoritative chunker is missing: {CHUNKING_MODULE}. This "
            "reference deliberately does not carry its own copy."
        )

    spec = importlib.util.spec_from_file_location(
        "dlp_reference_chunking", CHUNKING_MODULE
    )
    if spec is None or spec.loader is None:
        raise ImportError(f"Could not build an import spec for {CHUNKING_MODULE}")

    module = importlib.util.module_from_spec(spec)
    # Registered before execution so the dataclasses defined inside it resolve
    # their own module, as they would under a normal import.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class FastTokenizerShim:
    """Makes a ``tokenizers.Tokenizer`` answer the transformers call convention.

    :class:`~chunking.DocumentChunker` uses exactly one tokenizer API::

        tok(text, add_special_tokens=..., truncation=...)["input_ids"]

    and nothing else -- no attention masks, no offsets, no padding, no batching.
    Supplying that one call is all it takes to run the frozen chunker on the
    torch-free fast tokenizer, which is why this shim is four lines of substance
    rather than a tokenizer reimplementation.

    Attributes:
        tokenizer: The underlying ``tokenizers.Tokenizer``.
    """

    def __init__(self, tokenizer: Any) -> None:
        """Wrap a fast tokenizer.

        Args:
            tokenizer: A ``tokenizers.Tokenizer`` loaded from tokenizer.json.
        """
        self.tokenizer = tokenizer

    def __call__(
        self,
        text: str,
        add_special_tokens: bool = True,
        truncation: bool = False,
        **_ignored: Any,
    ) -> Mapping[str, list[int]]:
        """Encode one string.

        Args:
            text: The fragment to encode.
            add_special_tokens: Whether the post-processor wraps the ids in
                [CLS]/[SEP]. The chunker calls this both ways: False for content,
                True once at construction to *measure* what the wrapper adds.
            truncation: Always False here. The bundled tokenizer.json declares no
                truncation, and the chunker's whole purpose is that nothing is
                truncated at the tokenizer.
            **_ignored: Swallowed so a future chunker keyword does not explode
                this shim; nothing else is consulted.

        Returns:
            A mapping with a single ``input_ids`` key, which is all the chunker
            reads.
        """
        encoding = self.tokenizer.encode(
            text, add_special_tokens=bool(add_special_tokens)
        )
        return {"input_ids": list(encoding.ids)}


# --------------------------------------------------------------------- #
# The classifier
# --------------------------------------------------------------------- #


class ReferenceClassifier:
    """A loaded ONNX model plus the frozen chunker, ready to classify text.

    One instance serves any number of documents and keeps nothing between calls,
    so a golden-vector run loads the 256 MB graph once.

    Attributes:
        labels: The 29 label ids, index-ordered and frozen.
        label_names: Label id to display name.
        max_chars: The truncation bound applied before tokenization.
        model_path: The ONNX graph being served.
    """

    def __init__(
        self,
        *,
        session: Any,
        chunker: Any,
        labels: Sequence[str],
        label_names: Mapping[str, str],
        max_chars: int,
        model_path: Path,
        model_version: str,
    ) -> None:
        """Hold an assembled pipeline. Built through :meth:`load`."""
        self._session = session
        self._chunker = chunker
        self.labels = tuple(labels)
        self.label_names = dict(label_names)
        self.max_chars = max_chars
        self.model_path = model_path
        self.model_version = model_version

    @classmethod
    def load(
        cls,
        *,
        model: Path = DEFAULT_MODEL,
        sidecar: Path = DEFAULT_SIDECAR,
        tokenizer: Path = DEFAULT_TOKENIZER,
        providers: Sequence[str] | None = None,
    ) -> "ReferenceClassifier":
        """Assemble the pipeline.

        The label space and the chunk geometry are read from the sidecar written
        beside the graph, never from a configuration file, so neither can drift
        from the weights.

        Args:
            model: The exported ONNX graph.
            sidecar: ``model.onnx.json``, carrying labels and chunk geometry.
            tokenizer: The bundled HuggingFace fast tokenizer.
            providers: ONNX Runtime execution providers. CPU only by default:
                the agent runs on employee PCs with no GPU, and CPU is what the
                golden vectors must be reproducible on.

        Returns:
            The loaded classifier.

        Raises:
            FileNotFoundError: If an artifact is missing.
        """
        import onnxruntime as ort  # imported late so --help works without it
        from tokenizers import Tokenizer

        for path in (model, sidecar, tokenizer):
            if not Path(path).is_file():
                raise FileNotFoundError(f"Missing artifact: {path}")

        block = json.loads(Path(sidecar).read_text(encoding="utf-8"))
        chunking_block = {**DEFAULT_CHUNKING, **(block.get("chunking") or {})}

        chunking = load_chunking_module()
        settings = chunking.ChunkingSettings(
            max_tokens=int(chunking_block["max_tokens"]),
            overlap_tokens=int(chunking_block["overlap_tokens"]),
            min_tokens=int(chunking_block["min_tokens"]),
            micro_batch_size=int(chunking_block["micro_batch_size"]),
            aggregation=str(chunking_block["aggregation"]),
            # Only affects the backward pass, which inference does not have.
            gradient_checkpointing=False,
        )

        shim = FastTokenizerShim(Tokenizer.from_file(str(tokenizer)))
        chunker = chunking.DocumentChunker(shim, settings)

        session = ort.InferenceSession(
            str(model), providers=list(providers or ("CPUExecutionProvider",))
        )

        return cls(
            session=session,
            chunker=chunker,
            labels=block["labels"],
            label_names=block.get("label_names") or {},
            max_chars=int(block.get("max_chars") or DEFAULT_MAX_CHARS),
            model_path=Path(model),
            model_version=str(block.get("model_version") or ""),
        )

    # ----------------------------------------------------------------- #
    # Prediction
    # ----------------------------------------------------------------- #

    def chunk(self, raw_text: str) -> tuple[tuple[int, ...], ...]:
        """Truncate and chunk, stopping short of inference.

        Split out because the golden-vector generator needs the chunk ids
        themselves -- which are what the Rust port is actually gated on -- and
        because a chunk-geometry test should not pay for a forward pass.

        Args:
            raw_text: The document text, as extracted upstream.

        Returns:
            The chunks in document order, each already wrapped in [CLS]/[SEP].

        Raises:
            EmptyTextError: If nothing but whitespace survives truncation.
        """
        text = self.prepare(raw_text)
        return self._chunker.chunk(text)

    def prepare(self, raw_text: str) -> str:
        """Apply the two pre-tokenizer steps, in the reference's order.

        1. truncate to ``max_chars``;
        2. presentation is "full" for this model, which is the identity
           transform -- so there is deliberately no step 2 here. Porting
           ``presentation.py`` would add a code path that never runs.

        Args:
            raw_text: The text as submitted.

        Returns:
            The text the tokenizer will see.

        Raises:
            EmptyTextError: If nothing but whitespace survives.
        """
        text = raw_text[: self.max_chars] if self.max_chars else raw_text
        if not text.strip():
            raise EmptyTextError(
                "The submitted text holds no readable content. This classifier "
                "expects already-extracted plain text."
            )
        return text

    def classify(self, raw_text: str) -> dict[str, Any]:
        """Classify one document.

        Args:
            raw_text: The document text.

        Returns:
            A result dictionary carrying the label, the confidence, the chunk
            geometry and the raw logits. No text, no snippet, no fragment of the
            input -- ids, counts and scores only.

        Raises:
            EmptyTextError: If the text holds nothing to classify.
        """
        text = self.prepare(raw_text)
        chunks = self._chunker.chunk(text)
        if not chunks:
            raise EmptyTextError("The submitted text tokenized to no tokens.")

        logits = self.run(chunks)
        probabilities = softmax(logits)
        index = int(np.argmax(probabilities))
        label = self.labels[index]

        return {
            "modelVersion": self.model_version,
            "labelId": label,
            "labelIndex": index,
            "labelName": self.label_names.get(label, label),
            "confidence": float(probabilities[index]),
            "chunks": len(chunks),
            "chunkLens": [len(chunk) for chunk in chunks],
            "tokens": int(self._chunker.count_tokens(text)),
            "logits": [float(value) for value in logits],
            "probabilities": [float(value) for value in probabilities],
        }

    def run(self, chunks: Sequence[Sequence[int]]) -> np.ndarray:
        """Feed one document's chunks through the graph, in one call.

        Padding is to the LONGEST CHUNK IN THIS CALL, not always to 512: the
        graph's sequence axis is dynamic, and a short single-chunk document
        therefore runs a short sequence. The Rust port must do the same or its
        attention masks -- and with them its pooled representation -- differ.

        Args:
            chunks: The wrapped chunks, in document order.

        Returns:
            The 29 raw logits for the document.
        """
        width = max(len(chunk) for chunk in chunks)
        input_ids = np.full((len(chunks), width), PAD_ID, dtype=np.int64)
        attention_mask = np.zeros((len(chunks), width), dtype=np.int64)

        for row, chunk in enumerate(chunks):
            input_ids[row, : len(chunk)] = chunk
            attention_mask[row, : len(chunk)] = 1

        outputs = self._session.run(
            ["logits"],
            {"input_ids": input_ids, "attention_mask": attention_mask},
        )
        # The graph pools every chunk into one document, so the batch axis of the
        # output is 1 regardless of how many chunks went in.
        return np.asarray(outputs[0], dtype=np.float64)[0]


def softmax(logits: np.ndarray) -> np.ndarray:
    """Softmax over one document's logits.

    The maximum is subtracted first. Not cosmetic: without it a logit around 90
    overflows float32's exponential and the confidence comes back NaN, which
    would then be compared against a policy threshold.

    Args:
        logits: The raw output values.

    Returns:
        Probabilities summing to one.
    """
    shifted = np.asarray(logits, dtype=np.float64) - np.max(logits)
    exponentiated = np.exp(shifted)
    return exponentiated / np.sum(exponentiated)


# --------------------------------------------------------------------- #
# Command line
# --------------------------------------------------------------------- #


def read_text(args: argparse.Namespace) -> str:
    """Obtain the text to classify.

    Args:
        args: The parsed command line.

    Returns:
        The text, exactly as supplied. Nothing is parsed, no format is detected.

    Raises:
        FileNotFoundError: If ``--text-file`` names a file that is not there.
        ValueError: If neither or both inputs were given.
    """
    if args.text is not None and args.text_file is not None:
        raise ValueError("Give either --text or --text-file, not both.")

    if args.text is not None:
        return sys.stdin.read() if args.text == "-" else args.text

    if args.text_file is not None:
        path = Path(args.text_file)
        if not path.is_file():
            raise FileNotFoundError(f"No such text file: {path}")
        return path.read_text(encoding="utf-8", errors="replace")

    raise ValueError(
        'No input given. Pass --text "<document text>", --text - to read stdin, '
        "or --text-file <path to a UTF-8 text file>."
    )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Read the command line.

    Args:
        argv: Arguments to parse, or None to read ``sys.argv``.

    Returns:
        The parsed arguments.
    """
    parser = argparse.ArgumentParser(
        prog="classify_ref.py",
        description="Torch-free reference classifier for the V6.2.01 document "
        "model. The Rust detection engine is gated against this.",
    )
    parser.add_argument(
        "--text", default=None, help="the document text; '-' reads standard input"
    )
    parser.add_argument(
        "--text-file",
        type=Path,
        default=None,
        help="a UTF-8 text file whose whole contents are the document text",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit the result as JSON only, for scripting",
    )
    parser.add_argument("--model", type=Path, default=DEFAULT_MODEL)
    parser.add_argument("--sidecar", type=Path, default=DEFAULT_SIDECAR)
    parser.add_argument("--tokenizer", type=Path, default=DEFAULT_TOKENIZER)
    parser.add_argument(
        "--providers",
        nargs="+",
        default=None,
        help="ONNX Runtime execution providers (default: CPUExecutionProvider)",
    )
    return parser.parse_args(argv)


def report(result: Mapping[str, Any], model_path: Path) -> None:
    """Print a prediction for a human.

    Args:
        result: What :meth:`ReferenceClassifier.classify` returned.
        model_path: The graph that produced it.
    """
    rule = "=" * 52
    print(rule)
    print("  DLP ML reference prediction (torch-free)")
    print(rule)
    print()
    print(f"Model             : {model_path}")
    print(f"Model version     : {result['modelVersion']}")
    print(f"Document tokens   : {result['tokens']:,}")
    print(f"Chunks            : {result['chunks']}")
    print(f"Chunk lengths     : {result['chunkLens'][:12]}"
          + (" ..." if result["chunks"] > 12 else ""))
    print(f"Predicted ID      : {result['labelId']} (index {result['labelIndex']})")
    print(f"Predicted Label   : {result['labelName']}")
    print(f"Confidence        : {result['confidence'] * 100:.2f} %")
    print(f"Raw Confidence    : {result['confidence']:.4f}")
    print()


def main(argv: list[str] | None = None) -> int:
    """Run the script, turning failures into readable messages.

    Args:
        argv: Arguments to parse, or None to read ``sys.argv``.

    Returns:
        Zero on success, non-zero on failure.
    """
    args = parse_args(argv)

    try:
        text = read_text(args)
        classifier = ReferenceClassifier.load(
            model=args.model,
            sidecar=args.sidecar,
            tokenizer=args.tokenizer,
            providers=args.providers,
        )
        result = classifier.classify(text)
    except EmptyTextError as exc:
        print(f"\n{exc}", file=sys.stderr)
        return 4
    except FileNotFoundError as exc:
        print(f"\n{exc}", file=sys.stderr)
        return 2
    except ImportError as exc:
        print(f"\n{exc}", file=sys.stderr)
        return 3
    except ValueError as exc:
        print(f"\n{exc}", file=sys.stderr)
        return 6
    except Exception as exc:  # noqa: BLE001 - a script's last line of defence
        print(f"\n{type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        report(result, classifier.model_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
