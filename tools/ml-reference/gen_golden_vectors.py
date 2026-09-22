"""Freeze the reference pipeline's behaviour into the Rust engine's golden vectors.

Why this exists
---------------

``classify_ref.py`` says what correct means; this script writes it down. The
artifact it emits, ``dlp-agent/tests/fixtures/ml-golden-vectors.json``, is what
the Rust ML path is tested against -- the same way
``dlp-agent/src/detect/`` is gated against its frozen fingerprint vectors. A Rust
change that shifts a chunk boundary by one token, pads to 512 instead of to the
longest chunk in the call, or drops the overlap carry, fails here rather than in
a customer's incident feed.

What each case pins down
------------------------

Two independent layers, because they fail independently:

  chunk geometry   chunkCount, chunkLens and chunkIdsSha256 -- reproducible with
                   the tokenizer alone, no 256 MB graph and no float comparison.
                   A Rust test can run these on every commit.
  model output     labelId, labelIndex, confidence and the 29 logits, compared
                   within ``tolerance``. Floats, so a different BLAS or a
                   different onnxruntime build moves the last digits; 1e-4 is
                   wide enough for that and far narrower than any policy
                   threshold.

Why recipes and not prose
-------------------------

Several cases need thousands of tokens, and one needs 200 000 characters to
exercise the ``max_chars`` truncation. Storing that text would put a megabyte of
filler in the repository for no information. Each case therefore stores a
RECIPE -- ``{"kind": "literal", "text": ...}`` or ``{"kind": "repeat", "text":
..., "times": n}``, the latter meaning ``text`` concatenated ``times`` times with
NO separator -- and both sides rebuild the same string from it.

Determinism
-----------

Nothing here is random, timestamped or path-dependent, so re-running the script
rewrites the file byte for byte. That is checked in CI by regenerating and
diffing: a fixture that drifts on its own is not a fixture.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

sys.path.insert(0, str(Path(__file__).resolve().parent))

from classify_ref import (  # noqa: E402
    DEFAULT_MODEL,
    DEFAULT_SIDECAR,
    DEFAULT_TOKENIZER,
    PAD_ID,
    REPO_ROOT,
    ReferenceClassifier,
    softmax,
)

DEFAULT_OUTPUT = REPO_ROOT / "dlp-agent" / "tests" / "fixtures" / "ml-golden-vectors.json"

#: How closely the Rust engine must reproduce a float. Chunk geometry is exact;
#: only the logits and the confidence get a tolerance.
TOLERANCE = 1e-4

#: Logits and confidences are rounded before they are written. Six decimals is
#: two orders of magnitude finer than the tolerance and stops the fixture
#: churning on the last binary digit between runs and machines.
FLOAT_DIGITS = 6


# --------------------------------------------------------------------- #
# Case material
#
# Deliberately synthetic, deliberately boring: no real document, no customer
# text, nothing that could be a fragment of anything sensitive. What is being
# tested is chunk arithmetic, not the model's judgement -- whatever label these
# come back as is simply recorded.
# --------------------------------------------------------------------- #

#: Twelve tokens, one sentence, ends in a period so the sentence-level splitter
#: can cut between repetitions. The unit of arithmetic for every boundary case.
SENTENCE = "The finance committee approved the departmental expenditure for the current quarter. "

#: One token per repetition and no sentence-ending punctuation at all, so a whole
#: block of these is one indivisible unit until the hard token split runs.
WORD = "budget "

#: One long line: no newline and no .!? followed by whitespace, so the block
#: splitter and the sentence splitter both return a single part and the chunker
#: is forced down to level 3, the hard split of the token ids.
UNSPLITTABLE = "alpha-bravo-charlie-delta-echo-foxtrot-golf-hotel-india-juliet-"

#: A blank-line-separated block, the boundary ``compose_text`` actually writes.
BLOCK = (
    "Section heading for the operational readiness review.\n"
    "The unit reported full readiness across all assigned platforms.\n"
    "\n"
)


def literal(text: str) -> dict[str, Any]:
    """A recipe carrying its text verbatim.

    Args:
        text: The document text.

    Returns:
        The recipe.
    """
    return {"kind": "literal", "text": text}


def repeat(text: str, times: int) -> dict[str, Any]:
    """A recipe that concatenates a fragment n times, with no separator.

    Args:
        text: The fragment. Any separator belongs inside it.
        times: How many times it is repeated.

    Returns:
        The recipe.
    """
    return {"kind": "repeat", "text": text, "times": times}


def render(recipe: Mapping[str, Any]) -> str:
    """Rebuild a case's text from its recipe.

    The Rust side implements exactly this function; it is two branches on
    purpose.

    Args:
        recipe: The stored recipe.

    Returns:
        The document text.

    Raises:
        ValueError: If the recipe names a kind that does not exist.
    """
    kind = recipe["kind"]
    if kind == "literal":
        return str(recipe["text"])
    if kind == "repeat":
        return str(recipe["text"]) * int(recipe["times"])
    raise ValueError(f"unknown textRecipe kind {kind!r}")


# --------------------------------------------------------------------- #
# The cases
#
# Ordered from the simplest geometry to the most awkward. The note on each one
# states the branch of the chunker it is there to hold still.
# --------------------------------------------------------------------- #

CASES: tuple[tuple[str, str, dict[str, Any]], ...] = (
    (
        "short_single_chunk",
        "A short document: one unit, one chunk, sequence far below 512. Pins the "
        "dynamic padding width -- a port that always pads to 512 fails here.",
        literal(
            "The quarterly budget report sets out expenditure against each cost "
            "centre for the financial year. Total operating expenditure was 4.2 "
            "million, against an approved budget of 4.5 million, leaving an "
            "underspend of 300 thousand."
        ),
    ),
    (
        "boundary_just_under",
        "504 content tokens: one token block still inside the 510-token budget, "
        "so it stays a single unit and a single chunk. The near miss on the "
        "boundary is the point.",
        repeat(SENTENCE, 42),
    ),
    (
        "boundary_overlap_carry",
        "516 content tokens: one token over the budget, so the block descends to "
        "sentences and the second chunk is seeded with the 64-token carry-over. "
        "The narrowest test of the overlap there is.",
        repeat(SENTENCE, 43),
    ),
    (
        "three_chunks",
        "Around 1200 content tokens: three chunks, so the carry-over is applied "
        "twice and chunk lengths settle at the steady-state 510.",
        repeat(SENTENCE, 100),
    ),
    (
        "eight_chunks",
        "Around 3360 content tokens: eight chunks in one run() call, which is "
        "also more chunks than the recorded micro_batch_size of 8 leaves slack "
        "for -- the graph pools all of them into one document regardless.",
        repeat(SENTENCE, 280),
    ),
    (
        "min_final_chunk",
        "A 510-token block followed by a one-token block. Produces the SHORTEST "
        "final chunk the V6.2.01 geometry admits: 64 carried tokens plus one. "
        "See the README on why the min_tokens tail extension cannot fire.",
        literal(WORD * 510 + "\nok"),
    ),
    (
        "blank_line_blocks",
        "Sixty blank-line-separated blocks. Every unit boundary is a BLOCK_PATTERN "
        "match, so chunks close between blocks and never inside one.",
        repeat(BLOCK, 60),
    ),
    (
        "unsplittable_long_line",
        "One line, no newline and no sentence-ending punctuation: block split and "
        "sentence split both return a single part, so the chunker descends to the "
        "hard split of the token ids. Also forces the carried head to be TRIMMED "
        "from the left, because each unit is exactly a full budget wide.",
        repeat(UNSPLITTABLE, 120),
    ),
    (
        "punctuation_and_numbers",
        "Digits, decimals, currency and bracketed references. WordPiece fragments "
        "these heavily, so a port with a hand-rolled tokenizer diverges here first.",
        literal(
            "Invoice 2024/AB-8817 (rev. 3) -- net 12,450.75 GBP; VAT @ 20% = "
            "2,490.15; gross 14,940.90.\n"
            "Cost centres: 41-002, 41-003, 41-117.  Ref: PO#99321/A.\n"
            "Payment terms: 30 days net. Late fee 1.5%/month. IBAN GB29 NWBK 6016 "
            "1331 9268 19.\n"
            "Schedule: Q1 25%, Q2 25%, Q3 25%, Q4 25% -- reviewed 2024-11-03."
        ),
    ),
    (
        "unicode_accented",
        "Accented Latin, a German sharp s, French and Spanish punctuation and a "
        "non-Latin script. The bundled normalizer lowercases and handles CJK; a "
        "port that normalizes differently produces different ids immediately.",
        literal(
            "Rapport financier: le comité a approuvé les dépenses de l'unité pour "
            "le trimestre. Coût total: 1.234,56 EUR.\n"
            "Jahresabschluss der Straße GmbH -- Prüfung abgeschlossen, Maßnahmen "
            "eingeleitet.\n"
            "¿Cuál es el presupuesto asignado? El déficit fue de 12% según el "
            "informe anual.\n"
            "年度財務報告書 -- 予算執行状況の確認。"
        ),
    ),
    (
        "max_chars_truncation",
        "Over 200 000 characters. Everything past text.max_chars is dropped "
        "BEFORE tokenization, so a port that truncates by tokens instead of by "
        "characters -- or not at all -- gets a different chunk count.",
        repeat(SENTENCE, 2600),
    ),
)


# --------------------------------------------------------------------- #
# Hashing
# --------------------------------------------------------------------- #


def chunk_ids_sha256(chunks: Sequence[Sequence[int]]) -> str:
    """Hash a document's chunk ids into one comparable string.

    The construction, stated once so both languages can implement it from this
    sentence: render every token id of a chunk in decimal, join them with a comma
    ``,``; join the chunks with a semicolon ``;``; encode the result as UTF-8 and
    take its SHA-256, lowercase hex. The ids are the FINAL ids fed to the graph,
    [CLS] and [SEP] included, and PAD is NOT included -- padding is a property of
    the batch, not of a chunk.

    Storing the hash rather than the ids keeps a 56-chunk case to 64 characters
    while still failing on a single token's difference.

    Args:
        chunks: The wrapped chunks, in document order.

    Returns:
        The lowercase hex digest.
    """
    joined = ";".join(",".join(str(token) for token in chunk) for chunk in chunks)
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()


def file_sha256(path: Path) -> str:
    """SHA-256 of a file, read in blocks.

    The ONNX graph is 256 MB, so it is not read into memory to be hashed.

    Args:
        path: The file.

    Returns:
        The lowercase hex digest.
    """
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


# --------------------------------------------------------------------- #
# Generation
# --------------------------------------------------------------------- #


def build_case(
    classifier: ReferenceClassifier, name: str, note: str, recipe: Mapping[str, Any]
) -> dict[str, Any]:
    """Run one case and record what the reference produced.

    Args:
        classifier: The loaded reference pipeline.
        name: The case name, used in the Rust test's failure message.
        note: What branch of the chunker this case exists to hold still.
        recipe: How to rebuild the text.

    Returns:
        The case, ready to serialise.
    """
    text = render(recipe)
    prepared = classifier.prepare(text)
    chunks = classifier.chunk(text)

    logits = classifier.run(chunks)
    probabilities = softmax(logits)
    index = int(probabilities.argmax())

    return {
        "name": name,
        "note": note,
        "textRecipe": dict(recipe),
        "expected": {
            "chunkCount": len(chunks),
            "chunkLens": [len(chunk) for chunk in chunks],
            "chunkIdsSha256": chunk_ids_sha256(chunks),
            "tokenCount": int(classifier._chunker.count_tokens(prepared)),  # noqa: SLF001
            "labelId": classifier.labels[index],
            "labelIndex": index,
            "confidence": round(float(probabilities[index]), FLOAT_DIGITS),
            "logits": [round(float(value), FLOAT_DIGITS) for value in logits],
        },
    }


def build_fixture(classifier: ReferenceClassifier, model: Path) -> dict[str, Any]:
    """Run every case and assemble the fixture.

    Args:
        classifier: The loaded reference pipeline.
        model: The ONNX graph, hashed so a fixture cannot be silently paired with
            a different set of weights.

    Returns:
        The fixture document.
    """
    cases = []
    for name, note, recipe in CASES:
        case = build_case(classifier, name, note, recipe)
        expected = case["expected"]
        print(
            f"  {name:<26} chunks={expected['chunkCount']:>3} "
            f"tokens={expected['tokenCount']:>6} "
            f"label={expected['labelId']} conf={expected['confidence']:.4f}",
            flush=True,
        )
        cases.append(case)

    return {
        "modelVersion": classifier.model_version,
        "modelSha256": file_sha256(model),
        "tolerance": TOLERANCE,
        "padId": PAD_ID,
        "maxChars": classifier.max_chars,
        "chunking": {
            "maxTokens": classifier._chunker.settings.max_tokens,  # noqa: SLF001
            "overlapTokens": classifier._chunker.settings.overlap_tokens,  # noqa: SLF001
            "minTokens": classifier._chunker.settings.min_tokens,  # noqa: SLF001
            "contentBudget": classifier._chunker.content_budget,  # noqa: SLF001
            "effectiveOverlap": classifier._chunker.overlap,  # noqa: SLF001
        },
        "labels": list(classifier.labels),
        "chunkIdsSha256Spec": (
            "sha256 over UTF-8 of the chunk ids: token ids in decimal joined by "
            "',' within a chunk, chunks joined by ';'. Ids include [CLS]/[SEP] "
            "and exclude padding."
        ),
        "textRecipeSpec": (
            "kind 'literal' -> text as given; kind 'repeat' -> text concatenated "
            "'times' times with no separator."
        ),
        "cases": cases,
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Read the command line.

    Args:
        argv: Arguments to parse, or None to read ``sys.argv``.

    Returns:
        The parsed arguments.
    """
    parser = argparse.ArgumentParser(
        prog="gen_golden_vectors.py",
        description="Regenerate the ML golden vectors the Rust engine is gated "
        "against.",
    )
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--model", type=Path, default=DEFAULT_MODEL)
    parser.add_argument("--sidecar", type=Path, default=DEFAULT_SIDECAR)
    parser.add_argument("--tokenizer", type=Path, default=DEFAULT_TOKENIZER)
    parser.add_argument(
        "--check",
        action="store_true",
        help="regenerate in memory and fail if it differs from the file on disk, "
        "without writing anything. What CI runs.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Generate or verify the fixture.

    Args:
        argv: Arguments to parse, or None to read ``sys.argv``.

    Returns:
        Zero on success, non-zero on failure.
    """
    args = parse_args(argv)

    print(f"Loading {args.model} ...", flush=True)
    classifier = ReferenceClassifier.load(
        model=args.model, sidecar=args.sidecar, tokenizer=args.tokenizer
    )

    print(f"Running {len(CASES)} cases:", flush=True)
    fixture = build_fixture(classifier, Path(args.model))

    # Trailing newline so the file is a well-formed text file; ensure_ascii so a
    # unicode case survives any checkout's encoding settings unchanged.
    rendered = json.dumps(fixture, indent=2, ensure_ascii=True) + "\n"

    if args.check:
        existing = (
            args.output.read_text(encoding="utf-8") if args.output.is_file() else None
        )
        if existing == rendered:
            print(f"\nOK: {args.output} is up to date.")
            return 0
        print(
            f"\nFAIL: {args.output} does not match a fresh generation. Re-run "
            "without --check and review the diff.",
            file=sys.stderr,
        )
        return 1

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(rendered, encoding="utf-8")
    print(f"\nWrote {args.output} ({len(rendered):,} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
