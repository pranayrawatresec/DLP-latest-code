# ML reference implementation and golden vectors

The Rust detection engine (`dlp-agent/src/`) is about to grow a second detection
signal: an ONNX document classifier that predicts one of 29 business-function
classes. The classifier's Python pipeline already exists, in
`Document_classification/`, but it needs torch and transformers to run — a
multi-gigabyte dependency tree that has no business on an engineer's box, in CI,
or anywhere near an air-gapped build.

This directory is the **torch-free reference**: the same preprocessing, the same
chunk geometry and the same model, on three packages instead of forty. It is the
authority the Rust port is gated against. If Rust and this disagree, Rust is
wrong.

| file | what it is |
|---|---|
| `classify_ref.py` | the reference classifier — truncate, tokenize, chunk, pad, run, softmax, argmax |
| `gen_golden_vectors.py` | runs a fixed set of documents through it and freezes the answers |
| `requirements.txt` | onnxruntime, numpy, tokenizers — and the reason for each |
| `../../dlp-agent/tests/fixtures/ml-golden-vectors.json` | the generated artifact the Rust tests read |

Nothing here ships to a customer. It is a developer and CI tool; the agent and
the management server do not depend on it.

## Setup

Python 3.14 on Windows; any 3.11+ works.

```bash
cd tools/ml-reference
python -m venv .venv
.venv/Scripts/python -m pip install -r requirements.txt      # Windows
# .venv/bin/python -m pip install -r requirements.txt        # POSIX
```

The repository root `.gitignore` does not yet cover `.venv/` or `__pycache__/`;
add them there, or put the virtualenv outside the working tree, so a local
environment never lands in a commit.

Three packages, ~200 MB. No torch, no transformers, no HuggingFace hub call —
everything is read off disk from `Document_classification/`, so this runs with
the network unplugged, which is the whole point of the product.

## Classifying some text

```bash
.venv/Scripts/python classify_ref.py --text "The quarterly budget report ..."
.venv/Scripts/python classify_ref.py --text-file extracted.txt
.venv/Scripts/python classify_ref.py --json --text - < extracted.txt
```

`--json` emits `labelId`, `labelName`, `labelIndex`, `confidence`, `chunks`,
`chunkLens`, `tokens`, the 29 `logits` and the 29 `probabilities`. Never any
text: the same rule the agent obeys applies to the tool that gates it.

Observed on the artifacts in this repo, as a smoke test:

| input | result |
|---|---|
| a budget / expenditure paragraph | `FIN` Finance, 0.9908, 1 chunk, 65 tokens |
| a reactor-safety / deterrent paragraph | `NUC` Nuclear & Strategic Systems, 0.9955, 1 chunk, 77 tokens |

## Regenerating the golden vectors

```bash
.venv/Scripts/python gen_golden_vectors.py            # write the fixture
.venv/Scripts/python gen_golden_vectors.py --check    # CI: fail if it drifted
```

`--check` regenerates in memory and diffs against the file without writing.
Re-running the generator reproduces the fixture byte for byte — no timestamps,
no paths, no randomness — so a non-empty diff means something real changed:
onnxruntime, the tokenizer, the graph, or the chunker.

**Changing the fixture is a deliberate act.** It is the definition of correct for
the Rust engine; regenerate it only when the model or the geometry actually
changes, and say so in the commit message.

## What the reference does, step by step

The Rust port implements exactly this, in this order. Steps 1–4 are in
`ai_classifier/training/chunking.py`, which this tool **imports by path** rather
than reimplementing (see below).

1. **Truncate** the raw text to `max_chars` = 200 000 **characters**. Before a
   single token exists — truncating by tokens instead gives a different answer.
2. **Presentation** is `full` for V6.2.01, which is the identity transform.
   There is deliberately no code for it here; porting `presentation.py` would add
   a branch that never runs.
3. **Tokenize** with `backbone/tokenizer.json` (WordPiece, lowercasing
   `BertNormalizer`), `add_special_tokens=false`, no truncation.
4. **Chunk** with a content budget of `max_tokens(512) − specials(2) = 510`:
   - split into units — blank-line blocks (`/\n\s*\n/`); a unit still over budget
     descends to lines (`\n`), then sentences (`/(?<=[.!?])\s+/`), then a hard
     split of the token ids. A split that yields ≤ 1 part descends a level
     instead of recursing on the same text.
   - pack whole units greedily in document order. When a unit does not fit, close
     the chunk and seed the next one with the **carry-over**: the last
     `overlap = min(64, budget/2) = 64` tokens of the chunk just closed.
   - while the carried head plus the unit still exceeds the budget, **trim the
     head from the left**.
   - if there are ≥ 2 chunks and the last one holds fewer than `min_tokens` (32),
     replace it with the last `min(32, budget, len(flat))` tokens of the flat
     token stream. (Unreachable at this geometry — see below.)
   - wrap each chunk as `[CLS](101) + ids + [SEP](102)`.
5. **Pad** right to the **longest chunk in this call** — dynamic, *not* always
   512 — with pad id `0`. `attention_mask` is 1 for real tokens, 0 for padding.
   Both tensors are int64.
6. **Run** the graph **once**, `input_ids[num_chunks, sequence]` +
   `attention_mask[num_chunks, sequence]` → `logits[1, 29]`. The graph performs
   the encoder pass, the per-chunk `[CLS]` **mean pooling** and the
   classification head, so every chunk fed into one call is one document.
7. **Softmax** (subtract the max first, or a logit near 90 overflows to NaN and
   the NaN then gets compared against a policy threshold), **argmax**, and map
   the index through the frozen 29-label list.

### Why the chunker is imported, not copied

Chunk geometry is the one place where a subtle disagreement — an off-by-one in
the carry, a different sentence regex — changes the ids the model sees, and
therefore the answer, silently and without an error. So `classify_ref.py` loads
`Document_classification/ai_classifier/training/chunking.py` **directly by path**
with `importlib.util.spec_from_file_location`, bypassing
`ai_classifier/__init__.py` (which imports torch). That module is pure stdlib —
`re`, `statistics`, `dataclasses`, `typing` — so it executes clean on its own.

The one adapter needed is `FastTokenizerShim`. `DocumentChunker` uses exactly one
tokenizer API, the *transformers* convention
`tok(text, add_special_tokens=…, truncation=…)["input_ids"]`, while the
torch-free `tokenizers.Tokenizer` exposes `.encode(...).ids`. The shim is that
one call and nothing more.

### The `min_tokens` tail extension cannot fire at V6.2.01 geometry

Worth stating so nobody hunts for a golden vector that covers it. With
`overlap = 64` and `min_tokens = 32`, the final chunk of a multi-chunk document
is always ≥ 65 content tokens:

- every chunk after the first is seeded with the carry-over, so a final chunk is
  `carry + trailing units`;
- a carry shorter than 32 requires the preceding chunk to be shorter than 32,
  which only happens when the unit that closed it is wider than `510 − 32 = 478`
  — and that wide unit then lands in the *next* chunk, making that one wide;
- the head-trim branch leaves the chunk at exactly the budget, never short.

An exhaustive search over unit-length sequences confirms it: the shortest
reachable final chunk is **65** content tokens (67 with specials), from unit
lengths `(510, 1)`. The `min_final_chunk` case pins exactly that. **The Rust port
must still implement the tail extension** — the geometry is read from
`model.onnx.json`, so a future model with `overlap < min_tokens` reaches the
branch — it simply cannot be covered by a golden vector today.

## The fixture format

`dlp-agent/tests/fixtures/ml-golden-vectors.json`:

```jsonc
{
  "modelVersion": "V6.2.01",
  "modelSha256": "<sha256 of model/model.onnx>",   // fixture ↔ weights are paired
  "tolerance": 1e-4,                                // floats only; geometry is exact
  "padId": 0,
  "maxChars": 200000,
  "chunking": { "maxTokens": 512, "overlapTokens": 64, "minTokens": 32,
                "contentBudget": 510, "effectiveOverlap": 64 },
  "labels": [ "ADM", ... 29 ids in frozen index order ],
  "cases": [
    {
      "name": "boundary_overlap_carry",
      "note": "what branch of the chunker this case holds still",
      "textRecipe": { "kind": "repeat", "text": "...", "times": 43 },
      "expected": {
        "chunkCount": 2,
        "chunkLens": [506, 78],          // wrapped lengths, specials included
        "chunkIdsSha256": "…",
        "tokenCount": 516,               // content tokens before chunking, no specials
        "labelId": "ADM",
        "labelIndex": 0,
        "confidence": 0.960897,
        "logits": [ 29 floats ]
      }
    }
  ]
}
```

### `textRecipe` — how to rebuild a case's text

Several cases need thousands of tokens and one needs 200 000 characters, so the
fixture stores the recipe rather than the prose:

- `{"kind": "literal", "text": T}` → the text is `T`.
- `{"kind": "repeat", "text": T, "times": n}` → the text is `T` concatenated `n`
  times **with no separator**. Any separator (a space, a `\n`, a blank line) is
  already inside `T`.

### `chunkIdsSha256` — the exact construction

Stated once, unambiguously, so Rust can reproduce it:

1. take the **final** token ids of each chunk — `[CLS]` and `[SEP]` **included**,
   padding **excluded** (padding belongs to the batch, not to a chunk);
2. within a chunk, render each id in decimal and join with a comma `,`;
3. join the chunks with a semicolon `;`, in document order;
4. encode that string as UTF-8 and take its **SHA-256**, lowercase hex.

So chunks `[[101, 5, 6, 102], [101, 7, 102]]` hash the string
`101,5,6,102;101,7,102`.

This lets a Rust test assert on every token of a 64-chunk document in 64
characters — and it fails on a single token's difference. Note that `chunkCount`,
`chunkLens` and `chunkIdsSha256` need only the tokenizer, not the 256 MB graph,
so the geometry half of the suite can run on every commit while the logits half
runs where the model is available.

### The cases and what each one is for

| case | chunks | tokens | label | what it holds still |
|---|---|---|---|---|
| `short_single_chunk` | 1 | 44 | FIN | dynamic padding width — a port that always pads to 512 fails here |
| `boundary_just_under` | 1 | 504 | ADM | one token block still inside the 510 budget |
| `boundary_overlap_carry` | 2 | 516 | ADM | one token over: descends to sentences, second chunk seeded with the 64-token carry |
| `three_chunks` | 3 | 1200 | ADM | carry applied twice, steady-state 510-token chunks |
| `eight_chunks` | 8 | 3360 | ADM | more chunks than `micro_batch_size`; all pooled into one document |
| `min_final_chunk` | 2 | 511 | ADM | the shortest final chunk the geometry admits (64 carried + 1) |
| `blank_line_blocks` | 3 | 1080 | OPS | every unit boundary is a `BLOCK_PATTERN` match |
| `unsplittable_long_line` | 6 | 2640 | EXM | hard token split at level 3, and the carried head trimmed from the left |
| `punctuation_and_numbers` | 1 | 136 | FIN | WordPiece fragmentation of digits, currency and references |
| `unicode_accented` | 1 | 118 | OOD | accented Latin, `ß`, Spanish punctuation, CJK — normalizer behaviour |
| `max_chars_truncation` | 64 | 28236 | ADM | truncation by **characters** at 200 000, before tokenization |

Labels are recorded, not asserted by design: these are synthetic geometry
probes, and what the model makes of them is simply frozen. Two of them
(`unsplittable_long_line` at 0.40, `blank_line_blocks` at 0.82) sit well below a
sensible policy threshold, which is correct — filler is not a finance document.

Nothing in the fixture is real or customer-derived text; the cases are synthetic
filler chosen for their token arithmetic.
