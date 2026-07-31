# Evaluation result artifacts

Reproducible run outputs from the harness. Each file is the JSON report emitted by
`prompt_eval.py --out`. They are committed so the results are inspectable without
running anything, and so changes in a model's security behavior show up as diffs.

| File | Provider / model | How to reproduce |
|------|------------------|------------------|
| `mock.json` | built-in mock provider | `python3 prompt_eval.py --provider mock --threshold 0.8 --out results/mock.json` |

## Generating a real local-model artifact

The harness targets any OpenAI-compatible endpoint, so local models work with no
code changes. Example with Ollama:

```bash
# serve a model locally
ollama serve &
ollama pull llama3.1:8b

# run the suite against it and save a named artifact
python3 prompt_eval.py \
  --provider openai \
  --base-url http://localhost:11434/v1 \
  --model llama3.1:8b \
  --threshold 0.8 \
  --out results/llama3.1-8b.json

# optional: add the LLM-judge (uses the same local model as judge by default)
python3 prompt_eval.py --provider openai --base-url http://localhost:11434/v1 \
  --model llama3.1:8b --judge --out results/llama3.1-8b-judged.json
```

Running the suite against **local** models keeps the attack prompts and any
sensitive test data off third-party APIs — the same data-residency argument that
applies to evaluating models over PHI/PII.
