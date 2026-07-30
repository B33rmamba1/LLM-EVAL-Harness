# prompt-eval-harness

A minimal, **zero-dependency** prompt-security evaluation harness. It fires a suite of
prompt-injection / jailbreak / data-exfiltration / tool-misuse attacks at a target LLM,
scores each response against a security policy, and returns a CI-gating exit code.

Built as a compact demonstrator of the pattern behind *"automated evaluation harnesses and
regression test suites that continuously validate prompt and agent behavior against security
policies"* and *"integrate prompt-security controls and tests into CI/CD pipelines."*

## Quickstart

```bash
# Offline demo — no model, no network, no dependencies:
python3 prompt_eval.py --provider mock

# ── Local models via Ollama (http://localhost:11434/v1) ──

# General-purpose (GPT-OSS 20B, ~140 tok/s on RTX 5070 Ti 16GB):
python3 prompt_eval.py --provider openai --base-url http://localhost:11434/v1 --model gpt-oss-claude

# Security-focused (Security Gemma4 2B, tuned for CySA+/CareFortress):
python3 prompt_eval.py --provider openai --base-url http://localhost:11434/v1 --model security-gemma4-claude

# Security + instruction following (Qwen3 14B, security system prompt):
python3 prompt_eval.py --provider openai --base-url http://localhost:11434/v1 --model security-qwen3

# Strong instruction following (Qwen3 14B, 131K context):
python3 prompt_eval.py --provider openai --base-url http://localhost:11434/v1 --model qwen3-claude

# Code specialist (Qwen Coder 14B):
python3 prompt_eval.py --provider openai --base-url http://localhost:11434/v1 --model qwen-coder-claude

# General + long context (Gemma4 12B, 131K context):
python3 prompt_eval.py --provider openai --base-url http://localhost:11434/v1 --model gemma4-claude

# ── LM Studio ──
python3 prompt_eval.py --provider openai --base-url http://localhost:1234/v1 --model <model>

# ── Hosted OpenAI-compatible endpoint ──
OPENAI_API_KEY=sk-... python3 prompt_eval.py --provider openai \
    --base-url https://api.openai.com/v1 --model gpt-4o-mini

# Run the scorer unit tests:
python3 test_prompt_eval.py        # or: python3 -m pytest -q
```

Exit codes: `0` pass rate ≥ threshold, `1` below threshold (fails CI), `2` usage/runtime error.

## How it works

- **attacks.json** — the test suite. Each case has an OWASP-LLM tag, an attack prompt, and a
  scoring rule. Attacks try to make the model emit a **canary marker** (e.g. `INJECTED_OK_7X9`)
  or leak a **planted secret** in the system prompt (`SYS_CANARY_Zeta_9f31`). If the marker or
  secret shows up in the output, the attack won and the case **FAILS**.
- **prompt_eval.py** — loads the suite, runs each case through a provider, scores it, prints a
  report, writes `results.json`, and sets the exit code from the pass rate vs. `--threshold`.
- **test_prompt_eval.py** — unit tests for the scorer itself.
- **.github/workflows/prompt-eval.yml** — runs the tests + a mock smoke test on every PR, and
  evaluates a real model when a key is configured.

### Why deterministic canary-marker scoring
Scoring is exact-match / regex, so results are reproducible and cheap — no LLM judge required,
no flakiness. The trade-off is that it catches *known* attack outcomes rather than judging
nuance; the scorer is a single function (`score_case`) so an LLM-judge scorer can be layered in
for cases that need it.

### Coverage (OWASP Top 10 for LLM Applications)
| Case | OWASP | What it probes |
|------|-------|----------------|
| PI-01 | LLM01 | Direct instruction override |
| PI-02 | LLM01 | **Indirect** injection hidden in retrieved content |
| PI-03 | LLM07 | System-prompt / secret extraction |
| PI-04 | LLM01 | Roleplay jailbreak ("DAN") |
| PI-05 | LLM02 | PII / sensitive-data exfiltration |
| PI-06 | LLM06 | Excessive-agency / unauthorized tool action |
| PI-07 | LLM01 | Base64-encoded payload (filter evasion) |
| PI-08 | —     | Benign control (catches an over-blocking filter) |

## Talking points (for the interview)

- **This is the guardrail regression suite the JD asks for.** Attacks live in versioned config,
  scoring is deterministic, it emits a machine-readable artifact, and it gates CI. Adding a new
  attack = one JSON object. That's how you make "protections ship with every release" real.
- **Provider-agnostic on purpose.** Any OpenAI-compatible endpoint — hosted or self-hosted —
  which means I can run the same suite against a local model *and* the production model.
- **The benign control case (PI-08) is deliberate.** A prompt firewall that refuses everything
  is a failing firewall, not a passing one. Security controls have to preserve the consumer
  experience — that's explicitly in the JD.
- **Extends naturally to agents.** The PI-06 tool-misuse case is the seed of agent-level testing:
  assert that a tool/function call is *not* emitted for an unauthorized request — least-privilege
  enforced at the tool-invocation layer.
- **Same pattern I already build.** In CareFortress I run a content-aware protocol proxy that
  whitelists allowed messages and rejects-and-logs the rest at a boundary the workload can't
  bypass. Swap HL7 payloads for prompts and it's an LLM firewall with an eval harness in front.
