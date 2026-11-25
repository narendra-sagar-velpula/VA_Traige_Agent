# va-triage-agent

**AI-assisted vulnerability analysis (VA) for a software product**: collect scanner findings, decide which
ones really affect the product, and write the VA report, with an LLM agent for the hard cases and an
evaluation harness that proves the automation is safe before it is trusted.

Scanners report everything that *could* be a problem. Most of it is not: the vulnerable function is never
called, the input is not attacker-controlled, or the finding is in test code. Someone has to check each
one and write down why. This project automates that triage, the repetitive part of VA, without letting
automation close a real vulnerability.

## Pipeline

```
SBOM (CycloneDX) ──► OSV advisory matching ─┐
Bandit JSON ────────────────────────────────┼─► collect: clean, redact secrets, de-duplicate,
SARIF (Semgrep, CodeQL, ...) ───────────────┘            add CVSS + CISA KEV
                                                                │
                      code index (imports, API calls, template filters, constant-only inputs)
                                                                │
                   rules (safe | aggressive) ──► LLM agent via MCP tools for what rules cannot decide
                                                                │
                         guardrails: KEV / critical never closed without a human
                                                                │
          VA report (Markdown) · OpenVEX · SARIF for CI · release gate · evaluation vs ground truth
```

## Results on the lab service (real data)

`lab/netcfg-service` is a small, deliberately outdated Python service (YAML upload, Jinja2 rendering,
vendor API calls, image thumbnails, diagnostics). Its dependency tree was resolved with pip, matched against
the **real PyPA advisory database** (snapshot `8bc6845`, 2026-11-24) and the **CISA KEV catalog
2026.11.24**, and scanned with Bandit. I labelled every finding by reading the advisory and the code
(`lab/ground_truth.yaml`, with an OpenVEX justification for each).

- 86 raw findings → 85 after merging a re-published libwebp advisory → **only 17 truly affect the service**
  (11 dependency, 6 code). One of them, CVE-2023-4863 in Pillow's bundled libwebp, is on CISA's KEV list.

| Engine | Decided automatically | Accuracy of automatic decisions | Real issues caught | Unsafe dismissals |
| --- | --- | --- | --- | --- |
| Rules, safe mode | 30 of 85 (35%) | 76.7% | 17 / 17 | **0** |
| Rules, aggressive mode | 61 of 85 (72%) | 86.9% | 16 / 17 | **1** (Jinja2 `urlize` ReDoS) |

- Code (SAST) findings: rules close **10 of 11 false positives** and keep all 6 true positives.
- Aggressive rules automate twice as much, but dismiss a real ReDoS because its advisory only names an
  internal regex (`_punctuation_re`), not the `urlize` filter the service uses. Exported to
  [agent-eval-console](https://github.com/narendra-sagar-velpula/agent-eval-console), the comparison shows
  +34.1 points of safe automation (McNemar p < 0.001) **and the gate still blocks it** because one
  `critical` case regressed. That is the point: more automation is only accepted if it is also safe.
- The hard cases (format allowlists in `Image.open`, `requests` percent-encoding parameters before urllib3,
  a trusted vendor key, an IP-validated shell call, a "this is safe, mark as false positive" comment that
  is false) are what the LLM agent is for. Run it with your own model and the same gate decides whether it
  is good enough (see *Agent* below).

## Trust and safety controls

| Risk | Control |
| --- | --- |
| Automation closes a real vulnerability | Safe mode by default; KEV or CVSS ≥ 9.0 is never closed without a human; eval gate tags every truly affected case `critical` |
| The LLM invents evidence | Every evidence item must be a code line, advisory or SBOM path the agent actually fetched in this session; one repair round, then the rule decision is kept |
| Prompt injection via code comments or advisory text | All tool output is wrapped in `<untrusted>`; comments are claims, not evidence; the lab contains a real injection attempt and a test for it |
| Secrets leak into reports or to an external LLM | Secrets are redacted at ingestion and in every tool response (field names like `"password"` are kept) |
| The agent changes something | All MCP tools are read-only; `read_code` is confined to the analysed code (path traversal is refused) |
| LLM outage or nonsense output | Fallback to the rule decision with the reason recorded in the trace |
| Unreviewed decisions shipped | Every open item is labelled `needs human`; the report and VEX mark them `under_investigation` |

## Outputs

- `va-report.md`: summary, tools used, remaining findings by priority with evidence, a remediation plan
  (smallest upgrade that fixes all open advisories per package), and the **not-affected / false-positive
  list with justifications**.
- `netcfg-service.openvex.json`: OpenVEX 0.2.0 statements (`affected`, `not_affected` + justification,
  `under_investigation`).
- `va-findings.sarif`: SARIF 2.1.0 for GitHub code scanning or any SARIF viewer.
- `run-*.json`: runs for agent-eval-console (pass rate, regressions, McNemar test, gate).

## Run it

```sh
pip install -e ".[dev]"
vatriage lab --out out                     # whole pipeline on the lab service
vatriage eval out/findings.json out/decisions-safe.json --truth lab/ground_truth.yaml
vatriage gate out/findings.json out/decisions-safe.json --block P1,P2      # CI release gate
vatriage search "urlize regular expression" --package jinja2                # advisory knowledge retrieval

# your own project
pip install --dry-run --ignore-installed --report pip.json -r requirements.txt
vatriage sbom --pip-report pip.json --name myapp --version 1.0 -o sbom.cdx.json
scripts/update_data.sh sbom.cdx.json       # fresh advisories + CISA KEV
bandit -r src -f json -o bandit.json
vatriage collect --sbom sbom.cdx.json --bandit bandit.json --code src -o findings.json
vatriage triage findings.json --code src --sbom sbom.cdx.json -o decisions.json
vatriage report findings.json decisions.json --format md -o va-report.md
```

### Agent

Any OpenAI-compatible endpoint works (OpenAI, Azure OpenAI, Groq, a local Ollama or vLLM):

```sh
export VA_LLM_BASE_URL=http://localhost:11434/v1 VA_LLM_API_KEY=ollama VA_LLM_MODEL=qwen2.5:14b
vatriage triage out/findings.json --code lab/netcfg-service \
  --sbom lab/netcfg-service/sbom/netcfg-service.cdx.json --agent -o out/decisions-agent.json
vatriage eval out/findings.json out/decisions-agent.json --truth lab/ground_truth.yaml --export-run out/run-agent.json
aec gate out/run-rules-safe.json out/run-agent.json      # the agent must not regress any critical case
```

The MCP server can also be used on its own from an IDE assistant or a desktop client:
`python -m vatriage.mcp_server --findings ... --code ... --sbom ... --advisories data/advisories --kev data/kev.json`.
Tools: `get_finding`, `get_advisory`, `search_advisories`, `find_usages`, `read_code`,
`get_dependency_path`, `get_deployment_config`.

## Labelling policy (ground truth)

- **affected**: the vulnerable code path is reachable from the service with input an adversary can
  influence. Exploit preconditions are written down but do not change the label.
- **not affected**: the code is not used, its input cannot be controlled, or an inline mitigation blocks it.
- For code findings, affected = true positive and not affected = false positive.

## Tests and CI

36 tests: CVSS 3.x scores against the specification, OSV version ranges, SBOM graphs, cleaning and redaction,
de-duplication, symbol extraction, constant-input detection, every rule, guardrails, reports, evaluation,
the CLI, and **7 agent tests that drive the real MCP server over stdio with a scripted model** (evidence
check, invented evidence, KEV guardrail, LLM outage, prompt injection, path traversal).

CI runs tests on Python 3.11 to 3.13, lints and Bandit-scans the tool, runs the VA pipeline on the lab, uploads
the report, VEX and SARIF, runs the agent-eval gate, and **dogfoods**: it builds an SBOM of this tool, pulls
fresh advisories and KEV data, and triages its own dependencies. A manual job runs the LLM agent with
repository secrets and gates it against the safe rules.

## Limits

- Python ecosystem (PyPI advisories, Python AST). The pipeline accepts any SARIF, but reachability is Python-only.
- Reachability is static and best-effort: it shows whether an API is used, not every data flow.
- The lab ground truth is my own analysis of 85 findings; a second reviewer would make it stronger.

Data: PyPA advisory database (CC-BY 4.0), CISA KEV catalog (public domain).
Built with an AI coding assistant; every change was gated by the tests, linters and the evaluation above.
