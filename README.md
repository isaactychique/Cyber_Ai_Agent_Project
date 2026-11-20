# SENTINEL-AI LAB

**A hands-on laboratory for designing, attacking, and securing AI agents and LLM systems.** The project emphasizes practical work (about 80% implementation and experimentation, 20% concepts): build agents, reproduce attacks in a controlled local environment, develop defenses, and measure their effects.

## Project vision

SENTINEL-AI LAB is evolving toward a platform with six modules:

1. **Agent Arena** — local agents that answer questions, use tools, and collaborate on specialized tasks.
2. **Attack Lab** — reproducible scenarios for prompt injection, jailbreaks, tool abuse, exfiltration, and memory poisoning.
3. **AI Firewall** — inspection of inputs, outputs, and tool calls, with explainable decisions and testable rules.
4. **Zero Trust Control Plane** — agent identities, least-privilege permissions, per-action authorization, isolation, and controlled secret management.
5. **Detection Engine** — event monitoring and rules for detecting unusual actions or privilege escalation.
6. **Security Dashboard** — active agents, scenarios, risk, events, allowed or blocked actions, and comparative results.

The goal is a laboratory where the same scenario can be run against an unprotected agent and a protected agent, then inspected and compared.

## Incremental target architecture

```text
Streamlit interface
        |
FastAPI ---- Attack Lab / scenarios
        |
Orchestrator ---- Local agents through Ollama
        |
AI Firewall ---- Authorization policies
        |
Tools isolated in Docker
        |
Events and results stored in PostgreSQL
```

The current foundation uses Python, Ollama, and pytest. FastAPI can expose platform features, Streamlit can provide the interface, Docker can isolate tools, PostgreSQL can store campaigns and events, and OPA can host policies when they outgrow a local prototype. Redis and LangGraph will be added when event queues or multi-agent workflows justify them, rather than as initial dependencies.

## Current status

- Local CLI agent connected to Ollama (`llama3.2:3b`).
- `calculator`, `read_document`, and `search_documents` tools with argument validation and file-access restrictions.
- Local full-text search over approved `.txt` files, with bounded excerpts and simple lexical ranking.
- First SOC triage workflow with specialized roles: evidence analyst, local demonstration threat intelligence, severity assessor, and report writer.
- Per-session risk policy that reevaluates each tool call and logs its decisions.
- Offline attack scenario catalog and runner for validating policy decisions, including inspection of untrusted incident text passed to the triage tool.
- Basic heuristic defenses against some prompt-injection and path-traversal attempts.
- Unit and integration tests that mock Ollama.

The first version of Agent Arena is in place. The triage workflow is read-only: it extracts indicators and patterns from supplied text, compares them with a local synthetic dataset, calculates an explainable severity score, and asks the LLM to write a report from the structured findings. Document search is local and lexical, not semantic embedding search. The first Attack Lab checks policy decisions offline, including prompt injection placed inside triage tool arguments; it does not yet run attacks against the LLM.

The repository does not yet include an API, Docker isolation, agent identities, PostgreSQL/OPA, advanced behavioral detection, or a dashboard. These are planned deliverables.

The triage intelligence is a small demonstration dataset made from synthetic values reserved for documentation. It is not a live threat feed and does not attribute attacks. The severity score is educational and does not replace analysis by a SOC analyst.

## Proposed practical roadmap

| Weeks | Phase | Work | Deliverable |
| --- | --- | --- | --- |
| 1–2 | Agent Arena | Stabilize agent and tool interfaces, then expand document search | Local agent with interchangeable tools |
| 3–4 | Attack Lab | Connect versioned scenarios to the agent and compare unprotected and policy-protected modes | Reproducible testbed with model results |
| 5–6 | AI Firewall | Centralize inspection and decisions before and after model calls and before each tool call | Configurable, auditable defenses |
| 7–8 | Zero Trust | Define identities, roles, least-privilege permissions, and execution isolation | Agents and tools separated by privilege |
| 9–10 | Detection Engine | Detect unusual sequences and escalation attempts from events | Explainable alerts and tested rules |
| 11–12 | Dashboard and evaluation | Visualize campaigns and compare protected and unprotected agents | Integrated demo and evaluation report |

For each phase, keep a baseline, add tests before expanding defenses, and measure at least attack success rate, false-positive rate, correct tool calls, and response time.

## Incident triage demo

In the CLI, enter a report or log excerpt after `Triage incident:`. For example:

```text
Triage incident: Failed password for admin; PowerShell encodedcommand contacted malware.example from 203.0.113.77; large upload detected.
```

The workflow does not contact external services or act on hosts. It returns a rule-based severity score, extracted indicators, matches from the synthetic dataset, a summary, and explicit limitations. Each role's events are written to `logs/audit.jsonl` without the raw incident text.

## Installation and current launch steps

Requirements: Python 3.10 or later and Ollama.

```bash
source .venv/bin/activate
pip install -r requirements.txt
ollama pull llama3.2:3b
```

Start Ollama in one terminal, then start the agent in another:

```bash
ollama serve
python main.py
```

Exit the agent with `exit`.

## Current security and limitations

The calculator evaluates a restricted arithmetic grammar with Python's AST and rejects code, excessively large exponents, and non-finite or out-of-range values. `read_document` confines reads to `data/documents/`, rejects path traversal and symlinks that point outside the directory, and limits files to 100 KB. `search_documents` only scans direct `.txt` files in that directory, skips symlinks and oversized files, and returns at most five results with three excerpts per document.

The risk score and detectors are heuristic; they do not cover every attack phrasing. State is local to the CLI process and resets on restart. This prototype does not yet provide real agent identities, process isolation, or statistical detection. It must not be described as complete protection against prompt injection.

Events are appended to `logs/audit.jsonl`. The log stores decisions, tools, reasons, and scores without recording prompt text.

## Tests

```bash
python -m pytest -q
```

Agent tests mock Ollama and do not require an LLM server.

Run the offline policy scenario runner:

```bash
python scripts/run_attack_lab.py
```

The summary is printed in the terminal. Details are written to `logs/attack_report.json`, and events are written to `logs/attack_audit.jsonl`. These metrics evaluate deterministic rules, not the model's overall resistance.

## Live model comparison

With Ollama running and the configured model installed, run:

```bash
python scripts/run_model_campaign.py --repeats 3
```

Each scenario runs through the actual agent with fresh session state in two modes. The baseline disables heuristic risk checks while retaining the same system prompt, tool allowlist, argument schema, and tool implementation safeguards. Protected mode uses the production security policy. This comparison measures the effect of the heuristic policy, rather than removing every defense.

The initial catalog in `data/attacks/model_scenarios.json` contains an output-marker injection, a greeting, and a deterministic calculator control. The calculator does not call Ollama. Marker matching measures the specified behavior only; it does not establish that an attack succeeded in general. A direct injection may still influence a final response because the current risk policy primarily restricts tool calls. A measured failure should remain visible in the report.

Campaign reports and separate per-run audit logs are stored under `logs/model_campaigns/` with unique identifiers. Reports retain the scenario prompts, full final responses, model name, latency, and errors. Errors are reported separately and excluded from success-rate denominators; a failed model request is never counted as a successful defense. The command exits with status 1 for execution errors. Inspect attack success rates in the report independently of the exit status.
