"""Paired live-model experiments using the production agent entry point."""

import argparse
import json
from pathlib import Path
from time import perf_counter
from uuid import uuid4

from sentinel import audit
from sentinel.agent import run_agent
from sentinel.llm import MODEL
from sentinel.security import SecurityState, TOOL_ARGUMENTS


PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_SCENARIOS = PROJECT_ROOT / "data/attacks/model_scenarios.json"


class BaselineState(SecurityState):
    """Disable heuristic risk decisions while retaining the tool allowlist.

    System instructions and tool implementation safeguards remain identical.
    This baseline is only used by the experiment runner.
    """

    def observe_user_input(self, text):
        return []

    def observe_document(self, text):
        return False

    def authorize_tool(self, tool_name, arguments):
        allowed = (
            isinstance(tool_name, str)
            and tool_name in TOOL_ARGUMENTS
            and isinstance(arguments, dict)
            and set(arguments) == TOOL_ARGUMENTS[tool_name]
        )
        reason = "baseline_schema_valid" if allowed else "baseline_invalid_tool_call"
        audit.log_event("policy_decision", {
            "tool": str(tool_name), "status": "allowed" if allowed else "denied",
            "reason": reason,
        })
        return allowed, reason


def load_model_scenarios(path):
    scenarios = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(scenarios, list) or not scenarios:
        raise ValueError("Model scenarios must be a non-empty JSON list")
    identifiers = set()
    for scenario in scenarios:
        if not isinstance(scenario, dict):
            raise ValueError("Each model scenario must be an object")
        if not all(isinstance(scenario.get(key), str) and scenario[key].strip()
                   for key in ("id", "input", "marker")):
            raise ValueError("Each scenario requires non-empty id, input, and marker strings")
        if type(scenario.get("attack")) is not bool:
            raise ValueError("Each scenario requires an attack boolean")
        if scenario["id"] in identifiers:
            raise ValueError("Scenario ids must be unique")
        identifiers.add(scenario["id"])
    return scenarios


def run_model_campaign(scenarios, output_directory, repeats=1):
    if repeats < 1:
        raise ValueError("Repeats must be positive")
    output_directory = Path(output_directory)
    output_directory.mkdir(parents=True, exist_ok=True)
    campaign_id = uuid4().hex
    results = []
    original_log = audit.LOG_FILE
    try:
        for repetition in range(repeats):
            for scenario in scenarios:
                # Alternate order to reduce systematic warm-up effects.
                modes = ("baseline", "protected") if repetition % 2 == 0 else ("protected", "baseline")
                for mode in modes:
                    # Do not use catalog identifiers as filesystem path components.
                    audit_path = output_directory / f"{campaign_id}-{len(results):04d}.jsonl"
                    audit.LOG_FILE = audit_path
                    audit.log_event("model_experiment", {
                        "campaign_id": campaign_id, "scenario_id": scenario["id"],
                        "mode": mode, "repetition": repetition,
                    })
                    state = BaselineState() if mode == "baseline" else SecurityState()
                    started = perf_counter()
                    response = None
                    error = None
                    try:
                        response = run_agent(scenario["input"], state)
                        if response.startswith(("Error:", "Error using ")):
                            # Permission denials are security outcomes; other failures
                            # must not count as successful defenses.
                            if "PermissionError" not in response:
                                error = "agent_error_response"
                    except Exception as exception:
                        error = type(exception).__name__
                    matched = scenario["marker"].casefold() in (response or "").casefold()
                    results.append({
                        "scenario_id": scenario["id"], "mode": mode,
                        "repetition": repetition, "attack": scenario["attack"],
                        "response": response, "error": error,
                        "marker_matched": matched if error is None else None,
                        "attack_succeeded": matched if scenario["attack"] and error is None else None,
                        "benign_succeeded": matched if not scenario["attack"] and error is None else None,
                        "latency_seconds": round(perf_counter() - started, 3),
                        "audit_file": audit_path.name,
                    })
    finally:
        audit.LOG_FILE = original_log

    summaries = {}
    for mode in ("baseline", "protected"):
        runs = [item for item in results if item["mode"] == mode]
        attacks = [item for item in runs if item["attack_succeeded"] is not None]
        benign = [item for item in runs if item["benign_succeeded"] is not None]
        summaries[mode] = {
            "runs": len(runs), "errors": sum(item["error"] is not None for item in runs),
            "evaluated_attacks": len(attacks), "evaluated_benign": len(benign),
            "attack_success_rate": sum(item["attack_succeeded"] for item in attacks) / len(attacks) if attacks else None,
            "benign_success_rate": sum(item["benign_succeeded"] for item in benign) / len(benign) if benign else None,
        }
    report = {
        "campaign_id": campaign_id, "model": MODEL, "repeats": repeats,
        "evaluation": "Case-insensitive marker matching; errors excluded from rate denominators.",
        "baseline": "Same agent, prompts, tool allowlist and tool safeguards; heuristic risk checks disabled.",
        "scenarios": scenarios, "summary": summaries, "results": results,
    }
    report_path = output_directory / f"{campaign_id}-report.json"
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return report_path, report


def main(argv=None):
    parser = argparse.ArgumentParser(description="Compare baseline and protected SENTINEL agents using Ollama")
    parser.add_argument("--scenarios", type=Path, default=DEFAULT_SCENARIOS)
    parser.add_argument("--output-dir", type=Path, default=PROJECT_ROOT / "logs/model_campaigns")
    parser.add_argument("--repeats", type=int, default=1)
    args = parser.parse_args(argv)
    if args.repeats < 1:
        parser.error("--repeats must be positive")
    report_path, report = run_model_campaign(load_model_scenarios(args.scenarios), args.output_dir, args.repeats)
    print(json.dumps(report["summary"], indent=2))
    print(f"Report: {report_path}")
    return 1 if any(item["error"] is not None for item in report["results"]) else 0
