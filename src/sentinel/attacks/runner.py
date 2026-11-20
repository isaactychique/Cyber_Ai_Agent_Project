import argparse
import json
from pathlib import Path

from sentinel import audit
from sentinel.security import SecurityState


PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_SCENARIOS = PROJECT_ROOT / "data" / "attacks" / "scenarios.json"


def evaluate_scenario(scenario: dict) -> dict:
    state = SecurityState()
    state.observe_user_input(scenario["input"])

    document_blocked = False
    if "document_content" in scenario:
        document_blocked = state.observe_document(scenario["document_content"])

    tool_authorized = None
    denial_reason = None
    if "tool" in scenario:
        tool_authorized, denial_reason = state.authorize_tool(
            scenario["tool"], scenario.get("arguments")
        )

    observed_signals = [entry["signal"] for entry in state.signals]
    expected_signals = scenario.get("expected_signals", [])
    checks = {
        "signals_match": sorted(observed_signals) == sorted(expected_signals),
    }

    if "expected_tool_authorized" in scenario:
        checks["tool_decision_matches"] = (
            tool_authorized == scenario["expected_tool_authorized"]
        )
    if "expected_document_blocked" in scenario:
        checks["document_decision_matches"] = (
            document_blocked == scenario["expected_document_blocked"]
        )

    return {
        "id": scenario["id"],
        "category": scenario["category"],
        "attack": scenario["attack"],
        "passed": all(checks.values()),
        "checks": checks,
        "observed_signals": observed_signals,
        "tool_authorized": tool_authorized,
        "denial_reason": denial_reason,
        "document_blocked": document_blocked,
        "risk_score": round(state.risk_score, 2),
    }


def run_scenarios(scenarios: list[dict], audit_log_path: Path | None = None) -> dict:
    original_audit_path = audit.LOG_FILE
    if audit_log_path is not None:
        audit.LOG_FILE = Path(audit_log_path)

    try:
        results = [evaluate_scenario(scenario) for scenario in scenarios]
    finally:
        audit.LOG_FILE = original_audit_path

    attacks = [result for result in results if result["attack"]]
    benign = [result for result in results if not result["attack"]]
    attack_detections = sum(
        bool(result["observed_signals"])
        or result["tool_authorized"] is False
        or result["document_blocked"]
        for result in attacks
    )
    false_positives = sum(
        bool(result["observed_signals"])
        or result["tool_authorized"] is False
        or result["document_blocked"]
        for result in benign
    )

    return {
        "summary": {
            "scenario_count": len(results),
            "passed": sum(result["passed"] for result in results),
            "failed": sum(not result["passed"] for result in results),
            "attack_count": len(attacks),
            "attack_detection_rate": (
                attack_detections / len(attacks) if attacks else None
            ),
            "benign_count": len(benign),
            "false_positive_rate": (
                false_positives / len(benign) if benign else None
            ),
        },
        "results": results,
    }


def load_scenarios(path: Path) -> list[dict]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        raise ValueError("Scenario file must contain a JSON list")
    required = {"id", "category", "attack", "input"}
    for scenario in payload:
        if not isinstance(scenario, dict) or not required.issubset(scenario):
            raise ValueError("Each scenario must define id, category, attack, and input")
    return payload


def main(argv=None):
    parser = argparse.ArgumentParser(description="Run offline SENTINEL-AI policy scenarios")
    parser.add_argument("--scenarios", type=Path, default=DEFAULT_SCENARIOS)
    parser.add_argument("--report", type=Path, default=PROJECT_ROOT / "logs" / "attack_report.json")
    parser.add_argument("--audit", type=Path, default=PROJECT_ROOT / "logs" / "attack_audit.jsonl")
    args = parser.parse_args(argv)

    report = run_scenarios(load_scenarios(args.scenarios), args.audit)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report["summary"], indent=2))
    return 1 if report["summary"]["failed"] else 0
