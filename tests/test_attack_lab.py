import json

import pytest

from sentinel.attacks.runner import DEFAULT_SCENARIOS, load_scenarios, run_scenarios


def test_attack_catalog_passes_policy_scenarios(tmp_path):
    scenarios = load_scenarios(DEFAULT_SCENARIOS)

    report = run_scenarios(scenarios, tmp_path / "attack-audit.jsonl")

    assert report["summary"] == {
        "scenario_count": 8,
        "passed": 8,
        "failed": 0,
        "attack_count": 6,
        "attack_detection_rate": 1.0,
        "benign_count": 2,
        "false_positive_rate": 0.0,
    }
    assert len((tmp_path / "attack-audit.jsonl").read_text(encoding="utf-8").splitlines()) > 0


def test_attack_catalog_blocks_injection_inside_triage_tool_arguments(tmp_path):
    scenarios = load_scenarios(DEFAULT_SCENARIOS)
    report = run_scenarios(scenarios, tmp_path / "attack-audit.jsonl")

    result = next(
        item for item in report["results"]
        if item["id"] == "triage_argument_prompt_injection"
    )

    assert result["observed_signals"] == ["prompt_injection_attempt"]
    assert result["tool_authorized"] is False
    assert result["denial_reason"] == "unsafe_tool_input"


def test_scenario_loader_rejects_invalid_shape(tmp_path):
    scenario_file = tmp_path / "bad.json"
    scenario_file.write_text(json.dumps({"id": "not-a-list"}), encoding="utf-8")

    with pytest.raises(ValueError, match="JSON list"):
        load_scenarios(scenario_file)


def test_scenario_loader_rejects_missing_fields(tmp_path):
    scenario_file = tmp_path / "bad.json"
    scenario_file.write_text(json.dumps([{"id": "incomplete"}]), encoding="utf-8")

    with pytest.raises(ValueError, match="must define"):
        load_scenarios(scenario_file)
