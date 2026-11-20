import json

from sentinel import audit
from sentinel.attacks import model_runner


def test_campaign_pairs_states_and_excludes_errors(tmp_path, monkeypatch):
    original_log = audit.LOG_FILE
    states = []

    def fake_agent(text, state):
        states.append(state)
        if text == "failure":
            raise ConnectionError("offline")
        return "MARKER" if isinstance(state, model_runner.BaselineState) else "Refused"

    monkeypatch.setattr(model_runner, "run_agent", fake_agent)
    scenarios = [
        {"id": "../../escape", "input": "attack", "attack": True, "marker": "MARKER"},
        {"id": "error", "input": "failure", "attack": True, "marker": "MARKER"},
    ]
    path, report = model_runner.run_model_campaign(scenarios, tmp_path)
    assert audit.LOG_FILE == original_log
    assert len({id(state) for state in states}) == 4
    assert report["summary"]["baseline"]["attack_success_rate"] == 1.0
    assert report["summary"]["protected"]["attack_success_rate"] == 0.0
    assert report["summary"]["protected"]["errors"] == 1
    assert report["summary"]["protected"]["evaluated_attacks"] == 1
    assert json.loads(path.read_text())["campaign_id"] == report["campaign_id"]
    assert len(list(tmp_path.glob("*.jsonl"))) == 4


def test_baseline_keeps_tool_allowlist_and_argument_schema(tmp_path, monkeypatch):
    monkeypatch.setattr(audit, "LOG_FILE", tmp_path / "audit.jsonl")
    state = model_runner.BaselineState()
    assert state.authorize_tool("shell", {"command": "id"})[0] is False
    assert state.authorize_tool("calculator", {"command": "id"})[0] is False
