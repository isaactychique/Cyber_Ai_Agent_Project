import json

import pytest

from sentinel import audit
from sentinel import triage


def test_evidence_agent_extracts_only_valid_indicators_and_patterns():
    evidence = triage.extract_evidence(
        "Failed password from 203.0.113.77; PowerShell encodedcommand; "
        "contacted malware.example; invalid IP 999.999.1.1"
    )

    assert evidence["indicators"]["ip_addresses"] == ["203.0.113.77"]
    assert evidence["indicators"]["domains"] == ["malware.example"]
    assert evidence["observed_patterns"] == [
        "repeated_authentication_failure",
        "suspicious_script_execution",
    ]
    assert len(evidence["evidence_fingerprint"]) == 64


def test_demo_intel_and_severity_are_explicit_and_deterministic():
    evidence = triage.extract_evidence(
        "Large upload from 203.0.113.77 to malware.example"
    )
    matches = triage.lookup_demo_intelligence(evidence)

    assert len(matches) == 2
    assert triage.score_severity(evidence, matches) == {
        "score": 60,
        "severity": "high",
        "method": "transparent_demo_rules_v1",
    }


def test_triage_report_writer_only_receives_structured_findings(tmp_path, monkeypatch):
    log_file = tmp_path / "audit.jsonl"
    monkeypatch.setattr(audit, "LOG_FILE", log_file)
    captured = {}

    def fake_chat(messages):
        captured["prompt"] = messages[1]["content"]
        return json.dumps({
            "summary": "Two indicators match the synthetic local dataset.",
            "next_steps": ["Validate against trusted telemetry."],
            "limitations": "The bundled intelligence is synthetic.",
        })

    monkeypatch.setattr(triage, "chat", fake_chat)
    report = json.loads(triage.triage_incident(
        "Large upload from 203.0.113.77 to malware.example; UNIQUE_RAW_LOG_SECRET"
    ))

    assert "UNIQUE_RAW_LOG_SECRET" not in captured["prompt"]
    assert report["severity"]["severity"] == "high"
    assert report["demo_intelligence_matches"][0]["confidence"] == "high"
    audit_events = [json.loads(line) for line in log_file.read_text().splitlines()]
    assert [event["details"]["agent"] for event in audit_events if event["event"] == "triage_stage"] == [
        "evidence_analyst", "evidence_analyst", "threat_intelligence", "risk_assessor", "report_writer"
    ]
    assert "UNIQUE_RAW_LOG_SECRET" not in log_file.read_text()


@pytest.mark.parametrize("incident_text", ["", " " , "x" * 20_001])
def test_triage_rejects_empty_or_oversized_incident(incident_text):
    with pytest.raises(ValueError):
        triage.triage_incident(incident_text)
