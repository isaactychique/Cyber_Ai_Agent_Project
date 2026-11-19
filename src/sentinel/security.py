import re

from sentinel.audit import log_event


TOOL_ARGUMENTS = {
    "calculator": {"expression"},
    "read_document": {"filename"},
    "search_documents": {"query"},
}

# A higher risk score means the session needs tighter permissions.
TOOL_RISK_LIMITS = {
    "calculator": 0.60,
    "read_document": 0.40,
    "search_documents": 0.40,
}

SIGNAL_PENALTIES = {
    "prompt_injection_attempt": 0.45,
    "path_traversal_attempt": 0.70,
    "code_execution_attempt": 0.70,
    "unknown_tool_attempt": 0.70,
    "invalid_tool_arguments": 0.40,
    "document_prompt_injection": 0.70,
}

INJECTION_PATTERNS = (
    re.compile(
        r"\b(?:ignore|disregard|forget)\b.{0,60}\b"
        r"(?:previous|prior|all|system|developer)\b.{0,50}\b"
        r"(?:instructions?|rules?|prompts?)\b",
        re.IGNORECASE | re.DOTALL,
    ),
    re.compile(
        r"\b(?:reveal|show|print|output|repeat|disclose)\b.{0,50}\b"
        r"(?:system|developer|hidden)\b.{0,30}\b(?:prompt|instructions?)\b",
        re.IGNORECASE | re.DOTALL,
    ),
    re.compile(r"\bsystem\s+override\b", re.IGNORECASE),
)
PATH_TRAVERSAL_PATTERN = re.compile(r"(?:\.\.[/\\])|%2e%2e(?:%2f|%5c)", re.IGNORECASE)
CODE_EXECUTION_PATTERN = re.compile(
    r"__import__\s*\(|\bos\.system\s*\(|\bsubprocess\b|\beval\s*\(",
    re.IGNORECASE,
)


def detected_signals(text: str) -> list[str]:
    signals = []
    if any(pattern.search(text) for pattern in INJECTION_PATTERNS):
        signals.append("prompt_injection_attempt")
    if PATH_TRAVERSAL_PATTERN.search(text):
        signals.append("path_traversal_attempt")
    if CODE_EXECUTION_PATTERN.search(text):
        signals.append("code_execution_attempt")
    return signals


class SecurityState:
    """Per-session risk state; every tool call still gets a fresh policy check."""

    def __init__(self):
        self.risk_score = 0.0

    def observe_user_input(self, text: str) -> list[str]:
        signals = detected_signals(text)
        if signals:
            for signal in signals:
                self._record_signal(signal, "user_input")
        else:
            self.risk_score = max(0.0, self.risk_score - 0.05)
            log_event("risk_update", {
                "source": "user_input",
                "reason": "no_detected_signal",
                "risk_score": round(self.risk_score, 2),
            })
        return signals

    def observe_document(self, text: str) -> bool:
        if any(pattern.search(text) for pattern in INJECTION_PATTERNS):
            self._record_signal("document_prompt_injection", "document")
            return True
        return False

    def authorize_tool(self, tool_name: str, arguments) -> tuple[bool, str]:
        expected_arguments = TOOL_ARGUMENTS.get(tool_name)
        if expected_arguments is None:
            self._record_signal("unknown_tool_attempt", "tool_call")
            log_event("policy_decision", {
                "tool": str(tool_name),
                "status": "denied",
                "reason": "tool_not_allowlisted",
                "risk_score": round(self.risk_score, 2),
            })
            return False, "tool_not_allowlisted"

        if not isinstance(arguments, dict) or set(arguments) != expected_arguments:
            self._record_signal("invalid_tool_arguments", "tool_call")
            log_event("policy_decision", {
                "tool": tool_name,
                "status": "denied",
                "reason": "invalid_arguments",
                "risk_score": round(self.risk_score, 2),
            })
            return False, "invalid_arguments"

        limit = TOOL_RISK_LIMITS[tool_name]
        if self.risk_score >= limit:
            log_event("policy_decision", {
                "tool": tool_name,
                "status": "denied",
                "reason": "risk_threshold_exceeded",
                "risk_score": round(self.risk_score, 2),
            })
            return False, "risk_threshold_exceeded"

        log_event("policy_decision", {
            "tool": tool_name,
            "status": "allowed",
            "reason": "allowlisted_and_arguments_valid",
            "risk_score": round(self.risk_score, 2),
        })
        return True, "authorized"

    def _record_signal(self, signal: str, source: str):
        penalty = SIGNAL_PENALTIES[signal]
        self.risk_score = min(1.0, self.risk_score + penalty)
        log_event("security_signal", {
            "signal": signal,
            "source": source,
            "risk_score": round(self.risk_score, 2),
        })
