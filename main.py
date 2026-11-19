from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parent
SRC_DIRECTORY = PROJECT_ROOT / "src"
if str(SRC_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SRC_DIRECTORY))

from sentinel.agent import run_agent
from sentinel.security import SecurityState


def main():
    security_state = SecurityState()
    print("=== SENTINEL-AI LAB ===")
    print("Type 'exit' to quit.")

    while True:
        user_input = input("\nUser > ")

        if user_input.lower().strip() == "exit":
            print("Shutting down SENTINEL-AI...")
            break

        if not user_input.strip():
            continue

        try:
            response = run_agent(user_input, security_state)
            print("\nSENTINEL-AI >", response)

        except Exception as error:
            print(f"\nExecution error: {type(error).__name__}: {error}")


if __name__ == "__main__":
    main()
