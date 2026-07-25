"""
ai_explainer.py
-----------------------------------
Sends our scan results to a locally-running open-weight model (via
Ollama) and asks it to explain the risky findings in plain language.

Why a local model instead of calling Claude/OpenAI directly?
The competition rules (Article 9) require AI features to run on an
open-weight model that can be hosted locally/independently, not just
call a closed commercial API. Ollama runs models like Gemma 2 or
Llama 3 fully on your own machine.

Ollama exposes a simple local HTTP API at http://localhost:11434,
so this is just a normal HTTP request - no API key needed.
"""

import json
import requests

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL_NAME = "qwen2.5:0.5b"  # lightweight model, good for limited-resource machines/VMs


def build_prompt(scan_report: list[dict]) -> str:
    """
    Turns the raw scan report into a plain-text prompt for the model.
    We only include packages that need attention, to keep the prompt
    short and focused.
    """
    risky = [item for item in scan_report if item["verdict"] != "ALLOW"]

    if not risky:
        return None

    lines = [
        "Explain these dependency risks to a non-expert developer in 1-2 "
        "short sentences per package, plus one suggested fix. Be concise.",
        "",
    ]

    for item in risky:
        lines.append(f"Package: {item['package']}=={item['version']} ({item['verdict']})")
        if item["vulnerabilities"]:
            # Only include ONE vulnerability summary to keep the prompt short
            lines.append(f"Issue: {item['vulnerabilities'][0]['summary']}")
        elif item["license_status"] != "ALLOWED":
            lines.append(f"Issue: license status is {item['license_status']}")
        lines.append("")

    return "\n".join(lines)


def explain_results(scan_report: list[dict]) -> str:
    """
    Calls the local Ollama model to generate a plain-language explanation
    of the risky findings. Returns the explanation text, or a message if
    there's nothing risky to explain or Ollama isn't reachable.
    """
    prompt = build_prompt(scan_report)

    if prompt is None:
        return "No risky packages found - nothing to explain."

    payload = {
        "model": MODEL_NAME,
        "prompt": prompt,
        "stream": False,
        # num_predict caps how many tokens the model can generate.
        # Lower = faster, which matters a lot on limited hardware (e.g. VMs).
        "options": {"num_predict": 250},
    }

    try:
        # Generation can be slow on constrained hardware, so we give it
        # a generous timeout (5 minutes) rather than failing too early.
        response = requests.post(OLLAMA_URL, json=payload, timeout=300)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        return (
            f"[WARNING] Could not reach local Ollama server: {e}\n"
            f"Make sure Ollama is running (try: ollama list) and that "
            f"'{MODEL_NAME}' has been pulled (try: ollama pull {MODEL_NAME})."
        )

    data = response.json()
    return data.get("response", "[No response text returned]")


if __name__ == "__main__":
    # Manual test: reuse scan_report.json produced by scanner.py
    with open("scan_report.json", "r", encoding="utf-8") as f:
        report = json.load(f)

    explanation = explain_results(report)
    print("\n===== AI Explanation =====\n")
    print(explanation)
