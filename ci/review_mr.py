import os
import sys
import json
import requests

# GitLab environment variables
API_URL = os.getenv("CI_API_V4_URL", "https://gitlab.nic.cz")
PROJECT_ID = os.getenv("CI_PROJECT_ID", 2)
MR_IID = os.getenv("CI_MERGE_REQUEST_IID")

# CZ.NIC Spark Configuration
CZNIC_BASE_URL = os.getenv("MY_AI_API_ENDPOINT", "https://spark-dev.office.nic.cz/api")
AI_API_KEY = os.getenv("AI_API_KEY")
MODEL_NAME = "Qwen/Qwen3.6-35B-A3B"

OUTPUT_FILE = "ai_review.md"

def get_mr_diff():
    url = f"{API_URL}/projects/{PROJECT_ID}/merge_requests/{MR_IID}/changes"
    res = requests.get(url)
    res.raise_for_status()

    changes = res.json().get("changes", [])
    diff_text = ""
    for change in changes:
        # Ignore dependency lock files to preserve token context
        if any(change['new_path'].endswith(ext) for ext in ['.lock', '-lock.json', '.sum']):
            continue
        diff_text += f"\n--- File: {change['new_path']} ---\n{change['diff']}\n"
    return diff_text

def validate_with_spark(diff_text):
    prompt = f"""You are a senior code reviewer evaluating a Git Merge Request diff for validity.

Check for:
1. Syntax errors, obvious logical flaws, or edge-case bugs.
2. Hardcoded secrets or security risks.
3. Look for grammatical mistakes.

Diff:
{diff_text}

Respond STRICTLY with a valid JSON object using this exact key structure:
{{
    "valid": true,
    "summary": "Brief summary of evaluation",
    "issues": ["Issue 1", "Issue 2"]
}}
"""

    endpoint = f"{CZNIC_BASE_URL.rstrip('/')}/v1/chat/completions"

    payload = {
        "model": MODEL_NAME,
        "response_format": {"type": "json_object"},
        "messages": [
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.2
    }

    headers = {
        "Authorization": f"Bearer {AI_API_KEY}",
        "Content-Type": "application/json"
    }

    res = requests.post(endpoint, json=payload, headers=headers, timeout=600, verify=False)
    res.raise_for_status()

    response_data = res.json()
    return response_data["choices"][0]["message"]["content"]

def main():
    if MR_IID is None:
        print("Missing MR ID")
        sys.exit(1)
    if AI_API_KEY is None:
        print("Missing AI API key")
        sys.exit(1)

    print("Fetching MR diff...")
    diff = get_mr_diff()

    if not diff.strip():
        message = "No relevant changes found in MR diff to review."
        print(message)
        with open(OUTPUT_FILE, "w") as f:
            f.write(message)
        sys.exit(0)

    print(f"Sending diff to CZ.NIC Spark using model: {MODEL_NAME}...")
    ai_raw = validate_with_spark(diff)

    try:
        ai_result = json.loads(ai_raw)
    except json.JSONDecodeError:
        error_msg = f"Failed to parse JSON response from LLM:\n{ai_raw}"
        print(error_msg)
        with open(OUTPUT_FILE, "w") as f:
            f.write(error_msg)
        sys.exit(1)

    # Format markdown review
    status_icon = "✅" if ai_result.get("valid") else "❌"
    report = f"# {status_icon} CZ.NIC Spark AI Review\n\n"
    report += f"**Summary:** {ai_result.get('summary', 'N/A')}\n\n"

    issues = ai_result.get("issues", [])
    if issues:
        report += "### Detected Issues:\n" + "\n".join([f"- {issue}" for issue in issues]) + "\n"
    else:
        report += "No major issues detected.\n"

    # Write report to file artifact
    with open(OUTPUT_FILE, "w") as f:
        f.write(report)

    # Print to console output
    print("\n" + "="*40)
    print(report)
    print("="*40 + "\n")

    if not ai_result.get("valid"):
        print("Validation failed according to Qwen3.6-35B model.")
        sys.exit(1)

    print("Validation passed successfully!")

if __name__ == "__main__":
    main()