import pytest
import subprocess
import sys
import os
import tempfile


@pytest.mark.parametrize("payload", [
    "'; rm -rf / #",
    "$(whoami)",
    "`id`",
    "normal_valid_data",
])
def test_shell_injection_not_possible_in_stats_influxdb(payload, monkeypatch):
    """Invariant: Shell commands never include unsanitized user input"""
    executed_commands = []

    # Patch os.system to capture the command string without executing it
    monkeypatch.setattr(os, "system", lambda cmd: executed_commands.append(cmd) or 0)

    # We need to simulate the script being called with a payload that could
    # end up in the curl command. The script reads from locust stats, so we
    # patch the relevant parts to inject our payload as database name / host.
    
    # Create a wrapper that imports and runs the relevant code path
    test_script = tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False)
    test_script.write(f"""
import os
import sys

executed = []
original_system = os.system
def capture_system(cmd):
    print("CMD:" + cmd, flush=True)
    return 0
os.system = capture_system

# Simulate the vulnerable pattern from stats_influxdb.py
host = "{payload.replace('"', '\\"')}"
port = "8086"
database = "{payload.replace('"', '\\"')}"
data = "{payload.replace('"', '\\"')}"

os.system("curl -i -XPOST 'http://%s:%s/write?db=%s&precision=s' --data-binary '%s'" % (host, port, database, data))
""")
    test_script.close()

    result = subprocess.run([sys.executable, test_script.name], capture_output=True, text=True)
    os.unlink(test_script.name)

    # Extract the command that would have been executed
    for line in result.stdout.splitlines():
        if line.startswith("CMD:"):
            cmd = line[4:]
            # Security invariant: shell metacharacters must be escaped or rejected
            # If payload contains shell metacharacters, they should NOT appear unescaped
            if payload != "normal_valid_data":
                # The vulnerable code passes these directly - this test documents the vulnerability
                # A secure implementation would escape or reject these characters
                dangerous_chars = ["'", ";", "$", "`", "|", "&"]
                has_injection = any(
                    c in payload and payload in cmd
                    for c in dangerous_chars
                    if c in payload
                )
                assert not has_injection, (
                    f"Shell injection possible: payload '{payload}' appears unsanitized in command: {cmd}"
                )