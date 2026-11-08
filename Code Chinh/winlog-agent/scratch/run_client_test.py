import subprocess, time, pathlib

cmd = [
    "powershell.exe",
    "-NoProfile",
    "-ExecutionPolicy", "Bypass",
    "-File", "winlog-agent\\client_agent.ps1",
    "-ServerUrl", "https://127.0.0.1:9443/ingest"
]

proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8")
time.sleep(6)
proc.terminate()
stdout, stderr = proc.communicate(timeout=5)

print("--- CLIENT AGENT STDOUT ---")
print(stdout)
if stderr:
    print("--- CLIENT AGENT STDERR ---")
    print(stderr)

