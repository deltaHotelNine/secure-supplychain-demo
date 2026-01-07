import subprocess
from flask import Flask, request

app = Flask(__name__)

# Vulnerability #1: Hardcoded Secret (CWE-798)
API_KEY = "12345-SUPER-SECRET-KEY-DO-NOT-COMMIT"

@app.route("/")
def home():
    return "Welcome to the Secure Supply Chain Demo!"


@app.route("/status")
def status():
    return {"status": "All systems operational"}


# Vulnerability #2: Remote Command Execution (RCE) / Command Injection (CWE-78)
@app.route("/debug")
def debug():
    cmd = request.args.get("cmd", "whoami")
    # This is intentionally vulnerable code for demonstration purposes
    return subprocess.check_output(cmd, shell=True)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
