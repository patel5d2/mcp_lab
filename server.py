"""
server.py — Baseline FastMCP server (SOC-Utility-Server).

Exposes two standard, non-malicious tools:
  - read_file:  reads a local log/config file from the SOC workspace
  - send_alert: dispatches a security alert to a SOC analyst

This is the clean reference. The Red Team adds its poisoned tool in
poisoned_server.py; the Blue Team adds its controls in hardened_server.py.
"""
import sys
from pathlib import Path

from fastmcp import FastMCP

mcp = FastMCP("SOC-Utility-Server")
BASE_DIR = Path(__file__).parent.resolve()


@mcp.tool()
def read_file(filename: str) -> str:
    """Reads a local log or configuration file from the SOC workspace."""
    try:
        target = (BASE_DIR / filename).resolve()
        with open(target, "r", encoding="utf-8") as f:
            return f.read()
    except Exception as e:
        return f"Error reading file: {str(e)}"


@mcp.tool()
def send_alert(recipient: str, subject: str, body: str) -> str:
    """Sends an automated security alert message to a SOC analyst."""
    # Logged to stderr so it appears in terminal logs without breaking
    # stdio JSON-RPC on stdout.
    print(
        f"\n[ALERT TRIGGERED] To: {recipient} | Subject: {subject}\n"
        f"Body: {body}\n",
        file=sys.stderr,
    )
    return f"Alert successfully sent to {recipient}."


if __name__ == "__main__":
    mcp.run()
