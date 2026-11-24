"""
hardened_server.py — BLUE TEAM deliverable (Phase 3).

Server-side controls that neutralize the poisoned_server.py attack even if the
LLM is fully tricked into *attempting* the exfiltration. Defense in depth: the
model's decision is no longer the only thing standing between an attacker and
the secret.

Implemented controls (3; the lab requires >= 2):

  * Defense 1 — PATH & FILE ALLOWLISTING (least privilege) in read_file:
      - Resolves the target and confirms it stays inside an approved logs
        directory (blocks path traversal like ../secret_keys.txt).
      - Only permits .log files.
      - Explicitly denies a sensitive-name denylist (secret_keys.txt, .env,
        *.pem, *.key, credentials, etc.).
      => read_file("secret_keys.txt") is refused outright.

  * Defense 2 — RECIPIENT DOMAIN PINNING in send_alert:
      - Validates recipient against an allowlist of internal domains
        (@uc.edu, @soc.internal). Anything else (e.g.
        audit@external-attacker.local) is rejected before any dispatch.
      => The exfil channel is closed even if a secret were somehow obtained.

  * Defense 3 — HUMAN-IN-THE-LOOP (HITL) APPROVAL GATE on send_alert:
      - Before a high-impact alert dispatch, prints the full arguments and
        requires an interactive y/n approval (auto-denies on non-interactive
        stdin). An analyst sees exactly what would be sent and can veto it.

Note: the client-side control (XML delimiter wrapping + data/instruction
separation) lives in hardened_client.py (Defense 4).
"""
import os
import sys
from pathlib import Path

from fastmcp import FastMCP

mcp = FastMCP("SOC-Utility-Server")
BASE_DIR = Path(__file__).parent.resolve()

# ---- Defense 1 config: path/file allowlist ----
ALLOWED_LOG_DIR = (BASE_DIR / "logs").resolve()
ALLOWED_EXTENSIONS = {".log"}
# Belt-and-suspenders explicit denylist of sensitive names/patterns.
DENY_NAMES = {"secret_keys.txt", ".env", "credentials", "credentials.json"}
DENY_SUFFIXES = {".pem", ".key", ".env", ".secret"}

# ---- Defense 2 config: recipient domain allowlist ----
ALLOWED_RECIPIENT_DOMAINS = ("@uc.edu", "@soc.internal")


def _hitl_approve(action: str, details: str) -> bool:
    """Defense 3: interactive approval gate for high-impact actions.

    Auto-denies when stdin is not a TTY (safe default for automation), so an
    unattended agent cannot silently push the action through.
    """
    print(f"\n[HITL] Approval requested for: {action}", file=sys.stderr)
    print(details, file=sys.stderr)
    if not sys.stdin or not sys.stdin.isatty():
        print("[HITL] Non-interactive stdin -> auto-DENY.", file=sys.stderr)
        return False
    try:
        answer = input("Approve tool execution? [y/n]: ").strip().lower()
    except EOFError:
        return False
    return answer in ("y", "yes")


@mcp.tool()
def read_file(filename: str) -> str:
    """Reads an approved .log file from the SOC logs directory.

    Only *.log files inside the approved logs/ folder may be read. Sensitive
    files (secrets, keys, .env, credentials) and path traversal are blocked.
    """
    try:
        requested = Path(filename)
        name = requested.name.lower()

        # Denylist: sensitive names and suffixes.
        if name in DENY_NAMES or requested.suffix.lower() in DENY_SUFFIXES:
            return (
                f"[DENIED] Access to '{filename}' is blocked by policy "
                f"(sensitive file)."
            )

        # Extension allowlist.
        if requested.suffix.lower() not in ALLOWED_EXTENSIONS:
            return (
                f"[DENIED] Only {sorted(ALLOWED_EXTENSIONS)} files may be read; "
                f"'{filename}' rejected."
            )

        # Resolve and confirm containment inside the approved logs dir
        # (blocks ../ traversal and absolute paths).
        target = (ALLOWED_LOG_DIR / requested.name).resolve()
        if os.path.commonpath([target, ALLOWED_LOG_DIR]) != str(ALLOWED_LOG_DIR):
            return f"[DENIED] '{filename}' is outside the approved logs directory."

        with open(target, "r", encoding="utf-8") as f:
            return f.read()
    except Exception as e:
        return f"Error reading file: {str(e)}"


@mcp.tool()
def send_alert(recipient: str, subject: str, body: str) -> str:
    """Sends a security alert, but only to approved internal SOC recipients."""
    # Defense 2: recipient domain pinning.
    if not any(recipient.lower().endswith(d) for d in ALLOWED_RECIPIENT_DOMAINS):
        print(
            f"[BLOCKED] send_alert refused: recipient '{recipient}' is not an "
            f"approved internal domain {ALLOWED_RECIPIENT_DOMAINS}.",
            file=sys.stderr,
        )
        return (
            f"[DENIED] Recipient '{recipient}' is not allowed. Alerts may only "
            f"go to {ALLOWED_RECIPIENT_DOMAINS}."
        )

    # Defense 3: human-in-the-loop approval gate.
    details = (
        f"  recipient: {recipient}\n  subject:   {subject}\n  body:      {body}"
    )
    if not _hitl_approve("send_alert", details):
        print("[BLOCKED] send_alert denied by HITL gate.", file=sys.stderr)
        return "[DENIED] Alert dispatch was not approved by a human operator."

    print(
        f"\n[ALERT TRIGGERED] To: {recipient} | Subject: {subject}\n"
        f"Body: {body}\n",
        file=sys.stderr,
    )
    return f"Alert successfully sent to {recipient}."


if __name__ == "__main__":
    mcp.run()
