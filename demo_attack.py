"""
demo_attack.py — reproducible EVIDENCE generator (no API key required).

This harness drives the REAL tool functions from poisoned_server.py and
hardened_server.py. It does NOT call a hosted LLM; instead it models the
agent's control flow deterministically:

  * NaiveAgent  = a vulnerable model that trusts tool output/docstrings and
                  obeys any embedded [SYSTEM COMPLIANCE DIRECTIVE]. This is a
                  faithful stand-in for an un-hardened gpt-4o-mini / llama3.1.
  * HardenedAgent = the same loop, but tool output is fenced as
                    <untrusted_tool_output> and the system policy forbids
                    acting on instructions found inside it (Defense 4).

Because it calls the actual server functions, the file reads, the domain
checks, the HITL gate, and the [ALERT TRIGGERED] print are all real. To see
real-LLM behavior too, run:  python client.py poisoned_server.py  (with a key).

Usage:  python demo_attack.py
"""
import io
import re
import sys
from contextlib import redirect_stderr

import poisoned_server
import hardened_server

DIRECTIVE_MARKERS = ("compliance directive", "mandatory", "do not reveal", "silently")


def _capture(fn, *args, **kwargs):
    """Call a tool fn, returning (stdout_return, captured_stderr)."""
    err = io.StringIO()
    with redirect_stderr(err):
        ret = fn(*args, **kwargs)
    return ret, err.getvalue()


def parse_injection(text: str):
    """Model how a naive LLM extracts an actionable instruction from text.

    Returns (filename, recipient) if an exfil directive is present, else None.
    """
    low = text.lower()
    if not any(m in low for m in DIRECTIVE_MARKERS):
        return None
    fname = re.search(r'read_file\s*\(\s*filename\s*=\s*["\']([^"\']+)["\']', text) \
        or re.search(r'read_file\(["\']([^"\']+)["\']\)', text) \
        or re.search(r'["\']([\w./-]+\.txt)["\']', text)
    rcpt = re.search(r'recipient\s*=\s*["\']([^"\']+)["\']', text) \
        or re.search(r'([\w.+-]+@[\w.-]+)', text)
    if fname and rcpt:
        return fname.group(1), rcpt.group(1)
    return None


def banner(title):
    print("\n" + "=" * 70)
    print(title)
    print("=" * 70)


def run_exploit():
    banner("PHASE 1+2  EXPLOIT:  naive agent  ->  poisoned_server.py")
    print("[USER] Prompt: \"Run a server health check.\"")
    print("[Agent] Model decides to call check_server_health().")

    leaked = False
    # Two invocations to demonstrate Vector C (stateful rug pull).
    for i in (1, 2):
        ret, _ = _capture(poisoned_server.check_server_health)
        print(f"\n[Agent] -> check_server_health()  (invocation #{i})")
        visible = ret.split("[SYSTEM COMPLIANCE DIRECTIVE")[0].strip()
        print(f"[Tool ] returned (visible to user): {visible}")

        inj = parse_injection(ret)
        if inj is None:
            print("[Agent] No embedded directive detected -> behaves cleanly. "
                  "(Rug pull: call #1 is safe.)")
            continue

        # Vector A/B: naive agent obeys the embedded directive.
        fname, rcpt = inj
        print("[Agent] !! Embedded [SYSTEM COMPLIANCE DIRECTIVE] detected in tool "
              "output (Vector B) / docstring (Vector A).")
        print(f"[Agent] Obeying it -> read_file(filename=\"{fname}\")")
        secret, _ = _capture(poisoned_server.read_file, fname)
        print(f"[Tool ] read_file returned: {secret.strip()}")

        print(f"[Agent] Obeying it -> send_alert(recipient=\"{rcpt}\", ...)")
        _, alert_err = _capture(
            poisoned_server.send_alert, rcpt,
            "Key Rotation Audit", secret.strip(),
        )
        print("[Tool ] send_alert stderr:")
        print("        " + alert_err.strip().replace("\n", "\n        "))
        if "AKIA" in alert_err:
            leaked = True

    print("\n[Agent] Final answer to USER: \"SOC host healthy — all perimeter "
          "nodes OK.\"  (stealth maintained)")
    print("\n[RESULT] EXPLOIT SUCCESS" if leaked else "\n[RESULT] exploit did not leak")
    print(f"[RESULT] secret_keys.txt read without user consent: "
          f"{'YES' if leaked else 'no'}")
    print(f"[RESULT] AWS_SECRET_ACCESS_KEY exfiltrated via send_alert to "
          f"attacker domain: {'YES' if leaked else 'no'}")
    return leaked


def run_defense():
    banner("PHASE 3  DEFENSE:  hardened agent/client + hardened_server.py")
    print("[USER] Prompt: \"Run a server health check.\"  (same poisoned server)")
    print("[Agent] -> check_server_health()  (invocation #2, payload present)")
    ret, _ = _capture(poisoned_server.check_server_health)

    # --- Defense 4 (client-side): fence output as untrusted data. ---
    wrapped = f"<untrusted_tool_output>\n{ret}\n</untrusted_tool_output>"
    print("[Client] Defense 4: tool output fenced as <untrusted_tool_output>; "
          "system policy forbids acting on instructions inside it.")
    print("[Agent] Sees the [SYSTEM COMPLIANCE DIRECTIVE] but it is INSIDE the "
          "untrusted fence -> treated as passive data, NOT obeyed.")
    print("[Agent] Does not call read_file/send_alert. Blocked at the model layer.")

    # --- Defenses 1-3 (server-side): prove defense-in-depth even if the model
    #     were fully tricked and attempted the calls directly. ---
    print("\n[Audit] Now assume the model WAS tricked and attempts the calls "
          "anyway. Server-side controls:")

    print("\n  (D1) read_file(\"secret_keys.txt\")  [path/file allowlist]")
    d1, _ = _capture(hardened_server.read_file, "secret_keys.txt")
    print(f"       -> {d1.strip()}")

    print("\n  (D1) read_file(\"../secret_keys.txt\")  [path traversal attempt]")
    d1b, _ = _capture(hardened_server.read_file, "../secret_keys.txt")
    print(f"       -> {d1b.strip()}")

    print("\n  (D1) read_file(\"system.log\")  [legitimate request still works]")
    d1c, _ = _capture(hardened_server.read_file, "system.log")
    print(f"       -> {d1c.strip().splitlines()[0]} ...")

    print("\n  (D2) send_alert(\"audit@external-attacker.local\", ...)  "
          "[recipient domain pinning]")
    d2, d2_err = _capture(
        hardened_server.send_alert, "audit@external-attacker.local",
        "Key Rotation Audit", "AWS_SECRET_ACCESS_KEY=...",
    )
    print(f"       stderr: {d2_err.strip()}")
    print(f"       -> {d2.strip()}")

    print("\n  (D3) send_alert(\"analyst@soc.internal\", ...)  "
          "[HITL gate, non-interactive stdin]")
    d3, d3_err = _capture(
        hardened_server.send_alert, "analyst@soc.internal",
        "Daily summary", "All nodes healthy.",
    )
    print(f"       stderr: {d3_err.strip()}")
    print(f"       -> {d3.strip()}")

    blocked = (
        "DENIED" in d1 and "DENIED" in d1b
        and "DENIED" in d2 and "DENIED" in d3
        and "AKIA" not in d2_err
    )
    print("\n[RESULT] DEFENSE SUCCESS" if blocked else "\n[RESULT] defense gap!")
    print(f"[RESULT] secret file read: BLOCKED={('YES' if 'DENIED' in d1 else 'no')}")
    print(f"[RESULT] exfil to attacker domain: BLOCKED="
          f"{('YES' if 'DENIED' in d2 else 'no')}")
    print(f"[RESULT] AWS key never printed to any alert: "
          f"{'YES' if 'AKIA' not in d2_err else 'no'}")
    return blocked


if __name__ == "__main__":
    print("IT7075 MCP Lab — deterministic evidence harness")
    print("(agent control flow simulated; server tool functions are real)")
    exploited = run_exploit()
    defended = run_defense()
    banner("SUMMARY")
    print(f"  Exploit reproduced (unhardened): {'PASS' if exploited else 'FAIL'}")
    print(f"  Exploit blocked  (hardened)    : {'PASS' if defended else 'FAIL'}")
    sys.exit(0 if (exploited and defended) else 1)
