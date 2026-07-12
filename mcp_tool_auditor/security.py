"""Security warnings for offensive simulation tooling."""

from __future__ import annotations

import os
import sys

AUTHORIZED_TESTING_BANNER = """
================================================================
 MCP TOOL AUDITOR - AUTHORIZED TESTING ONLY
================================================================
This command starts offensive MCP simulation tooling.

Use it only against systems you own or have explicit permission
to test. Unauthorized testing can be illegal and harmful.

See SECURITY.md for responsible disclosure guidance.
================================================================
"""

ATPA_SPECIFIC = """
This simulates ATPA behavioral poisoning: tools appear benign, then
return malicious error text after a configurable call threshold.
"""

RUG_PULL_SPECIFIC = """
This simulates rug-pull behavior: a server serves benign tools first,
then swaps to poisoned definitions after approval.
"""

STI_SPECIFIC = """
This simulates Special Token Injection (STI) time-bomb behavior: tools
appear benign, then emit a model chat-template control token (e.g.
<|im_start|>, DeepSeek's fullwidth <｜User｜>) in their response text
after a configurable call threshold, to spoof/close a conversation turn.
"""


def print_security_warning(specific: str = "") -> None:
    """Print an authorization warning to stderr.

    Deliberately stderr, not stdout: a command's actual report (json/sarif/
    markdown) goes to stdout, and this banner must never end up mixed into
    it if that output is piped or redirected -- e.g. `inventory --probe
    --format json | jq` must still get valid JSON on stdout regardless of
    whether the warning printed.
    """
    print(AUTHORIZED_TESTING_BANNER, file=sys.stderr)
    if specific:
        print(specific, file=sys.stderr)


def require_ack(auto_ack: bool = False) -> bool:
    """Require user acknowledgement unless an explicit bypass is provided.

    The prompt is written to stderr manually, then read with a bare
    input() -- input(prompt) always writes its prompt to stdout, which
    would otherwise land in the middle of a piped/redirected report the
    same way print_security_warning's banner would.
    """
    if auto_ack or os.environ.get("MCP_TOOL_AUDITOR_ASSUME_AUTHORIZED") in {
        "1",
        "true",
        "yes",
    }:
        return True

    print(
        "Do you acknowledge you are authorized to run this simulation? [yes/no]: ",
        end="",
        file=sys.stderr,
    )
    response = input()
    return response.strip().lower() in {"yes", "y"}
