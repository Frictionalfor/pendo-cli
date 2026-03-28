"""
formatter.py - Clean CLI output formatting
"""
import textwrap
import shutil

RESET  = "\033[0m"
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BLUE   = "\033[94m"
BOLD   = "\033[1m"
DIM    = "\033[2m"

RISK_COLOR = {
    "High":   RED,
    "Medium": YELLOW,
    "Low":    CYAN,
    "Info":   BLUE,
}

def _term_width():
    return shutil.get_terminal_size((80, 20)).columns

def _wrap(text, indent=18):
    width = max(40, _term_width() - indent)
    lines = textwrap.wrap(text, width)
    pad = " " * indent
    return f"\n{pad}".join(lines)

def print_info(msg):
    print(f"  {CYAN}[*]{RESET} {msg}")

def print_success(msg):
    print(f"  {GREEN}[+]{RESET} {msg}")

def print_error(msg):
    print(f"  {RED}[!]{RESET} {msg}")

def print_issue(issue):
    risk  = issue.get("risk", "Info")
    color = RISK_COLOR.get(risk, RESET)

    print(f"\n  {color}[!] {issue.get('type')}{RESET}")

    for key, label in [
        ("header",   "Header  "),
        ("endpoint", "Endpoint"),
        ("param",    "Param   "),
        ("payload",  "Payload "),
        ("detail",   "Detail  "),
    ]:
        val = issue.get(key)
        if val:
            print(f"      → {label} : {val}")

    print(f"      → Risk     : {color}{risk}{RESET}")

    confidence = issue.get("confidence")
    if confidence:
        conf_color = GREEN if confidence == "High" else YELLOW if confidence == "Medium" else DIM
        print(f"      → Confidence: {conf_color}{confidence}{RESET}")

    if "reason" in issue:
        wrapped = _wrap(issue["reason"], indent=20)
        print(f"      → Reason   : {DIM}{wrapped}{RESET}")
