"""
summary.py - Severity summary box printed at the end of every scan.
"""
from utils.banner import RESET, RED, YELLOW, CYAN, GREEN, BOLD, DIM

RISK_ORDER = ["Critical", "High", "Medium", "Low", "Info"]

RISK_COLOR = {
    "Critical": "\033[95m",   # magenta
    "High":     RED,
    "Medium":   YELLOW,
    "Low":      CYAN,
    "Info":     DIM,
}


def print_summary(results):
    """Print a clean severity summary box to terminal."""
    if not results:
        print(f"\n  {GREEN}{BOLD}No issues found.{RESET}\n")
        return

    counts = {}
    for r in results:
        risk = r.get("risk", "Info")
        counts[risk] = counts.get(risk, 0) + 1

    total = len(results)
    width = 44

    print(f"\n  {BOLD}{'─' * width}{RESET}")
    print(f"  {BOLD}  Scan Summary{RESET}")
    print(f"  {'─' * width}")

    for risk in RISK_ORDER:
        if risk in counts:
            color = RISK_COLOR.get(risk, RESET)
            bar_len = min(int(counts[risk] / total * 20), 20)
            bar = "█" * bar_len + "░" * (20 - bar_len)
            print(f"  {color}{risk:<10}{RESET}  {bar}  {counts[risk]}")

    print(f"  {'─' * width}")
    print(f"  {'Total':<10}  {'':20}  {total}")
    print(f"  {BOLD}{'─' * width}{RESET}\n")


def build_summary_dict(results):
    """Return a summary dict for JSON reports."""
    counts = {}
    for r in results:
        risk = r.get("risk", "Info")
        counts[risk] = counts.get(risk, 0) + 1
    counts["total"] = len(results)
    return counts
