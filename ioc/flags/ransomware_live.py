"""Threat flag extraction from Ransomware.live victim search results."""
from __future__ import annotations

from datetime import datetime, timezone

from .base import _flag, _days_since


def _flags_ransomware_live(rl: dict) -> list[dict]:
    """Extract threat flags from a Ransomware.live victim search result dict.

    Args:
        rl: Single-IOC result dict from ransomware_live_lookup_batch.

    Returns:
        List of flag dicts sorted by severity.
    """
    flags: list[dict] = []
    if not isinstance(rl, dict) or not rl or rl.get("error"):
        return flags

    victims: list[dict] = rl.get("victims") or []
    count: int = rl.get("count") or len(victims)
    if count == 0:
        return flags

    # Collect unique group names
    groups: list[str] = list(dict.fromkeys(
        str(v.get("group_name") or "").strip()
        for v in victims
        if v.get("group_name")
    ))
    group_str = ", ".join(groups[:3]) if groups else "unknown group"

    # Collect recent victims (discovered or published within 90 days)
    recent: list[dict] = []
    for v in victims:
        disc = v.get("discovered") or v.get("published") or ""
        age = _days_since(disc)
        if age is not None and age <= 90:
            recent.append(v)

    # ── Primary match flag (always emitted when count > 0) ────────────────────
    flags.append(_flag(
        "RL_VICTIM_MATCH",
        f"Domain/org found in ransomware victim database ({count} record(s))",
        "Ransomware victim",
        "CRITICAL",
        ["TA0040", "T1486"],
        f"{count} record(s); group(s): {group_str}",
        "Ransomware.live",
    ))

    # ── Recent incident within 90 days ───────────────────────────────────────
    if recent:
        most_recent = recent[0].get("discovered") or recent[0].get("published") or "unknown"
        flags.append(_flag(
            "RL_RECENT_ATTACK",
            f"Recent ransomware incident within 90 days ({len(recent)} record(s))",
            "Active ransomware threat",
            "CRITICAL",
            ["TA0040", "T1486"],
            f"Most recent: {most_recent}",
            "Ransomware.live",
        ))

    # ── Known ransomware group identified ────────────────────────────────────
    if groups:
        flags.append(_flag(
            "RL_KNOWN_GROUP",
            f"Ransomware group identified: {groups[0]}",
            "Known threat actor",
            "HIGH",
            ["TA0042", "TA0040"],
            f"Active group(s): {group_str}",
            "Ransomware.live",
        ))

    # ── Multiple victim records — repeated or wide targeting ─────────────────
    if count >= 3:
        flags.append(_flag(
            "RL_MULTIPLE_VICTIMS",
            f"Multiple victim records ({count}) — repeated or broad targeting",
            "Persistent threat actor activity",
            "HIGH",
            ["TA0040"],
            f"{count} total victim records found",
            "Ransomware.live",
        ))

    return flags
