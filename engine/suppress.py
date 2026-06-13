# -*- coding: utf-8 -*-
"""False-positive suppression (protects specificity).

Subtracts a bounded penalty from the rule score when the skill has a legitimate
context (DeFi/crypto, security/forensics tooling) that explains otherwise
suspicious tokens. Suppression can NEVER drop a confirmed Tier-A chain below the
malicious threshold (a reverse shell stays malicious even in a "security tool").
"""

from engine import constants as C


def _contains_any(text, needles):
    for n in needles:
        if n in text:
            return True
    return False


def compute(doc, fired):
    """Return (penalty:int, notes:list[str], drop_ids:set, cap_suspicious:bool).

    drop_ids are signal ids that should be removed entirely (e.g. an IP-literal
    that is actually a private/loopback address, an official-domain "paste host").
    cap_suspicious flags an analytical (security-tool) context: a confirmed
    primitive with no real-infrastructure corroboration should be capped at
    "suspicious", not "malicious".
    """
    lower = doc.all_text.lower()
    notes = []
    penalty = 0
    drop_ids = set()
    cap_suspicious = _contains_any(lower, C.SECTOOL_CONTEXT)

    fired_ids = set(s.id for s in fired)
    has_confirmed = bool(fired_ids & set(C.CONFIRMED_CHAIN_SIGNALS))

    # --- drop obvious non-malicious matches ------------------------------- #
    # Private / loopback IP-literal URLs are not exfil.
    for s in fired:
        if s.id == "S_ip_literal_url":
            sl = s.snippet.lower()
            if any(sl.startswith(p) for p in C.PRIVATE_IP_PREFIXES):
                drop_ids.add(s.id)
        if s.id == "S_paste_host":
            # If the only "host" match is an official domain, drop it.
            if _contains_any(s.snippet.lower(), C.OFFICIAL_DOMAINS) and \
                    not _contains_any(s.snippet.lower(),
                                      ("glot.io", "rentry", "pastebin", "0x0.st",
                                       "transfer.sh", "vercel.app", "glitch.me",
                                       "repl.co", "workers.dev", "anonfiles")):
                drop_ids.add(s.id)

    # --- DeFi / crypto context dampener ----------------------------------- #
    if _contains_any(lower, C.DEFI_CONTEXT):
        # Legit crypto skills touch keys/exchange APIs. Dampen credential signal
        # UNLESS the skill also fetches+runs external code (a real chain).
        if not has_confirmed:
            penalty += C.DEFI_PENALTY
            notes.append(C.SUPPRESS_DEFI_NOTE)

    # --- security / forensics tooling context ----------------------------- #
    if cap_suspicious:
        # shell/base64 mentions are analytical. Reverse-shell / persistence /
        # credential-egress still count (handled by the confirmed-chain floor),
        # but a lone quoted primitive is capped at suspicious in scoring.
        if not has_confirmed:
            penalty += C.SECTOOL_PENALTY
            notes.append(C.SUPPRESS_SECTOOL_NOTE)

    return penalty, notes, drop_ids, cap_suspicious
