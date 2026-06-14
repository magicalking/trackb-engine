# -*- coding: utf-8 -*-
"""Structured manifest analysis -> AST02/03/04/06/07/10 signals.

Agent-skill attacks are not only in the prose/code: the manifest itself encodes
risk (over-broad permissions, unrestricted network, brand typosquatting, version
drift, weak isolation, multi-platform autostart). The regex/ML layers cannot see
this structure, so we parse the declared metadata once (best-effort, never
raising) and emit the structural signals the OWASP Agentic Skills Top 10 lists
for each of those categories.

Parsing is deliberately tolerant: JSON manifests are parsed properly; YAML
frontmatter / non-standard manifests fall back to a flat raw-text scan so a
malformed manifest still contributes substring evidence instead of crashing.
"""

import json
import re

from engine import constants as C
from engine.signals import Signal


class Manifest(object):
    __slots__ = ("present", "name", "description", "author", "version",
                 "raw_text", "platforms")

    def __init__(self):
        self.present = False
        self.name = ""
        self.description = ""
        self.author = ""
        self.version = ""
        self.raw_text = ""        # concatenated manifest sources (original case)
        self.platforms = []


_FRONTMATTER_RE = re.compile(r"\s*---\s*\n(.*?)\n---\s*(?:\n|$)", re.DOTALL)


def _flatten_json(obj, out):
    """Append every scalar string/number in a parsed JSON object to ``out``."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            out.append(str(k))
            _flatten_json(v, out)
    elif isinstance(obj, list):
        for it in obj:
            _flatten_json(it, out)
    elif obj is not None:
        out.append(str(obj))


def _field(raw, names):
    """Best-effort extract a scalar field, JSON ("k": "v") or YAML (k: v)."""
    for nm in names:
        m = re.search(r'(?:"%s"|\b%s)\s*[:=]\s*"?([^"\n,}\]]+)' % (nm, nm),
                      raw, re.IGNORECASE)
        if m:
            return m.group(1).strip().strip("'\"` ")
    return ""


def parse(manifest_files, md_text):
    """Build a Manifest from (basename, text) manifest files + SKILL.md text.

    Never raises. Returns a Manifest (``present=False`` if nothing parseable).
    """
    man = Manifest()
    parts = []

    for _name, text in manifest_files or ():
        if not text:
            continue
        parts.append(text)
        # If it parses as JSON, also flatten it so nested values are searchable.
        stripped = text.lstrip()
        if stripped[:1] in ("{", "["):
            try:
                obj = json.loads(text)
                flat = []
                _flatten_json(obj, flat)
                parts.append(" ".join(flat))
            except (ValueError, TypeError):
                pass

    if md_text:
        fm = _FRONTMATTER_RE.match(md_text)
        if fm:
            parts.append(fm.group(1))

    if not parts:
        return man

    raw = "\n".join(parts)
    man.present = True
    man.raw_text = raw
    man.name = _field(raw, ("name", "skill_name", "id", "title"))
    man.description = _field(raw, ("description", "desc", "summary", "about"))
    man.author = _field(raw, ("author", "publisher", "maintainer", "vendor",
                              "owner"))
    man.version = _field(raw, ("version", "ver"))

    low = raw.lower()
    for plat in ("openclaw", "claude", "cursor", "vscode", "vs code",
                 "windsurf", "copilot", "continue"):
        if plat in low:
            man.platforms.append(plat)
    return man


# --------------------------------------------------------------------------- #
# Heuristics                                                                    #
# --------------------------------------------------------------------------- #
_PERM_KEY_RE = re.compile(
    r"(?:permission|scope|capabilit|access|allow|grant|tool)", re.IGNORECASE)
_BROAD_PERM_RE = re.compile(
    r"(?:/\*\*|\"\*\"|'\*'|:\s*\"?\*\"?|\ball\b|\bany\b|read[_\-]?all|"
    r"full[_\-]?access|all[_\-]?files|unrestricted|filesystem|"
    r"\"shell\"\s*:\s*true|\bexec\b|run[_\-]?command|arbitrary)", re.IGNORECASE)
_NET_RE = re.compile(
    r"(?:\"?network\"?\s*[:=]\s*(?:true|\"?\*\"?|\"any\"|\"all\")|"
    r"\"?egress\"?\s*[:=]\s*(?:\"\*\"|\"any\"|true)|"
    r"allow[_\-]?network\s*[:=]\s*true|\"?outbound\"?\s*[:=]\s*\"\*\")",
    re.IGNORECASE)
_NOSANDBOX_RE = re.compile(
    r"(?:\"?sandbox\"?\s*[:=]\s*(?:false|\"none\"|\"off\")|"
    r"\"?isolation\"?\s*[:=]\s*\"none\"|run[_\-]?in[_\-]?host|"
    r"\"?host[_\-]?mode\"?\s*[:=]\s*true|no[_\-]?sandbox)", re.IGNORECASE)
_BENIGN_DESC_RE = re.compile(
    r"(?:format|convert|lint|style|prettif|render|markdown|note|todo|"
    r"summar|translat|spell|grammar|emoji|color|theme|template|snippet)",
    re.IGNORECASE)
_DANGER_CAP_RE = re.compile(
    r"(?:shell|exec|subprocess|os\.system|child_process|credential|api[_\s-]?key|"
    r"token|~/\.ssh|\.aws|network|curl|wget|socket|/dev/tcp)", re.IGNORECASE)
_INTEGRITY_RE = re.compile(
    r"(?:content[_\-]?hash|integrity|sha256|sha-256|checksum|\"hash\"|signature|"
    r"signed|digest)", re.IGNORECASE)
_DRIFT_RE = re.compile(
    r"(?:[:=]\s*\"?(?:\^|~|>=|>)\s*\d|[:=]\s*\"?\*\"?|@latest\b|"
    r"\"version\"\s*:\s*\"(?:\*|latest|x)\"|:\s*latest\b)", re.IGNORECASE)
# Distinct OS-specific autostart families (cross-platform persistence).
_OS_AUTOSTART = (
    re.compile(r"launchagents|launchdaemons|\.plist\b", re.IGNORECASE),     # macOS
    re.compile(r"systemctl|/etc/systemd|/etc/cron|crontab|\.bashrc|\.zshrc",
               re.IGNORECASE),                                              # linux
    re.compile(r"hkcu|hkey_current_user|currentversion\\\\?run|reg\s+add|"
               r"schtasks", re.IGNORECASE),                                 # windows
)


def _lev(a, b, cap=3):
    """Bounded Levenshtein distance (returns cap+1 if it exceeds cap)."""
    a, b = a.lower(), b.lower()
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        best = i
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            v = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            cur.append(v)
            if v < best:
                best = v
        if best > cap:
            return cap + 1
        prev = cur
    return prev[-1]


def _mk(sid, snippet):
    spec = C.MANIFEST_SIGNALS[sid]
    return Signal(sid, spec["weight"], spec["tier"], spec["category"],
                  (snippet or "")[:80])


def scan(doc):
    """Return structural Signals for ``doc`` (manifest + cross-file heuristics)."""
    out = []
    man = getattr(doc, "manifest", None)
    raw = man.raw_text if (man and man.present) else ""

    # ---- AST03: over-privileged ------------------------------------------ #
    if raw and _PERM_KEY_RE.search(raw):
        bm = _BROAD_PERM_RE.search(raw)
        if bm:
            out.append(_mk("S_over_privileged", bm.group(0)))
    if raw:
        nm = _NET_RE.search(raw)
        if nm:
            out.append(_mk("S_unrestricted_network", nm.group(0)))

    # ---- AST06: weak isolation ------------------------------------------- #
    low_all = doc.all_text.lower()
    sens = next((p for p in C.SENSITIVE_HOST_PATHS if p in low_all), None)
    if sens and (not raw or not re.search(r"sandbox|container|isolat", raw,
                                          re.IGNORECASE)):
        if raw and _NOSANDBOX_RE.search(raw):
            out.append(_mk("S_weak_isolation", _NOSANDBOX_RE.search(raw).group(0)))
        elif _PERM_KEY_RE.search(raw or "") and sens:
            out.append(_mk("S_weak_isolation", sens))
    elif raw and _NOSANDBOX_RE.search(raw):
        out.append(_mk("S_weak_isolation", _NOSANDBOX_RE.search(raw).group(0)))

    # ---- AST07: update drift --------------------------------------------- #
    if raw and _DRIFT_RE.search(raw) and not _INTEGRITY_RE.search(raw):
        out.append(_mk("S_update_drift", _DRIFT_RE.search(raw).group(0)))

    # ---- AST04: typosquat + intent/metadata mismatch --------------------- #
    if man and man.name:
        nm = re.sub(r"[^a-z0-9]", "", man.name.lower())
        if 3 <= len(nm) <= 24:
            for known in C.KNOWN_SKILL_NAMES:
                if nm == known:
                    break
                d = _lev(nm, known, cap=2)
                if 1 <= d <= 2:
                    out.append(_mk("S_typosquat", "%s≈%s" % (man.name, known)))
                    break
    if man and man.description and _BENIGN_DESC_RE.search(man.description) \
            and _DANGER_CAP_RE.search(raw):
        out.append(_mk("S_metadata_mismatch",
                       "desc:%s" % man.description[:40]))

    # ---- AST10: cross-platform autostart reuse --------------------------- #
    hits = [rx.search(doc.all_text) for rx in _OS_AUTOSTART]
    present = [m for m in hits if m]
    if len(present) >= 2:
        out.append(_mk("S_cross_platform_reuse",
                       " / ".join(m.group(0) for m in present[:3])))

    return out
