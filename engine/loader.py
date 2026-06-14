# -*- coding: utf-8 -*-
"""Robust skill discovery and loading.

A "skill" is a directory under the input root. It usually contains a SKILL.md
plus optional helper files. Loading never raises on a single bad file: it caps
sizes, falls back on encoding, and skips/records binaries.
"""

import os

from engine import constants as C
from engine import manifest as manifest_mod
from engine import normalize


class SkillDoc(object):
    """Normalised view of one skill, ready for scanning."""

    __slots__ = ("skill_id", "md", "code", "all_text",
                 "has_zero_width", "bundled_binaries", "truncated", "empty",
                 "manifest")

    def __init__(self, skill_id):
        self.skill_id = skill_id
        self.md = ""              # normalised SKILL.md text
        self.code = ""            # normalised concatenation of helper files
        self.all_text = ""        # md + code (capped)
        self.has_zero_width = False
        self.bundled_binaries = []
        self.truncated = False
        self.empty = True
        self.manifest = None      # engine.manifest.Manifest (parsed metadata)


def discover_skills(input_dir):
    """Return a deterministically sorted list of skill_ids (subdir names).

    If the input dir does not exist or has no subdirectories, returns []. We sort
    by raw id string (byte order via Python's str ordering) for reproducibility.
    """
    try:
        entries = os.listdir(input_dir)
    except OSError:
        return []
    skills = []
    for name in entries:
        full = os.path.join(input_dir, name)
        if os.path.isdir(full):
            skills.append(name)
    skills.sort()
    return skills


def _read_text_capped(path):
    """Read up to MAX_FILE_BYTES, decode UTF-8 with replacement.

    Returns (text, is_binary). Binary files (high NUL ratio) return ("", True).
    """
    try:
        with open(path, "rb") as fh:
            raw = fh.read(C.MAX_FILE_BYTES + 1)
    except OSError:
        return "", False
    if not raw:
        return "", False
    truncated = len(raw) > C.MAX_FILE_BYTES
    if truncated:
        raw = raw[:C.MAX_FILE_BYTES]
    # Binary heuristic: NUL byte ratio.
    nul = raw.count(b"\x00")
    if nul and (nul / len(raw)) > C.BINARY_NUL_RATIO:
        return "", True
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = raw.decode("utf-8", errors="replace")
    if truncated:
        text += "\n[TRUNCATED]"
    return text, False


def load_skill(input_dir, skill_id):
    """Load and normalise one skill into a SkillDoc. Never raises."""
    doc = SkillDoc(skill_id)
    skill_dir = os.path.join(input_dir, skill_id)

    md_parts = []
    code_parts = []
    manifest_files = []
    total_bytes = 0

    # Walk deterministically (sorted) so output is reproducible.
    file_list = []
    for root, dirs, files in os.walk(skill_dir):
        dirs.sort()
        for fname in sorted(files):
            file_list.append(os.path.join(root, fname))

    for path in file_list:
        if total_bytes >= C.MAX_SKILL_BYTES:
            doc.truncated = True
            break
        fname = os.path.basename(path)
        lower = fname.lower()
        ext = os.path.splitext(lower)[1]

        if ext in C.BUNDLED_BINARY_EXT:
            doc.bundled_binaries.append(fname)
            continue

        is_skill_md = lower in ("skill.md",)
        is_text = is_skill_md or ext in C.TEXT_HELPER_EXT or ext == ""

        if not is_text:
            # Unknown extension: peek; if binary, record nothing; if text, treat
            # as a helper (defensive — adversaries rename payloads).
            text, is_binary = _read_text_capped(path)
            if is_binary:
                continue
        else:
            text, is_binary = _read_text_capped(path)
            if is_binary:
                # A ".py"/"sh" that is actually binary -> note as bundled blob.
                doc.bundled_binaries.append(fname)
                continue

        if not text:
            continue
        total_bytes += len(text.encode("utf-8", errors="ignore"))

        if lower in C.MANIFEST_FILENAMES:
            manifest_files.append((lower, text))

        nt = normalize.normalize(text)
        if nt.has_zero_width:
            doc.has_zero_width = True
        if is_skill_md or ext in (".md", ".markdown", ".txt"):
            md_parts.append(nt.text)
        else:
            code_parts.append(nt.text)

    doc.md = "\n".join(md_parts)
    doc.code = "\n".join(code_parts)
    combined = doc.md + "\n\n" + doc.code if doc.code else doc.md
    if len(combined) > C.MAX_SCAN_CHARS:
        combined = combined[:C.MAX_SCAN_CHARS]
        doc.truncated = True
    doc.all_text = combined
    doc.manifest = manifest_mod.parse(manifest_files, doc.md)
    doc.empty = not (doc.md.strip() or doc.code.strip() or doc.bundled_binaries)
    return doc


def doc_from_text(skill_id, md_text, helpers=None):
    """Build a SkillDoc directly from in-memory strings (no disk I/O).

    Used by the local self-test so real-malware samples never touch the disk as
    plaintext (Windows Defender would quarantine them). Mirrors load_skill's
    normalisation exactly so results match the on-disk pipeline. ``helpers`` is
    an optional list of (filename, text) pairs.
    """
    doc = SkillDoc(skill_id)
    md_norm = normalize.normalize(md_text or "")
    if md_norm.has_zero_width:
        doc.has_zero_width = True
    md_parts = [md_norm.text]
    code_parts = []
    manifest_files = []
    for name, text in (helpers or []):
        if name.lower() in C.MANIFEST_FILENAMES:
            manifest_files.append((name.lower(), text or ""))
        nt = normalize.normalize(text or "")
        if nt.has_zero_width:
            doc.has_zero_width = True
        ext = os.path.splitext(name.lower())[1]
        if ext in (".md", ".markdown", ".txt"):
            md_parts.append(nt.text)
        else:
            code_parts.append(nt.text)
    doc.md = "\n".join(md_parts)
    doc.code = "\n".join(code_parts)
    combined = doc.md + "\n\n" + doc.code if doc.code else doc.md
    if len(combined) > C.MAX_SCAN_CHARS:
        combined = combined[:C.MAX_SCAN_CHARS]
        doc.truncated = True
    doc.all_text = combined
    doc.manifest = manifest_mod.parse(manifest_files, doc.md)
    doc.empty = not (doc.md.strip() or doc.code.strip())
    return doc
