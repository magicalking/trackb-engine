# -*- coding: utf-8 -*-
"""Minimal pure-stdlib BERT WordPiece tokenizer (optional ONNX path only).

Used solely by engine.semantic when an ONNX prompt-injection model is bundled at
build time. If no model is shipped, this module is never imported at runtime, so
the deterministic engine carries no dependency on it. Implements lowercase basic
tokenisation + greedy WordPiece against a vocab.txt, with [CLS]/[SEP] and
padding/truncation to a fixed length.
"""

import unicodedata


class Tokenizer(object):
    def __init__(self, vocab_path, do_lower=True):
        self.do_lower = do_lower
        self.vocab = {}
        with open(vocab_path, "r", encoding="utf-8") as fh:
            for i, line in enumerate(fh):
                self.vocab[line.rstrip("\n")] = i
        self.unk = self.vocab.get("[UNK]", 100)
        self.cls = self.vocab.get("[CLS]", 101)
        self.sep = self.vocab.get("[SEP]", 102)
        self.pad = self.vocab.get("[PAD]", 0)

    def _basic(self, text):
        text = unicodedata.normalize("NFKC", text or "")
        if self.do_lower:
            text = text.lower()
        out = []
        cur = []
        for ch in text:
            cat = unicodedata.category(ch)
            if ch.isspace():
                if cur:
                    out.append("".join(cur)); cur = []
            elif cat.startswith("P") or cat.startswith("S"):
                if cur:
                    out.append("".join(cur)); cur = []
                out.append(ch)
            else:
                cur.append(ch)
        if cur:
            out.append("".join(cur))
        return out

    def _wordpiece(self, token):
        if token in self.vocab:
            return [self.vocab[token]]
        chars = list(token)
        sub = []
        start = 0
        n = len(chars)
        while start < n:
            end = n
            cur = None
            while start < end:
                piece = "".join(chars[start:end])
                if start > 0:
                    piece = "##" + piece
                if piece in self.vocab:
                    cur = self.vocab[piece]
                    break
                end -= 1
            if cur is None:
                return [self.unk]
            sub.append(cur)
            start = end
        return sub

    def encode(self, text, max_len=512):
        ids = [self.cls]
        for tok in self._basic(text):
            ids.extend(self._wordpiece(tok))
            if len(ids) >= max_len - 1:
                break
        ids = ids[:max_len - 1] + [self.sep]
        mask = [1] * len(ids)
        while len(ids) < max_len:
            ids.append(self.pad); mask.append(0)
        return ids[:max_len], mask[:max_len]
