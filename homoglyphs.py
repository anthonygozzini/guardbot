#!/usr/bin/env python3
"""Fold Latin-lookalike (homoglyph) characters, so a disguise cannot defeat identity checks.

Found in the wild on BSC: a scam whose ticker renders as USDT but is actually "\u054d\u054f
\u216e\ua4d4" — Armenian U+S, a Roman numeral D, a Lisu T. String comparison sees a brand-new
symbol, the impersonation check stays silent, and honeypot.is even shows PASSED (taxes are 0%;
the trick is the NAME, not the mechanics). NFKC normalization folds the compatibility forms
(fullwidth, math alphabets, Roman numerals); the map below covers the lookalikes NFKC leaves
alone, curated from the scripts actually abused in tickers (Cyrillic, Greek, Armenian, Lisu,
Cherokee). An honest non-Latin name (katakana, CJK) folds to itself and is never flagged."""

import unicodedata

_MAP = {
    # Cyrillic
    "\u0410": "A", "\u0412": "B", "\u0421": "C", "\u0415": "E", "\u041d": "H", "\u0406": "I",
    "\u0408": "J", "\u041a": "K", "\u041c": "M", "\u041e": "O", "\u0420": "P", "\u0405": "S",
    "\u0422": "T", "\u0423": "Y", "\u0425": "X", "\u0430": "a", "\u0441": "c", "\u0435": "e",
    "\u0456": "i", "\u0458": "j", "\u043e": "o", "\u0440": "p", "\u0455": "s", "\u0445": "x",
    "\u0443": "y", "\u0501": "d", "\u04bb": "h", "\u0433": "r", "\u0475": "v", "\u051b": "q",
    "\u051d": "w",
    # Greek
    "\u0391": "A", "\u0392": "B", "\u0395": "E", "\u0396": "Z", "\u0397": "H", "\u0399": "I",
    "\u039a": "K", "\u039c": "M", "\u039d": "N", "\u039f": "O", "\u03a1": "P", "\u03a4": "T",
    "\u03a5": "Y", "\u03a7": "X", "\u03bf": "o", "\u03bd": "v",
    # Armenian
    "\u054d": "U", "\u054f": "S", "\u0555": "O", "\u053c": "L", "\u0544": "U",
    # Lisu
    "\ua4d4": "T", "\ua4d0": "B", "\ua4d1": "P", "\ua4d3": "D", "\ua4d6": "G", "\ua4d7": "K",
    "\ua4d9": "J", "\ua4da": "C", "\ua4dc": "Z", "\ua4dd": "F", "\ua4de": "S", "\ua4df": "M",
    "\ua4e0": "N", "\ua4e1": "L", "\ua4e2": "S", "\ua4e3": "R", "\ua4e5": "A", "\ua4e6": "V",
    "\ua4e7": "H", "\ua4e8": "E", "\ua4e9": "J", "\ua4ea": "W", "\ua4eb": "X", "\ua4ec": "Y",
    "\ua4ee": "A", "\ua4f0": "E", "\ua4f2": "I", "\ua4f3": "O", "\ua4f4": "U",
    # Cherokee
    "\u13a0": "D", "\u13a1": "R", "\u13a2": "T", "\u13c2": "W", "\u13ba": "M", "\u13bb": "H",
    "\u13da": "S", "\u13de": "L", "\u13df": "C", "\u13e2": "P", "\u13d4": "V", "\u13e6": "K",
}
_ZERO_WIDTH = {0x200b, 0x200c, 0x200d, 0x2060, 0xfeff, 0x00ad}


def skeleton(s):
    """NFKC-normalize, drop zero-width characters, fold known lookalikes to their Latin twin."""
    out = []
    for ch in unicodedata.normalize("NFKC", s or ""):
        if ord(ch) in _ZERO_WIDTH:
            continue
        out.append(_MAP.get(ch, ch))
    return "".join(out)


def disguised(s):
    """(skeleton, spoofed): spoofed=True when the string contains non-ASCII characters yet folds
    to pure ASCII — i.e. it only READS as a Latin ticker because of lookalikes. An honest
    non-Latin name keeps non-ASCII in its skeleton and is never flagged."""
    sk = skeleton(s)
    spoofed = bool(s) and any(ord(c) > 127 for c in s) and sk != s and all(ord(c) < 128 for c in sk)
    return sk, spoofed
