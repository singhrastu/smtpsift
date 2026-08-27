"""Classify a single SMTP response."""
from __future__ import annotations

import re
from dataclasses import dataclass, asdict

from . import rules as R

# 550, 4.7.1, that sort of thing
_BASIC = re.compile(r"\b([245]\d\d)\b")
_ENHANCED = re.compile(r"\b([245])\.(\d{1,3})\.(\d{1,3})\b")


@dataclass
class Result:
    category: str
    action: str
    advice: str
    permanent: bool
    basic_code: str | None
    enhanced_code: str | None
    provider: str | None
    matched: str | None
    response: str

    def as_dict(self):
        return asdict(self)


def _codes(text):
    b = _BASIC.search(text)
    e = _ENHANCED.search(text)
    return (b.group(1) if b else None,
            ".".join(e.groups()) if e else None)


def _provider(text, hint=None):
    if hint:
        return hint
    for name, pat in R.PROVIDERS.items():
        if pat.search(text):
            return name
    return None


def classify(response, provider=None):
    """Classify one SMTP response line.

    provider can be passed in if you already know it from the MX or route,
    which is more reliable than sniffing the banner text.
    """
    text = (response or "").strip()
    if not text:
        return Result(R.UNKNOWN, *R.ACTIONS[R.UNKNOWN], False, None, None, None, None, "")

    basic, enhanced = _codes(text)

    for category, hint, pattern, note in R.RULES:
        m = pattern.search(text)
        if not m:
            continue
        # A provider-specific rule shouldn't fire for a different provider.
        if hint and provider and hint != provider:
            continue
        action, advice = R.ACTIONS[category]
        return Result(
            category=category,
            action=action,
            advice=advice,
            permanent=_is_permanent(category, basic, enhanced),
            basic_code=basic,
            enhanced_code=enhanced,
            provider=_provider(text, provider or hint),
            matched=note,
            response=text,
        )

    # Nothing matched. Fall back to the code class so we still return something useful.
    category = R.UNKNOWN
    if basic and basic.startswith("4"):
        category = R.TRANSIENT
    elif enhanced and enhanced.startswith("4"):
        category = R.TRANSIENT

    action, advice = R.ACTIONS[category]
    return Result(category, action, advice,
                  _is_permanent(category, basic, enhanced),
                  basic, enhanced, _provider(text, provider), None, text)


def _is_permanent(category, basic, enhanced):
    # Category wins over the code. Providers routinely return 5xx for things that
    # are really temporary (reputation blocks clear once you fix the sender) and
    # 4xx for things that never will.
    if category in (R.INVALID_RECIPIENT, R.MAILBOX_INACTIVE):
        return True
    if category in (R.RATE_LIMITED, R.GREYLISTED, R.TRANSIENT,
                    R.CONNECTION, R.MAILBOX_FULL):
        return False
    if basic:
        return basic.startswith("5")
    if enhanced:
        return enhanced.startswith("5")
    return False
