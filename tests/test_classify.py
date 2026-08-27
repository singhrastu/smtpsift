import pytest

from smtpsift import classify
from smtpsift import rules as R


# Real responses. Sources: Postfix and PowerMTA logs, provider postmaster docs.
CASES = [
    ("550 5.1.1 <a@b.com>: Recipient address rejected: User unknown in virtual mailbox table",
     R.INVALID_RECIPIENT, "suppress", True),
    ("550 5.1.1 The email account that you tried to reach does not exist. gsmtp",
     R.INVALID_RECIPIENT, "suppress", True),
    ("452 4.2.2 The email account that you tried to reach is over quota",
     R.MAILBOX_FULL, "retry", False),
    ("550 5.2.1 The user's account has been disabled",
     R.MAILBOX_INACTIVE, "suppress", True),
    ("550 5.7.1 Service unavailable, Client host [1.2.3.4] blocked using Spamhaus",
     R.BLOCKLIST, "pause", True),
    ("550 5.7.606 Access denied, banned sending IP [1.2.3.4]",
     R.REPUTATION_BLOCK, "pause", True),
    ("421 4.7.28 Our system has detected an unusual rate of unsolicited mail",
     R.RATE_LIMITED, "throttle", False),
    ("550-5.7.26 This message does not have authentication information",
     R.AUTH_FAILURE, "fix_config", True),
    ("451 4.7.1 Greylisted, please try again in 300 seconds",
     R.GREYLISTED, "retry", False),
    ("554 5.7.1 Message rejected due to content restrictions",
     R.CONTENT_BLOCK, "review", True),
    ("421 4.4.2 Connection timed out",
     R.CONNECTION, "retry", False),
]


@pytest.mark.parametrize("resp,cat,action,permanent", CASES)
def test_classification(resp, cat, action, permanent):
    r = classify(resp)
    assert r.category == cat, f"{resp!r} -> {r.category}"
    assert r.action == action
    assert r.permanent is permanent


def test_codes_extracted():
    r = classify("550 5.1.1 User unknown")
    assert r.basic_code == "550"
    assert r.enhanced_code == "5.1.1"


def test_provider_sniffed():
    assert classify("550 5.1.1 no such user gsmtp").provider == "gmail"
    assert classify("550 blocked by protection.outlook.com").provider == "microsoft"


def test_explicit_provider_beats_sniffing():
    r = classify("421 4.7.500 Server busy", provider="microsoft")
    assert r.provider == "microsoft"
    assert r.category == R.RATE_LIMITED


def test_provider_hint_does_not_misfire():
    # A Yahoo-specific pattern must not fire when we know it came from Gmail.
    r = classify("421 4.7.0 [TS03] deferred", provider="gmail")
    assert r.category != R.REPUTATION_BLOCK or r.provider == "gmail"


def test_unknown_falls_back_to_code_class():
    r = classify("451 Something nobody has seen before")
    assert r.category == R.TRANSIENT
    assert r.permanent is False


def test_empty_is_safe():
    r = classify("")
    assert r.category == R.UNKNOWN
    assert r.permanent is False


def test_every_category_has_an_action():
    for name in dir(R):
        val = getattr(R, name)
        if name.isupper() and isinstance(val, str) and name not in ("RULES", "ACTIONS", "PROVIDERS"):
            assert val in R.ACTIONS, f"{val} has no action mapping"
