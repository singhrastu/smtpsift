"""Rules for classifying SMTP rejections and deferrals.

Order matters. First match wins, so reputation and policy blocks sit above the
generic mailbox/syntax rules that would otherwise swallow them.

Why not just hard/soft: "soft bounce" covers three things that need opposite
responses. Full mailbox -> retry, it may clear. Rate limit -> back off. Reputation
block -> stop and fix the sender; retrying makes it worse. Collapsing those is the
most expensive mistake in bounce handling.
"""
import re

INVALID_RECIPIENT = "invalid_recipient"
MAILBOX_FULL      = "mailbox_full"
MAILBOX_INACTIVE  = "mailbox_inactive"
REPUTATION_BLOCK  = "reputation_block"
CONTENT_BLOCK     = "content_block"
BLOCKLIST         = "blocklist"
RATE_LIMITED      = "rate_limited"
GREYLISTED        = "greylisted"
AUTH_FAILURE      = "auth_failure"
POLICY_BLOCK      = "policy_block"
CONNECTION        = "connection"
TRANSIENT         = "transient"
UNKNOWN           = "unknown"

# what to actually do about it
ACTIONS = {
    INVALID_RECIPIENT: ("suppress",   "Permanent. Remove it. Retrying costs reputation."),
    MAILBOX_FULL:      ("retry",      "Retry with backoff for a few days, then suppress."),
    MAILBOX_INACTIVE:  ("suppress",   "Dormant or disabled. Suppress - these turn into spam traps."),
    REPUTATION_BLOCK:  ("pause",      "Stop sending to this provider from this IP/domain and remediate."),
    CONTENT_BLOCK:     ("review",     "Content or a linked domain triggered it. Fix the message, not the rate."),
    BLOCKLIST:         ("pause",      "Delist first. Find the emitting source before you request removal."),
    RATE_LIMITED:      ("throttle",   "Drop concurrency and rate for this provider, then retry."),
    GREYLISTED:        ("retry",      "Expected on first contact. Retry after the window."),
    AUTH_FAILURE:      ("fix_config", "SPF/DKIM/DMARC problem. Retrying will not help."),
    POLICY_BLOCK:      ("review",     "Recipient-side rule. Usually not your reputation."),
    CONNECTION:        ("retry",      "Network/TLS/DNS. Retry, but investigate if it sticks to one route."),
    TRANSIENT:         ("retry",      "Temporary remote condition. Normal retry schedule."),
    UNKNOWN:           ("retry",      "Unrecognised. Retry conservatively and add a rule."),
}


def _r(p):
    return re.compile(p, re.I)


# (category, provider_hint, pattern, note)
# Patterns match against the whole response line. These are what providers
# actually send, not what the RFCs suggest they should.
RULES = [
    (BLOCKLIST, None, _r(r"spamhaus|sbl\.spamhaus|xbl\.spamhaus|css\.spamhaus|pbl\.spamhaus"),
     "Spamhaus listing"),
    (BLOCKLIST, None, _r(r"spamcop|barracudacentral|sorbs|uceprotect|invaluement|"
                         r"\bsurbl\b|\buribl\b|dnsbl|\brbl\b|blocklist\.de"),
     "Named DNSBL listing"),
    (BLOCKLIST, "proofpoint", _r(r"blocked using proofpoint|proofpoint.*block"),
     "Proofpoint filtering"),
    (BLOCKLIST, "cloudmark", _r(r"cloudmark|csi\.cloudmark"),
     "Cloudmark reputation"),

    (AUTH_FAILURE, None, _r(r"dmarc.*(fail|reject|polic)|failed dmarc|"
                            r"unauthenticated email|"
                            r"spf.*(fail|softfail|permerror)|"
                            r"dkim.*(fail|invalid|not signed)|"
                            r"5\.7\.26"),
     "SPF/DKIM/DMARC alignment or policy failure"),

    (REPUTATION_BLOCK, "microsoft", _r(r"\bs3140\b|\bs3150\b|"
                                       r"unfortunately, messages from|"
                                       r"has been blocked by outlook\.com|"
                                       r"5\.7\.606|"
                                       r"access denied, banned sending ip"),
     "Microsoft/Outlook IP reputation block"),
    # Careful here: Gmail uses similar wording for two different things.
    # "unusual rate" + 4.7.28 is a deferral, handled by the rate limit rule below.
    # "likely unsolicited" + 5.7.1 is an actual block. Don't merge them.
    (REPUTATION_BLOCK, "gmail", _r(r"likely unsolicited mail|"
                                   r"this message has been blocked because|"
                                   r"suspicious due to the very low reputation|"
                                   r"not accepted from ip"),
     "Gmail sender reputation block"),
    (REPUTATION_BLOCK, "yahoo", _r(r"\[ts0\d+\]|not accepted for policy reasons|"
                                   r"mail server ip.*blocked"),
     "Yahoo policy/reputation block"),
    (REPUTATION_BLOCK, None, _r(r"(poor|bad|low) reputation|sender reputation|"
                                r"reputation of the sending"),
     "Sender reputation block"),

    (RATE_LIMITED, "gmail", _r(r"4\.7\.28|unusual rate of unsolicited"),
     "Gmail rate limiting"),
    (RATE_LIMITED, "microsoft", _r(r"4\.7\.500|4\.7\.650|server busy|too many concurrent"),
     "Microsoft throttling"),
    (RATE_LIMITED, None, _r(r"too many (messages|connections|recipients)|"
                            r"rate limited|slow down|throttl|"
                            r"exceeded.*(limit|quota).*(hour|minute|day)|4\.5\.3"),
     "Rate limiting"),

    (GREYLISTED, None, _r(r"grey ?list|gray ?list|"
                          r"try again later.*not previously|"
                          r"450 4\.7\.1.*try again"),
     "Greylisted"),

    (CONTENT_BLOCK, None, _r(r"spam content|message content|content filter|"
                             r"our content filters|high probability of spam|"
                             r"message (rejected|refused).*content|"
                             r"url.*(blacklist|blocked|reputation)|"
                             r"virus|malware|attachment.*not allowed"),
     "Content or URL reputation"),

    (MAILBOX_FULL, None, _r(r"mailbox (is )?full|over ?quota|quota exceeded|"
                            r"insufficient system storage|5\.2\.2|4\.2\.2"),
     "Recipient over quota"),
    (MAILBOX_INACTIVE, None, _r(r"account (is )?(disabled|inactive|suspended|closed)|"
                                r"mailbox (disabled|inactive|not accepting)|"
                                r"no longer (in use|active|employed)|5\.2\.1"),
     "Mailbox disabled or dormant"),
    (INVALID_RECIPIENT, None, _r(r"user unknown|unknown user|no such user|"
                                 r"recipient (address )?rejected|does not exist|"
                                 r"invalid (recipient|mailbox|address)|"
                                 r"address (not found|unknown)|"
                                 r"5\.1\.1|5\.1\.3|5\.1\.0|"
                                 r"mailbox unavailable|no mailbox here"),
     "Recipient does not exist"),

    (POLICY_BLOCK, None, _r(r"policy (reasons|violation|restriction)|"
                            r"not authori[sz]ed to send|relay (access )?denied|"
                            r"recipient.*not accepting"),
     "Recipient-side policy"),

    (CONNECTION, None, _r(r"connection (timed out|refused|reset|closed)|"
                          r"could not connect|no route to host|"
                          r"\btls\b|\bssl\b|certificate|handshake|"
                          r"dns (error|failure)|host not found|"
                          r"lost connection|network is unreachable"),
     "Connection, TLS or DNS failure"),

    (TRANSIENT, None, _r(r"temporar(y|ily)|try again|resources temporarily|"
                         r"internal error|service unavailable"),
     "Temporary remote condition"),
]

PROVIDERS = {
    "gmail":      _r(r"gmail|googlemail|gsmtp|google\.com"),
    "microsoft":  _r(r"outlook|hotmail|office365|protection\.outlook|microsoft|live\.com"),
    "yahoo":      _r(r"yahoo|yahoodns|\baol\b"),
    "proofpoint": _r(r"proofpoint|pphosted"),
    "mimecast":   _r(r"mimecast"),
    "apple":      _r(r"icloud|apple\.com|\bme\.com\b"),
}
