# smtpsift

Turns SMTP rejections and deferrals into a category and an action.

Most bounce handling splits responses into "hard" and "soft" and stops there. That
split is too coarse to act on. A full mailbox, a rate limit, and a reputation block
all arrive as soft bounces, and they need opposite responses:

- full mailbox -> retry, it may clear
- rate limit -> back off, slow down, retry later
- reputation block -> **stop**, fix the sender, retrying makes it worse

Getting that wrong is expensive in both directions. Treat a soft bounce as hard and
you suppress deliverable addresses. Treat a reputation block as a soft bounce and you
keep hammering a provider that has already decided it doesn't trust you.

## Install

```
pip install -e .
```

## Use

```
$ smtpsift "550 5.7.1 Service unavailable, Client host [1.2.3.4] blocked using Spamhaus"
blocklist          pause       permanent
  550 5.7.1 Service unavailable, Client host [1.2.3.4] blocked using Spamhaus
  -> Spamhaus listing
```

Pipe a log through it and get the shape of your problem:

```
$ grep 'dsn=' /var/log/maillog | smtpsift --summary
4812 responses

  invalid_recipient      2103   43.7%
  rate_limited           1290   26.8%
  reputation_block        684   14.2%
  mailbox_full            401    8.3%
  ...

actions:
  suppress               2287   47.5%
  throttle               1290   26.8%
  pause                   712   14.8%
```

That last block is the point. `throttle` at 27% means back off. `pause` at 15% means
something is wrong with the sender, not the send rate.

JSON Lines for piping into anything else:

```
$ smtpsift -f bounces.txt --json | jq -r 'select(.action=="pause") | .response'
```

As a library:

```python
from smtpsift import classify

r = classify("421 4.7.28 Our system has detected an unusual rate of unsolicited mail")
r.category    # 'rate_limited'
r.action      # 'throttle'
r.permanent   # False
r.provider    # 'gmail'
```

If you already know the provider from the MX or the route, pass it in. It is more
reliable than sniffing the banner:

```python
classify(line, provider="microsoft")
```

## Categories

| category | action | meaning |
|---|---|---|
| `invalid_recipient` | suppress | address doesn't exist |
| `mailbox_full` | retry | over quota, may clear |
| `mailbox_inactive` | suppress | disabled or dormant, spam trap risk |
| `reputation_block` | pause | IP or domain reputation |
| `blocklist` | pause | named DNSBL listing |
| `content_block` | review | message content or URL reputation |
| `rate_limited` | throttle | provider is asking you to slow down |
| `greylisted` | retry | deliberate first-contact deferral |
| `auth_failure` | fix_config | SPF/DKIM/DMARC problem |
| `policy_block` | review | recipient-side rule |
| `connection` | retry | network, TLS or DNS |
| `transient` | retry | temporary remote condition |

## Notes

**Category beats status code.** Providers return 5xx for things that are really
temporary (a reputation block clears once you fix the sender) and 4xx for things that
never will. `permanent` is derived from the category first and the code second.

**Rule order matters.** First match wins. Reputation and policy rules sit above the
generic mailbox rules, which would otherwise swallow them: plenty of reputation blocks
mention "mailbox unavailable" in the same string.

**Patterns are what providers actually send**, not what the RFCs suggest. Microsoft's
`S3140`, Yahoo's `[TS03]` and Gmail's `5.7.26` don't appear in any spec.

## Adding rules

Rules live in `smtpsift/rules.py` as `(category, provider_hint, pattern, note)` and are
evaluated in order. Add specific rules above general ones. If you set a provider hint,
the rule only fires when the provider matches or is unknown, so a Yahoo-specific
pattern won't misfire on a Gmail response.

## TODO

- ARF / feedback loop report parsing
- bulk mode reading Postfix and PowerMTA accounting files directly instead of grep
- confidence score when more than one rule could match

MIT.
