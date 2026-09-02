# Account Security Design for E-commerce Platforms

**Every control that stops a fraudster also stops some paying customers.
This is a study of where that dial should sit, and who in the business should
own it.**

Author: Zhenze Shi · 2026

---

## The argument in three lines

1. On a retail platform, security controls are not free — they cost orders,
   customers and support capacity, and those costs are usually invisible to
   the team setting the policy.
2. Because the cost is invisible, security policy tends to ratchet in one
   direction: every incident argues for tightening, nothing argues for
   loosening, and the business absorbs the difference quietly.
3. The fix is to put friction where money leaves the business rather than
   where it arrives, and to hold one owner accountable for the fraud rate and
   the conversion rate together.

---

## 1. Why this is a commercial decision, not a technical one

A security control on a single device has one job: keep the attacker out.
Tightening it costs nothing, because there is one legitimate user and they
know their own password.

A retail platform has no such luxury. The same login screen serves attackers
and paying customers, and no control can tell them apart in advance.

Take one example. Requiring an SMS code at checkout blocks a share of
fraudulent transactions. It also causes a share of genuine customers,
mid-purchase, to abandon the basket — the phone is in another room, the code
is slow, the session times out. The first number is money saved. The second
is money never earned. Both are real, and they move in opposite directions.

That pattern holds for almost every control worth having:

| Control | What it prevents | What it costs |
|---|---|---|
| Aggressive lockout | Credential guessing | Genuine users locked out; support tickets |
| Mandatory 2FA at login | Account takeover | Drop-off at sign-in; abandoned sessions |
| Strict password rules | Weak passwords | Registration abandonment; reset volume |
| Device re-verification | Session hijacking | Friction on shared and new devices |

So there is no "maximum security" setting worth choosing. Push every dial to
its limit and fraud approaches zero while the business stops functioning. The
design problem is to find, for each control, the point where the marginal
loss prevented stops exceeding the marginal revenue given up — and to
recognise that this point is different for different actions, different
customers, and different moments.

## 2. What is actually at risk

Generic security writing lists threats like eavesdropping and malware. Those
matter, but they are not what distinguishes online retail. What makes a
retail account worth attacking is that it is attached to stored value, saved
payment methods, and promotional budget.

| Threat | How it works | What it costs the business |
|---|---|---|
| **Credential stuffing** | Passwords leaked from other sites, replayed in bulk | Account takeover; fraudulent orders on saved cards |
| **Bulk account creation** | Automated sign-ups farming new-user coupons | Marketing budget drained by users who never convert |
| **Automated purchasing** | Scripts buying limited stock in seconds | Real customers cannot buy; resale damages the brand |
| **Account sharing and resale** | Membership credentials rented out | Direct erosion of subscription revenue |
| **Refund fraud after takeover** | Compromised account orders, then refunds elsewhere | Direct loss plus chargeback penalties from processors |

Two things follow, and they shape the whole design.

**The attacker's economics differ by threat.** Credential stuffing pays at a
fraction of a percent success rate, because the input list costs almost
nothing — so it must be caught at scale, by pattern. Coupon farming only pays
while account creation is nearly free — so the answer is to make creation
cost something. One countermeasure does not serve both.

**Loss is concentrated at specific actions, not at login.** A compromised
session browsing the catalogue costs nothing at all. The money is lost at
payment, at withdrawal of stored balance, and at changes to the bound phone
number or payment method. That is where security effort belongs — not spread
evenly across the session.

## 3. Five design decisions

Each is stated as the business trade-off first, with the technical
implementation compressed to a line. The engineering is mostly standard
practice; the decisions are the substance.

### 3.1 Make stolen password files worthless

**The trade-off.** Slower password checking costs a fraction of a second per
login and some server capacity at peak. In return, a database breach stops
being an immediate disaster.

**Verdict: the easiest call on this list.** The delay is below what a customer
can perceive, the infrastructure cost is small and predictable, and the
protection applies precisely when every other layer has already failed.

*Implementation: Argon2id with per-user salts from a cryptographically secure
source, work factor tuned to roughly 100 ms per verification. See
[appendix A.1](#a1-fast-hashing-is-the-wrong-tool-for-passwords) for why the
common shortcut fails.*

### 3.2 Count failures across dimensions, not just per account

**The trade-off.** Counting failures by network address catches bulk attacks
that per-account counting misses entirely. It also risks blocking whole
offices, campuses and mobile networks, where hundreds of legitimate customers
share one address.

**Verdict: worth doing, but thresholds must differ by dimension.** Per-account
limits can be tight, since one account generating many failures is genuinely
odd. Network-level limits must be loose and should add verification rather
than block. The platform-wide failure rate should block nothing at all — its
value is as an early warning that a campaign is underway.

*Implementation: independent counters per account, per source IP, per device
fingerprint, plus an aggregate anomaly signal. See
[appendix A.2](#a2-credential-stuffing-does-not-look-like-brute-force) for why
per-account counting fails against the most common attack.*

### 3.3 Escalate friction instead of locking the door

**The trade-off.** A hard lockout after three failures stops guessing. It also
stops the customer who cannot remember which of their passwords they used
here — and turns them into a support ticket, or a lost customer.

**Verdict: replace lockout with escalation.** The two populations behave
differently as friction rises, and escalation exploits that.

| Failed attempts | Response |
|---|---|
| 1–3 | Retry, no friction |
| 4–6 | CAPTCHA or equivalent challenge |
| 7+ | Exponential backoff, doubling each attempt |
| Anomalous pattern | Step-up verification on next attempt |

Backoff makes sustained automated attack pointless within a handful of
attempts, while a real customer always has a path forward. Hard lockout is
worse on both counts: the attacker simply moves to the next account on the
list, and the customer contacts support. **A permanent lockout converts a
security event into a support cost and often a churn event.**

### 3.4 Put the friction where money leaves, not where it arrives

**The trade-off.** Uniform security spends its entire friction budget at
login — the moment a customer is most likely to give up — and then leaves the
account settings page, where takeover is actually converted into cash, no
better defended than the product catalogue.

**Verdict: match verification strength to what is at stake.**

| Action | Risk if compromised | Verification |
|---|---|---|
| Browse, search, add to basket | Negligible | None |
| Place an order on a saved card | Moderate | Password or valid session |
| Withdraw balance, change bound phone, change payment method | High | Password plus second factor, and notify the previous contact |

**This is the layer with the best return in the whole design**, because it
does not add friction so much as move it — off the paths that earn money, onto
the paths that lose it.

### 3.5 Attack password reuse at the source

**The trade-off.** Screening new passwords against known-breached credentials
adds a step at registration for the minority who are affected, with some
abandonment.

**Verdict: worth it, and cheaper than it looks.** Only customers who chose an
already-compromised password see any friction; everyone else passes through
unaware. It also strikes at the root of credential stuffing — the attack only
works because passwords are reused across sites — which no amount of rate
limiting can address.

*Implementation: k-anonymity range query against a breach corpus, so the
password itself never leaves the platform.*

## 4. Measuring it — and the organisational trap

A design like this can only be judged against both of its objectives at once.
The metric set matters as much as the controls, because what gets measured
determines which way the dials get turned.

| Metric | What it captures | Direction |
|---|---|---|
| Account takeover rate | Compromised accounts per 10,000 per month | Lower |
| False lockout rate | Genuine users blocked by a control | Lower |
| First-attempt login success | Customers who get in without friction | Higher |
| Checkout abandonment | Sessions reaching payment but not completing | Lower |
| Security support tickets | Recovery, unlock and reset requests | Lower |

The first row is what a security function is usually accountable for. **The
other four are the cost side of the ledger, and they land on growth, product
and customer service — teams with no formal say in the policy that generates
them.**

That split produces a failure mode worth designing around. If only the first
metric is owned and reported, every incident creates pressure to tighten and
nothing ever creates pressure to loosen. The policy ratchets in one direction
indefinitely. Nobody makes a bad decision at any point; the costs are simply
real and unattributed.

The practical recommendation is therefore organisational as much as
technical: **report the whole set together, to one owner, on one dashboard.**
A change that halves takeover while doubling checkout abandonment should be
visible as the trade it is — not as a security win in one report and an
unexplained conversion dip in another.

## 5. Limitations

- This is a design study. Nothing here has been deployed or tested against
  production traffic; the trade-offs are argued rather than measured.
- No numeric thresholds are proposed. The right values depend on a platform's
  own fraud rate, order value distribution and customer tolerance, and can
  only be set from its own data.
- Detection beyond rate limiting — device fingerprinting, behavioural
  signals, graph analysis of account relationships — is out of scope, though
  at real scale it carries much of the load.
- Regulation is not addressed. Payment authentication rules, data protection
  law and card scheme requirements constrain several of these choices, and
  vary by jurisdiction.
- The economic argument is qualitative. A fuller version would model expected
  loss against threshold settings, identify the minimum explicitly, and show
  how sensitive that answer is to the assumed cost of a single takeover.

---

## Background

In autumn 2025 I led a three-person coursework project for an Embedded
Systems Security course, building a salted-hash authentication system with
brute-force protection for an embedded Linux device. I was responsible for
the security design and wrote the implementation. The code is in
[`coursework/`](coursework/), with scope and background in
[`coursework/NOTES.md`](coursework/NOTES.md).

That project answered a narrow question: how do you stop someone standing in
front of a device from guessing their way in? This document asks what changes
when the same login screen is put in front of several million paying
customers — which turns out to be less a security question than a question
about who bears the cost of the answer.

---

## Appendix — what breaks at platform scale

Three properties of the coursework implementation are reasonable
simplifications for one device and one user, and genuine problems on a
platform. They are the technical basis for decisions 3.1 and 3.2.

### A.1 Fast hashing is the wrong tool for passwords

The coursework stores passwords as a single round of SHA-256 over the
password concatenated with a random salt.

The salt does its job. Without it, an attacker who obtains the database can
look every hash up in a table of common passwords prepared in advance, and
recover hundreds of thousands of accounts in seconds. With a distinct salt
per user, every account must be attacked separately.

But salting does not stop direct guessing, and SHA-256 is built for speed.
Commodity GPU hardware evaluates it billions of times per second, so an
exhaustive search over short or common passwords finishes in minutes once the
file is in hand.

The fix is a deliberately slow algorithm — bcrypt, scrypt or Argon2 — with a
work factor set so one verification takes around 100 ms. A customer cannot
perceive that during login. An attacker's throughput falls from billions per
second to roughly ten, which changes the arithmetic of an offline attack by
many orders of magnitude. Argon2 also demands substantial memory per
evaluation, which limits the parallelism that makes GPU attacks efficient.

Stated plainly: **a salt stops the attacker looking the answer up; a slow hash
stops them working it out.** The coursework does the first and not the second.

A second, smaller issue: the salt is generated with `rand()` seeded from the
current time and process ID. Both are narrow and partly guessable. On one
device this hardly matters. Across a breached user base, salts drawn from a
predictable sequence weaken the very property that makes salting useful.

### A.2 Credential stuffing does not look like brute force

This is the most consequential gap, and the least obvious.

The coursework keeps a failure counter for the registered account and locks
after three consecutive failures. That is the right shape for the threat it
was built against: a person at a physical prompt, trying passwords one after
another.

Credential stuffing looks nothing like that. The attacker holds a list of
username–password pairs leaked from other sites and tries each **once**. One
attempt against a million accounts, not a million attempts against one
account. A per-account counter never approaches its threshold, and the attack
passes through untouched.

Catching it requires counting along dimensions a single-device design has no
reason to have: failure rate per source address, per device fingerprint, and
platform-wide over time. A stuffing run shows up as an anomaly in the
aggregate long before any individual account looks unusual.

### A.3 A short lockout is a scheduling parameter

The coursework locks for ten seconds, then resets the counter automatically.

Ten seconds is a real deterrent to a person typing at a prompt. To a script it
is a delay to schedule around. Against automation, a short fixed lockout
imposes almost no cost on the attacker while imposing the full cost on any
customer who has forgotten their password — which is the reasoning behind the
escalating scheme in decision 3.3.

---

## Repository contents

```
ecommerce-account-security/
├── README.md
├── LICENSE
└── coursework/
    ├── password_auth.c   # coursework implementation
    └── NOTES.md          # project background, scope, known limitations
```

## License

MIT License. See [`LICENSE`](LICENSE).
