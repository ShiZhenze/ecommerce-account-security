# About the coursework code

`password_auth.c` is the implementation from a coursework project completed
for **Embedded Systems Security** at Fujian Police College, autumn semester
2025. It is included here because it is the starting point for the analysis
in the main README, and because the design decisions discussed there are
easier to follow with the original code in view.

## Scope of the original project

The brief was to protect the login step on an embedded Linux device against
two threats: passwords stored in plaintext, and brute-force guessing at the
prompt. The implementation is a single C program running on Ubuntu 22.04
that provides:

- registration with password confirmation
- an 8-character random salt generated per user
- SHA-256 hashing over password concatenated with salt
- credentials persisted as `username:salt:hash`, file mode 600
- a failure counter persisted across runs, locking the account for 10
  seconds after 3 consecutive failures
- input length bounds and buffer-safe string handling throughout

## My role

This was a three-person team project. I was the team lead and was
responsible for the security design: the threat model, the choice of salted
hashing over plaintext storage, the lockout mechanism, and the file
permission scheme. I also wrote and debugged the implementation.


## Why the original report is not published here

The submitted report carries the names and student ID numbers of my two
teammates. Publishing it would expose their personal data without their
consent, which would sit poorly in a repository about protecting user
credentials. The code is my own work and is published; the report is not.

The report is available on request.

## Known limitations of this code

These are discussed at length in the main README, in the context of what
changes when the same mechanism is deployed on a commercial platform rather
than a single device:

- the salt is generated with `rand()` seeded from time and PID, which is not
  a cryptographically secure source
- SHA-256 is a fast hash; password storage should use a deliberately slow
  algorithm such as bcrypt, scrypt or Argon2
- the lockout counter is keyed on the account only, and resets automatically
  after 10 seconds
- only a single registered user is supported

In the context of the original brief — one device, one user, an attacker at
a physical prompt — these are reasonable simplifications. The main README is
about what happens to each of them when the context changes.
