# Executive Summary - VulnTracker Security Review

## What it is

An internal system that tracks customers' vulnerabilities and lets our staff
share individual reports with them. Built as a prototype; not security-reviewed
until now.

## Where we were, where we are

**Before:** anyone who could reach the application could take it over - bypass
login, read and change any customer's data, and pull cloud credentials through a
connected service. The key that signs login sessions was sitting in our source
history.

**After:** those paths are closed and covered by automated tests. Login can no
longer be bypassed, each user sees only their own data, secrets are out of the
code, and the deployment is locked down (network-isolated, least-privilege,
secrets from a vault). No known critical exposure remains in the application
itself.

## What still needs attention

1. **A connected helper service isn't locked down.** It sends out notifications
   and sits behind our network defences, so it isn't exposed today - but anyone
   who got inside the network could misuse it to reach other systems. The team
   that owns that service needs to close this.
2. **The login page doesn't limit password guessing.** Someone could try many
   passwords in a row. The usual protection for this lives in shared
   infrastructure that sits in front of the application, not in the application
   itself.
3. **Parts of the system are still demo-grade** - there's no backup of the data
   and only one copy of the service running. Nothing an attacker can exploit,
   but not something we'd want real customer data to depend on yet.

## What we will do about it

- **Security checks run on every change** and block a release if they find a
  serious flaw - the guardrail is the pipeline, not someone remembering to look.
- **Replace the exposed login key**, and have the pipeline automatically reject
  any secret, out-of-date component, or weakened security setting in future
  changes.
- **Keep components up to date continuously** and grow the automated tests, so
  each fix stays fixed and problems surface the moment they're introduced.
- **Engage the notification service's owners** to close the one issue outside our
  code, then commission a full external security assessment before launch and on
  a regular schedule after.
