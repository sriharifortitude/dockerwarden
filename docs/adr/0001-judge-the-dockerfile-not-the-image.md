# 0001. Judge the Dockerfile, not the image

**Status:** accepted

## Decision

dockerwarden reads a Dockerfile and nothing else. It never builds, never pulls
an image, and makes no network call. Where a rule would need to know what is
inside a base image, it uses what the Dockerfile and the image's *name* say.

## Reasoning

- **Determinism.** The same file gives the same findings on a laptop, in CI
  and offline, today and next month. A linter whose answer depends on what a
  registry returns cannot gate a build.
- **Speed and trust.** It runs in milliseconds, needs no credentials, and
  cannot be made to pull an attacker's image by scanning a hostile Dockerfile.
- **A clear boundary.** Image scanners already answer "what is in this image".
  A Dockerfile linter's job is what the *file* does wrong: the instruction
  that stores a secret, the stage name that is a typo.

## Cost, and one compromise

Some rules are weaker than they would be with the image in hand. DW003 (runs
as root) cannot see a `USER` baked into the base. Rather than flag every
`FROM nginx-unprivileged` as root, it recognises the names `nonroot`,
`unprivileged`, `chiseled` and `rootless` as images that publish a non-root
user. That is a convention, and a name can lie, so the finding is wrong in
the other direction for an image that misuses one of those words. The
alternative was a known false positive on every distroless and unprivileged
image, which is how a linter gets switched off.

Anyone who knows better can suppress it with a reason (ADR 2).
