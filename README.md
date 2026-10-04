# dockerwarden

[![CI](https://github.com/sriharifortitude/dockerwarden/actions/workflows/ci.yml/badge.svg)](https://github.com/sriharifortitude/dockerwarden/actions/workflows/ci.yml)

A security linter for Dockerfiles: unpinned base images, containers that run
as root, secrets baked into layers, downloads piped into a shell, and
verification turned off. Python 3.12, no dependencies, MIT.

## Why

A Dockerfile is a build script that runs with network access and produces
something you ship. The mistakes that matter are not exotic. A `FROM node`
changes every time the publisher pushes. An `ENV` with a password stores it in
the image configuration for anyone who can pull the image. A `COPY .env` puts
the file in a layer, and deleting it in the next instruction does not take it
out of the previous one. `curl ... | sh` builds the image from whatever a
server returns that day.

dockerwarden reads the Dockerfile the way Docker does (continuation lines with
comments between them, heredocs, `ARG` before `FROM`, `--mount` and `--from`
flags, multi-stage builds) and reports each of these with the line and the fix.
It is the supply-chain companion to
[actionwarden](https://github.com/sriharifortitude/actionwarden), which does
the same for GitHub Actions workflows.

## What it finds

Two Dockerfiles in `testdata/vulnerable/`: a Node service and a Go service
built in two stages.

<!-- demo:start -->
```
testdata/vulnerable/Dockerfile:1  MEDIUM   DW001  base image node has no tag, so it resolves to :latest, which changes under you
testdata/vulnerable/Dockerfile:1  MEDIUM   DW003  the final stage never sets USER, so the container runs as root unless its base image sets another user
testdata/vulnerable/Dockerfile:2  MEDIUM   DW004  ARG NPM_TOKEN has a literal default, which stays in the image history (docker history)
testdata/vulnerable/Dockerfile:3  HIGH     DW004  ENV DB_PASSWORD stores a literal secret in the image's configuration, readable by anyone who can pull the image
testdata/vulnerable/Dockerfile:4  LOW      DW007  apt-get update in a RUN of its own is cached as a layer and goes stale; run it in the same RUN as the install
testdata/vulnerable/Dockerfile:5  LOW      DW007  apt-get install leaves /var/lib/apt/lists in the layer; remove it in the same RUN
testdata/vulnerable/Dockerfile:5  LOW      DW007  apt-get install without --no-install-recommends pulls in packages nobody asked for, each one more to patch
testdata/vulnerable/Dockerfile:6  MEDIUM   DW005  downloads a script and pipes it into a shell, so the image is built from whatever the server returns that day
testdata/vulnerable/Dockerfile:7  MEDIUM   DW006  ADD fetches https://example.com/tool.tar.gz with no --checksum, so nothing verifies what arrives
testdata/vulnerable/Dockerfile:8  HIGH     DW012  copies .env into the image; files like this carry credentials and stay in the layer even if a later step deletes them
testdata/vulnerable/Dockerfile:10  LOW      DW008  RUN uses sudo; build steps already run as the current USER, so sudo only adds a setuid binary to the image
testdata/vulnerable/Dockerfile:10  MEDIUM   DW009  chmod 777 makes files writable by every user in the container, including whatever process an attacker gets
testdata/vulnerable/Dockerfile:11  MEDIUM   DW010  EXPOSE 22: an SSH server in a container is a second way in, and one the image has to keep patched
testdata/vulnerable/Dockerfile.multistage:1  LOW      DW002  base image golang:1.22 is pinned by tag, and a tag can be re-pushed to different content
testdata/vulnerable/Dockerfile.multistage:6  LOW      DW002  base image alpine:3.20 is pinned by tag, and a tag can be re-pushed to different content
testdata/vulnerable/Dockerfile.multistage:7  LOW      DW007  apk add without --no-cache leaves the package index in the layer
testdata/vulnerable/Dockerfile.multistage:8  MEDIUM   DW011  COPY --from=biuld: no stage is named 'biuld', so Docker will pull an image called 'biuld' from the registry instead
testdata/vulnerable/Dockerfile.multistage:9  MEDIUM   DW003  the final stage ends as root

18 finding(s): 2 high, 9 medium, 7 low, in 2 Dockerfile(s)
```
<!-- demo:end -->

| Rule | Severity | What |
| --- | --- | --- |
| DW001 | medium | base image untagged or `:latest` |
| DW002 | low | base image pinned by tag, not digest |
| DW003 | medium | final stage runs as root |
| DW004 | medium, high | literal secret in `ENV` / `ARG`, or a token-shaped string |
| DW005 | medium | `curl ... \| sh` |
| DW006 | low, medium | `ADD` from a URL without `--checksum`, or where `COPY` is meant |
| DW007 | low | apt / apk usage that bloats or stales the image |
| DW008 | low | `sudo` in a build step |
| DW009 | medium | `chmod 777` and friends |
| DW010 | medium | SSH server in the image |
| DW011 | medium | `COPY --from=` a stage that does not exist |
| DW012 | medium, high | `.env`, private keys, `.npmrc` copied into the image |
| DW013 | medium | `curl -k`, `--no-check-certificate`, `--trusted-host`, ... |

`dockerwarden rules` prints each with why it matters and how to fix it.

Two of these are less obvious than they look.

**DW011** is a typo that becomes a supply-chain hole. `COPY --from=biuld`
looks like a stage name. If no earlier stage has that name, Docker treats it as
an image and pulls `biuld` from the registry, so the files come from whoever
owns that name there.

**DW003 follows the stage chain.** `FROM base` inherits `base`'s `USER`, so a
`USER app` two stages up counts. The rule also recognises images that publish
a non-root default by name (`nonroot`, `unprivileged`, `chiseled`, `rootless`).
That is a naming convention, not a lookup: dockerwarden does not pull images
([ADR 1](docs/adr/0001-judge-the-dockerfile-not-the-image.md)).

## Usage

```bash
pip install git+https://github.com/sriharifortitude/dockerwarden@v0.1.0

dockerwarden scan                      # every Dockerfile under .
dockerwarden scan --brief services/    # one line per finding
dockerwarden scan --fail-on medium .   # exit 1 at medium or above (default: high)
dockerwarden scan --format sarif . > dockerwarden.sarif
dockerwarden scan --format json .
```

A directory is searched for `Dockerfile`, `Dockerfile.*`, `*.Dockerfile` and
`Containerfile` (skipping `.git`, `node_modules`, `.venv`). A named file is
scanned whatever it is called.

Exit codes: 0 nothing at or above `--fail-on`, 1 at least one finding is, 2 a
usage error or a file that could not be read. A file that is not a Dockerfile
fails the run even when everything else is clean, because a check that exits 0
having read nothing looks like a result and is not one.

Suppress a finding with a reason, on the comment line directly above the
instruction:

```dockerfile
# dockerwarden:ignore DW003 -- the base image already runs as uid 1000
FROM registry.example.com/team/app-base:7
```

A suppression without a reason suppresses nothing and is itself reported
(DW000). There is no same-line form, because in a Dockerfile a `#` after an
instruction is part of the instruction, not a comment
([ADR 2](docs/adr/0002-suppressions-are-comment-lines-with-a-reason.md)).

## Run on real Dockerfiles

**My own repositories** (12 Dockerfiles, 2026-10-04): 24 findings, all DW002
(tag, not digest). No root users, no secrets, no unverified downloads. Running
it also showed a false positive in my own rule: `nginx-unprivileged` and
`...-chiseled` images do set a non-root user, which is why DW003 now
recognises those names.

**214 Dockerfiles from the official Docker library repositories** (python,
node, nginx, redis, postgres, golang, php, ruby, mysql, httpd, memcached,
rabbitmq): every one parsed. 465 findings: 231 DW002, 208 DW003, 23 DW007, 3
DW001. DW003 is those images' final stages, which these base images leave
as root by design. The three DW001 are `node:0.x` images from a decade ago. Four
`Dockerfile.template` files (Jinja, starting with `{{`) were refused as not
Dockerfiles, which is the right answer.

That corpus also found a bug in the first version: it reported 120 DW007
findings, 97 of them for files that clean up with `apt-get dist-clean` (a
newer apt command that removes the package lists), which it did not know.
Fixed, with a test. It also showed that `apt-get clean` had been wrongly
accepted as cleaning the lists; it empties the package cache, not the lists.

What this does and does not show. It shows the parser copes with real
Dockerfiles, many of them long, shell-heavy and full of comments between
continuation lines. It does not show the rules are accurate: there is no
ground truth for those files. I have not compared the output with hadolint,
the established Dockerfile linter.

## Tested

```bash
pip install -e ".[dev]"
pytest          # 127 tests
ruff check src tests && mypy
```

Each rule has cases that must fire and cases that must not. The parser has
tests for continuations with comments and blank lines between, heredocs, the
`escape` directive, flags, JSON form, and the errors (unknown instruction,
unterminated heredoc, instruction before `FROM`). Twelve of the tests were run
against deliberately broken copies of the code to check they fail: comments
inside a continuation, heredoc reading, `:latest` matching, stage inheritance,
the pipe-to-shell pattern, a suppression without a reason, the unknown-stage
check, the secret-name boundary, `dist-clean`, the size cap, the exit code for
an unreadable file, and the SARIF levels. All twelve were caught. CI builds the
wheel, installs it into a clean environment and diffs the example above against
what it prints.

Secret-shaped strings are built at test time rather than written into the
repository, so nothing here trips a secret scanner.

**Not tested:** against Dockerfiles known to be vulnerable; false negatives
are unmeasured.

## Not covered

- What is *in* the image. dockerwarden reads the Dockerfile, not the layers,
  and does not query a registry, so it cannot tell you a base image has a CVE
  or what user it really runs as. Use an image scanner for that.
- `.dockerignore`, the build context, and Compose files.
- `ONBUILD` triggers are read as instructions but not analysed.
- A `FROM` whose image comes from an `ARG` with no default is skipped.
- Findings are reported at the instruction's first line, not at the line
  inside a long `RUN` where the problem is.
- DW004 knows six token formats and a list of secret-sounding names. For
  secrets in a whole repository use
  [credsweep](https://github.com/sriharifortitude/credsweep).

See [`docs/adr/`](docs/adr/) for the decisions behind it.

## Licence

MIT.
