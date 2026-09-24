# himalaya-sherpa

A policy gate that lets AI agents use email through
[himalaya](https://github.com/pimalaya/himalaya) while:

- **never giving the agent the account credentials**,
- **holding outgoing mail for your approval** (or saving it to Drafts, denying it, or
  pretending to send it),
- **withholding one-time codes, password resets and sign-in links**, redacting
  other sensitive mail, and stopping the agent from deleting security alerts.

An agent that can read your inbox and send mail can take over most of your online
accounts ("reset my password, then read the email"), and a single injected
instruction in an incoming message is enough to try. himalaya-sherpa closes those
paths while leaving everyday email work (triage, reading, drafting replies) intact.

## How it works

```
agent (uid hermes)                          service user sherpa (systemd, or its own container)
  himalaya ──► sherpa client ──unix socket──►  sherpa-gate ──► himalaya ──► IMAP / SMTP / JMAP
   (no credentials, no sudo)  /run/himalaya-   │ /etc/himalaya-sherpa/sherpa.toml    policy
                              sherpa/hermes.sock│ /etc/himalaya-sherpa/himalaya.toml  no plain passwords
                                               │ /etc/himalaya-sherpa/secrets/*      root:sherpa 0640
                                               └ /var/lib/himalaya-sherpa            outbox, audit log
you ── sudo sherpa-admin review / policy / log / doctor
```

A wrapper running as the agent's own user cannot protect a password: the agent could
read the config, run the password command, swap the binary or read the process's
memory. So the gate runs as a separate **service user**, and the agent reaches it only
through a Unix socket:

- **The client holds nothing.** `sherpa` (installed as the agent's `himalaya`) forwards
  the arguments and makes no decisions. It does the agent's file I/O with the agent's
  own privileges: it reads the files named by `--attach` and saves downloaded attachments.
- **The gate starts clean.** systemd owns the socket and starts a fresh, sandboxed gate
  process for each connection (`Accept=yes`), in a fixed environment, so the agent
  controls nothing about how the gate runs. The unit uses `NoNewPrivileges`,
  `ProtectSystem=strict`, no capabilities and a syscall filter (`systemd-analyze
  security` rates it 1.5/10).
- **Each agent has its own socket**, `/run/himalaya-sherpa/<agent>.sock`, owned by the
  service user and the agent's group, mode 0660. The gate also checks the kernel-verified
  peer uid (`--allow-uid`), and records the peer uid and pid in the audit log.
- **No sudo.** The agent needs no sudo rights at all; `doctor` fails if it can act as
  root or as the service user.

The gate accepts a strict subset of the himalaya v2 command line and re-parses every
request itself. Everything else is rejected, including `-c`/`--config`,
`--log-level`/`--log-file`, the raw `imap`/`smtp`/`gmail`/`jmap` commands and
`account configure`. Every message the agent reads, replies to, forwards, flags, moves
or deletes is first fetched and classified. If a decision cannot be written to the
audit log, the agent gets nothing back.

## Install

Build as **a user other than the agent**, so the agent cannot tamper with the binaries
that will hold your credentials. `setup` refuses binaries and configs the agent can
write to, unless you pass `--allow-untrusted`.

```sh
git clone https://github.com/<you>/himalaya-sherpa && cd himalaya-sherpa
make release himalaya      # himalaya: the pinned, checksum-verified release

sudo target/release/sherpa-admin setup \
    --agent-user hermes \
    --himalaya .cache/himalaya-2.1.0/himalaya \
    --import-config /home/hermes/.config/himalaya/config.toml \
    --link /home/hermes/.local/bin/himalaya     # optional: keep the agent's `himalaya` command
```

`setup` prints each step (preview it with `--dry-run`). It:

1. creates the `sherpa` system user;
2. installs `sherpa-gate` and himalaya for the service user only (`root:sherpa 0750`),
   the client as `/usr/local/bin/sherpa`, and `sherpa-admin`;
3. writes the default policy to `/etc/himalaya-sherpa/sherpa.toml`;
4. imports your himalaya config and rewrites every `password.command` to read a secret
   file. It flags any other setting that runs a command (hooks and so on) for you to review;
5. asks for each account password, or with `--import-secrets` runs the original
   password commands as the agent user one last time;
6. installs the socket and service units for the agent and enables the socket;
7. with `--link`, points the given paths at the client (created as the agent user).

The client finds the agent's socket by user name. Set `SHERPA_SOCKET` to use another path.

Then:

```sh
sudo sherpa-admin doctor --agent-user hermes   # checks the boundary from the agent's side
```

Finally, **remove the agent's copy of the credentials** (its himalaya config and any
`pass` entries it can decrypt), and **rotate the passwords**, since the agent could read
them until now. `doctor` warns about leftovers it can see.

## Containers

The same socket works across containers. Tested with rootless podman under SELinux
enforcing:

- **Gate and agent in separate containers** (recommended): run the gate image, share
  only the socket volume with the agent's container, and mount the static client there
  as `himalaya`. See [`contrib/compose.yaml`](contrib/compose.yaml) and
  [`contrib/Containerfile`](contrib/Containerfile) (`make image`). The gate container
  runs read-only with no capabilities, and gets the password as a container secret.
- **Agent sandbox containers, gate on the host** (for example Hermes with
  `terminal.backend: docker`): mount the socket and a static client (`make static`)
  into the sandbox:

  ```yaml
  terminal:
    backend: docker
    docker_volumes:
      - "/run/himalaya-sherpa/hermes.sock:/run/himalaya-sherpa/agent.sock"
      - "/path/to/static/sherpa:/usr/local/bin/himalaya:ro"
    docker_env: { SHERPA_SOCKET: /run/himalaya-sherpa/agent.sock }
  ```

  On SELinux hosts, the default policy does not let a container process connect to a
  service running outside containers. Run the gate as a container instead (above), or
  give the sandbox a policy that allows the connection (for example with
  [udica](https://github.com/containers/udica)).

Across user namespaces the kernel reports the peer as uid 0, so `--allow-uid` does not
apply there: the socket volume itself is the agent's access, which is why the image
uses socket mode 666 inside a volume shared with one agent only.

Containers also make it practical to close the other exfiltration paths: give the
gate's network egress to your mail servers only, and the agent's to the model API only.

## What the agent sees

The agent's commands look like himalaya's, and every refusal explains itself and tells
the agent not to look for a workaround:

```console
$ himalaya message read 1002
Message 1002 is withheld by policy (filter: one-time-code). It contains content agents
may not read, such as a one-time code, a password reset or sign-in link. ...

$ himalaya message reply 57 --body "Sure, 1pm works" --send
Message queued for human approval (outbox id 20260924-075608-1f09). It has NOT been
sent yet; the user will review it and decide. Do not resend it ...

$ himalaya outbox list
$ himalaya policy          # the rules, in plain words
```

[`docs/agent-prompt.md`](docs/agent-prompt.md) has a snippet to add to the agent's
instructions.

## Reviewing

```sh
sudo sherpa-admin review list           # pending messages
sudo sherpa-admin review show <ID>
sudo sherpa-admin review approve <ID>                # send it (needs a send backend)
sudo sherpa-admin review approve <ID> --via draft    # or put it in Drafts, send it yourself
sudo sherpa-admin review deny <ID> --reason "wrong recipient"
sudo sherpa-admin log -n 100            # audit log (metadata only, never contents)
sudo sherpa-admin log --decision suspicious   # commands the gate refused that reach for
                                              # settings, forwarding, raw protocols or config
```

Commands the gate does not offer are refused and logged with their command words only
(never values such as addresses or paths). Refused commands that mention forwarding,
filters, delegates, settings, raw protocols, credentials or configuration are logged as
`suspicious`: an agent reaching for those is a strong sign of an injected instruction.

## Policy

See [`etc/sherpa.toml`](etc/sherpa.toml); every option is documented there. In short:

| Setting | |
|---|---|
| `send.mode` | `queue` (default), `draft`, `deny`, `blackhole` |
| `send.auto-send-to` | recipient patterns that go out without approval (with a daily cap) |
| `[[filter]]` | `from` / `to` / `subject` / `body` / `text` regexes, with an action |
| filter actions | `withhold` (unreadable), `redact` (codes and links masked), `protect` (read-only) |
| `release-after-hours` | embargo: e.g. withhold an OTP for 48h, then show it redacted |
| `read.withheld` | `notice` (say it's withheld) or `not-found` |
| `search.allow-body` | off by default: body searches work as an oracle on withheld mail |
| `mailboxes.readable` / `writable` | optional mailbox allowlists |

The default filters cover one-time codes, verification mails, password resets, magic
links, security alerts, mail-forwarding confirmations (whose code Gmail puts in the
subject, so they are hidden from listings), and notices that forwarding, filters,
delegates or send-as addresses changed (readable, but the agent cannot hide them), in
English and Spanish.

### Testing policy changes

The policy carries its own test cases: `[[example]]` messages with the outcome they
must get, and `[[send-example]]` recipients with the route they must take:

```toml
[[example]]
name = "code in the subject is hidden from listings"
from = "no-reply@instagram.com"
subject = "837201 is your Instagram code"
body = "Someone tried to log in. 837201 is your Instagram code."
expect = "withhold"            # allow | protect | redact | withhold
secrets = ["837201"]           # must never reach the agent, in listings or reads

[[send-example]]
name = "mail to anyone needs approval"
to = ["someone@example.org"]
expect = "queue"               # auto-send | queue | draft | deny | blackhole
```

Examples run through the same code as the gate: listing classification, full
classification and the rendering the agent receives. So `secrets` catches real leaks,
such as a code shown in a subject line or left unmasked by redaction.

```sh
sudo sherpa-admin policy edit                 # like visudo: edit, check, diff, install
sudo sherpa-admin policy install new.toml     # check, diff, confirm, install
sherpa-admin policy check new.toml            # just check
sherpa-admin policy test --policy new.toml message.eml   # what the agent would see
```

To see what a policy would do to your actual mail before installing it, dry-run it
against a mailbox:

```sh
sudo sherpa-admin policy scan --days 30                  # what the installed policy catches
sudo sherpa-admin policy scan --policy new.toml --compare --since 2026-09-01 --until 2026-09-24
sudo sherpa-admin policy scan -a gmail -m inbox -m archive --limit 500 --all --json
```

The scan runs as the service user, fetches each message (4 in parallel by default,
see `--jobs`), and classifies it exactly as the gate would. It lists what a filter
matches, or with `--compare`, only the messages the candidate treats differently from
the installed policy. Nothing is changed in the mailbox (messages are not marked seen),
and the scan itself is recorded in the audit log.

A policy that fails to parse or gets any example wrong is never installed. When a
filter misses (or wrongly catches) a message, save it as `.eml`, look at it with
`policy test`, and add it as an example with the fix.

## Limitations

- **Email is not the only way out.** If the agent has unrestricted network access, it
  can exfiltrate data with `curl`. Pair this with egress rules if that is in your
  threat model (see [Containers](#containers)).
- Filters are regular expressions: good at the formulaic mail services send, not a
  guarantee. Messages that can't be parsed are withheld (fail closed).
- Envelope listings are classified on sender, recipients and subject only. A message
  matched by a body rule shows in listings but can't be read.
- Mailbox counts (`mailbox list --counts`) include withheld messages.
- `blackhole` mode deceives the agent by design. The agent may then tell you it sent
  something. Prefer `queue` or `draft`.
- Targets the himalaya v2 CLI (tested with v2.1.0).
- Socket paths are limited to 107 bytes by the kernel.

## Development

```sh
make            # list the tasks
make check      # formatting, clippy, docs and tests: run before pushing
make test-e2e   # end-to-end tests against the pinned himalaya release (downloaded, checksum-verified)
make static     # static binaries for containers (x86_64-unknown-linux-musl)
make image      # the gate container image
make ci         # everything CI runs, including cargo-deny
```

The end-to-end tests start a real `sherpa-gate` on a temporary socket and drive it
through the real client, against a temporary Maildir account. They use `HIMALAYA_BIN`,
the pinned release in `.cache/` (`make himalaya`), or a `himalaya` on `PATH`, and are
skipped if none is found (CI sets `SHERPA_REQUIRE_HIMALAYA=1` to fail instead). The
minimum supported Rust version is 1.88 (`make msrv`).

To try it without installing anything:

```sh
target/debug/sherpa-gate serve --agent me --socket /tmp/sherpa.sock --config my-sherpa.toml &
SHERPA_SOCKET=/tmp/sherpa.sock target/debug/sherpa envelope list
```

## License

MIT
