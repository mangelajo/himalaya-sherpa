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
agent (uid hermes) ── sherpa ─sudo─► sherpa gate (uid sherpa) ──► himalaya ──► IMAP/SMTP/...
                                      │  /etc/himalaya-sherpa/sherpa.toml     (policy, root-owned)
                                      │  /etc/himalaya-sherpa/himalaya.toml   (no plain passwords)
                                      │  /etc/himalaya-sherpa/secrets/*       (root:sherpa 0640)
                                      └► /var/lib/himalaya-sherpa             (outbox, audit log)
you ── sudo sherpa-admin review / log / doctor
```

A wrapper running as the agent's own user cannot protect a password: the agent could
read the config, run the password command, swap the binary or read the process's
memory. So the gate runs as a separate **service user**. The agent can run only the
gate, through a single sudo rule. It cannot read the credentials, the himalaya config
or the policy, and it cannot run the gate's himalaya binary directly.

The gate accepts a strict subset of the himalaya v2 command line. Everything else is
rejected by the argument parser, including `-c`/`--config`, `--log-level`/`--log-file`,
the raw `imap`/`smtp`/`gmail`/`jmap` commands, `account configure` and file-path
arguments such as `--attach`. Every message the agent reads, replies to, forwards,
flags, moves or deletes is first fetched and classified.

## Install

Build as **a user other than the agent**, so the agent cannot tamper with the binaries
that will hold your credentials. `setup` refuses binaries and configs the agent can
write to, unless you pass `--allow-untrusted`.

```sh
git clone https://github.com/<you>/himalaya-sherpa && cd himalaya-sherpa
cargo build --release

# Get himalaya from a trusted source too (a release you verified, or your distribution).
sudo target/release/sherpa-admin setup \
    --agent-user hermes \
    --himalaya /usr/bin/himalaya \
    --import-config /home/hermes/.config/himalaya/config.toml \
    --shim /home/hermes/.local/bin/himalaya     # optional: keep the agent's `himalaya` command
```

`setup` prints each step (preview it with `--dry-run`). It:

1. creates the `sherpa` system user;
2. installs himalaya (`root:sherpa 0750`, so the agent can't run it) and the gate;
3. writes the default policy to `/etc/himalaya-sherpa/sherpa.toml`;
4. imports your himalaya config and rewrites every `password.command` to read a secret
   file. It flags any other setting that runs a command (hooks and so on) for you to review;
5. asks for each account password, or with `--import-secrets` runs the original
   password commands as the agent user one last time;
6. installs a sudo rule (validated with `visudo`) and the `sherpa` command.

Then:

```sh
sudo sherpa-admin doctor --agent-user hermes   # checks the boundary from the agent's side
```

Finally, **remove the agent's copy of the credentials** (its himalaya config and any
`pass` entries it can decrypt), and **rotate the passwords**, since the agent could read
them until now. `doctor` warns about leftovers it can see.

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
```

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
links and security alerts, in English and Spanish.

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
  threat model.
- Filters are regular expressions: good at the formulaic mail services send, not a
  guarantee. Messages that can't be parsed are withheld (fail closed).
- Envelope listings are classified on sender, recipients and subject only. A message
  matched by a body rule shows in listings but can't be read.
- Mailbox counts (`mailbox list --counts`) include withheld messages.
- `blackhole` mode deceives the agent by design. The agent may then tell you it sent
  something. Prefer `queue` or `draft`.
- Targets the himalaya v2 CLI (tested with v2.1.0).

## Development

```sh
make            # list the tasks
make check      # formatting, clippy, docs and tests: run before pushing
make test-e2e   # end-to-end tests against the pinned himalaya release (downloaded, checksum-verified)
make ci         # everything CI runs, including cargo-deny
```

The end-to-end tests drive the gate against a temporary Maildir account. They use
`HIMALAYA_BIN`, the pinned release in `.cache/` (`make himalaya`), or a `himalaya` on
`PATH`, and are skipped if none is found (CI sets `SHERPA_REQUIRE_HIMALAYA=1` to fail
instead). The minimum supported Rust version is 1.88 (`make msrv`).

To try the gate without installing it, run `target/debug/sherpa` with
`SHERPA_CONFIG=/path/to/sherpa.toml`. The variable is ignored under sudo.

## License

MIT
