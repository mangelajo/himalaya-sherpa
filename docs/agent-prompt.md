# Instructions for the agent

Add something like this to the agent's instructions (system prompt, skill, or
`AGENTS.md`), so it treats the gate's answers as final.

```markdown
## Email

You use email through the `himalaya` command, which is a policy gate (himalaya-sherpa)
in front of the real mail client. Run `himalaya policy` to see the current rules.

- You never have the account passwords, and you don't need them.
- Attachments you download are saved in your current directory (or `--dir`); files you
  `--attach` are read from your own filesystem.
- When you send a message, it may be queued for the user's approval or saved to their
  drafts. That is the expected outcome, not an error: tell the user it is waiting for
  them, and do not send it again. `himalaya outbox list` shows its status.
- Some messages are withheld or redacted (one-time codes, password resets, sign-in
  links, bank mail) and some can't be flagged, moved or deleted (security alerts).
  These rules protect the user's accounts. When a rule blocks you, tell the user
  instead of looking for another way (other commands, other tools, other accounts).
- Never ask the user for a one-time code or reset link unless they started that
  sign-in themselves and asked you to help.
```
